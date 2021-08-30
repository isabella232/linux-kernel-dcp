// SPDX-License-Identifier: GPL-2.0
/*
 * shstk.c - Intel shadow stack support
 *
 * Copyright (c) 2021, Intel Corporation.
 * Yu-cheng Yu <yu-cheng.yu@intel.com>
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h>
#include <linux/compat.h>
#include <linux/sizes.h>
#include <linux/user.h>
#include <asm/msr.h>
#include <asm/fpu/internal.h>
#include <asm/fpu/xstate.h>
#include <asm/fpu/types.h>
#include <asm/cet.h>
#include <asm/special_insns.h>
#include <asm/fpu/api.h>

static unsigned long alloc_shstk(unsigned long size)
{
	int flags = MAP_ANONYMOUS | MAP_PRIVATE;
	struct mm_struct *mm = current->mm;
	unsigned long addr, unused;

	mmap_write_lock(mm);
	addr = do_mmap(NULL, 0, size, PROT_READ, flags, VM_SHADOW_STACK, 0,
		       &unused, NULL);
	mmap_write_unlock(mm);

	return addr;
}

static void unmap_shadow_stack(u64 base, u64 size)
{
	while (1) {
		int r;

		r = vm_munmap(base, size);

		/*
		 * vm_munmap() returns -EINTR when mmap_lock is held by
		 * something else, and that lock should not be held for a
		 * long time.  Retry it for the case.
		 */
		if (r == -EINTR) {
			cond_resched();
			continue;
		}

		/*
		 * For all other types of vm_munmap() failure, either the
		 * system is out of memory or there is bug.
		 */
		WARN_ON_ONCE(r);
		break;
	}
}

int shstk_setup(void)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	unsigned long addr, size;
	void *xstate;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    shstk->size ||
	    shstk->base)
		return 1;

	size = PAGE_ALIGN(min_t(unsigned long long, rlimit(RLIMIT_STACK), SZ_4G));
	addr = alloc_shstk(size);
	if (IS_ERR_VALUE(addr))
		return 1;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);
	err = xsave_wrmsrl(xstate, MSR_IA32_PL3_SSP, addr + size);
	if (!err)
		err = xsave_wrmsrl(xstate, MSR_IA32_U_CET, CET_SHSTK_EN);
	end_update_xsave_msrs();

	if (err) {
		/*
		 * Don't leak shadow stack if something went wrong with writing the
		 * msrs. Warn about it because things may be in a weird state.
		 */
		WARN_ON_ONCE(1);
		unmap_shadow_stack(addr, size);
		return 1;
	}

	shstk->base = addr;
	shstk->size = size;
	return 0;
}

int shstk_alloc_thread_stack(struct task_struct *tsk, unsigned long clone_flags,
			     unsigned long stack_size)
{
	struct thread_shstk *shstk = &tsk->thread.shstk;
	unsigned long addr;
	void *xstate;

	/*
	 * If shadow stack is not enabled on the new thread, skip any
	 * switch to a new shadow stack.
	 */
	if (!shstk->size)
		return 0;

	/*
	 * clone() does not pass stack_size, which was added to clone3().
	 * Use RLIMIT_STACK and cap to 4 GB.
	 */
	if (!stack_size)
		stack_size = min_t(unsigned long long, rlimit(RLIMIT_STACK), SZ_4G);

	/*
	 * For CLONE_VM, except vfork, the child needs a separate shadow
	 * stack.
	 */
	if ((clone_flags & (CLONE_VFORK | CLONE_VM)) != CLONE_VM)
		return 0;


	/*
	 * Compat-mode pthreads share a limited address space.
	 * If each function call takes an average of four slots
	 * stack space, allocate 1/4 of stack size for shadow stack.
	 */
	if (in_compat_syscall())
		stack_size /= 4;

	/*
	 * 'tsk' is configured with a shadow stack and the fpu.state is
	 * up to date since it was just copied from the parent.  There
	 * must be a valid non-init CET state location in the buffer.
	 */
	xstate = get_xsave_buffer_unsafe(&tsk->thread.fpu, XFEATURE_CET_USER);
	if (WARN_ON_ONCE(!xstate))
		return -EINVAL;

	stack_size = PAGE_ALIGN(stack_size);
	addr = alloc_shstk(stack_size);
	if (IS_ERR_VALUE(addr)) {
		shstk->base = 0;
		shstk->size = 0;
		return PTR_ERR((void *)addr);
	}

	xsave_wrmsrl_unsafe(xstate, MSR_IA32_PL3_SSP, (u64)(addr + stack_size));
	shstk->base = addr;
	shstk->size = stack_size;
	return 0;
}

void shstk_free(struct task_struct *tsk)
{
	struct thread_shstk *shstk = &tsk->thread.shstk;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    !shstk->size ||
	    !shstk->base)
		return;

	/*
	 * When fork() with CLONE_VM fails, the child (tsk) already has a
	 * shadow stack allocated, and exit_thread() calls this function to
	 * free it.  In this case the parent (current) and the child share
	 * the same mm struct.
	 */
	if (!tsk->mm || tsk->mm != current->mm)
		return;

	unmap_shadow_stack(shstk->base, shstk->size);

	shstk->base = 0;
	shstk->size = 0;
}

int shstk_disable(void)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	void *xstate;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    !shstk->size ||
	    !shstk->base)
		return 1;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);
	err = xsave_set_clear_bits_msrl(xstate, MSR_IA32_U_CET, 0, CET_SHSTK_EN);
	if (!err)
		err = xsave_wrmsrl(xstate, MSR_IA32_PL3_SSP, 0);
	end_update_xsave_msrs();

	if (err)
		return 1;

	shstk_free(current);
	return 0;
}
