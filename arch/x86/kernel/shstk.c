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

/*
 * Create a restore token on the shadow stack.  A token is always 8-byte
 * and aligned to 8.
 */
static int create_rstor_token(bool proc32, unsigned long ssp,
			      unsigned long *token_addr)
{
	unsigned long addr;

	/* Aligned to 8 is aligned to 4, so test 8 first */
	if ((!proc32 && !IS_ALIGNED(ssp, 8)) || !IS_ALIGNED(ssp, 4))
		return -EINVAL;

	addr = ALIGN_DOWN(ssp, 8) - 8;

	/* Is the token for 64-bit? */
	if (!proc32)
		ssp |= BIT(0);

	if (write_user_shstk_64((u64 __user *)addr, (u64)ssp))
		return -EFAULT;

	*token_addr = addr;

	return 0;
}

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

int wrss_control(bool enable)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	void *xstate;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return 1;
	/*
	 * Only enable wrss if shadow stack is enabled. If shadow stack is not
	 * enabled, wrss will already be disabled, so don't bother clearing it
	 * when disabling.
	 */
	if (!shstk->size || shstk->wrss == enable)
		return 1;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);
	if (enable)
		err = xsave_set_clear_bits_msrl(xstate, MSR_IA32_U_CET, CET_WRSS_EN, 0);
	else
		err = xsave_set_clear_bits_msrl(xstate, MSR_IA32_U_CET, 0, CET_WRSS_EN);
	end_update_xsave_msrs();

	if (err)
		return 1;

	shstk->wrss = enable;
	return 0;
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
	/* Disable WRSS too when disabling shadow stack */
	err = xsave_set_clear_bits_msrl(xstate, MSR_IA32_U_CET, 0,
					CET_SHSTK_EN | CET_WRSS_EN);
	if (!err)
		err = xsave_wrmsrl(xstate, MSR_IA32_PL3_SSP, 0);
	end_update_xsave_msrs();

	if (err)
		return 1;

	shstk_free(current);
	shstk->wrss = 0;
	return 0;
}

static unsigned long get_user_shstk_addr(void)
{
	void *xstate;
	unsigned long long ssp;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);

	xsave_rdmsrl(xstate, MSR_IA32_PL3_SSP, &ssp);

	end_update_xsave_msrs();

	return ssp;
}

/*
 * Create a restore token on shadow stack, and then push the user-mode
 * function return address.
 */
int shstk_setup_rstor_token(bool proc32, unsigned long ret_addr,
			    unsigned long *new_ssp)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	unsigned long ssp, token_addr;
	int err;

	if (!shstk->size)
		return 0;

	if (!ret_addr)
		return -EINVAL;

	ssp = get_user_shstk_addr();
	if (!ssp)
		return -EINVAL;

	err = create_rstor_token(proc32, ssp, &token_addr);
	if (err)
		return err;

	if (proc32) {
		ssp = token_addr - sizeof(u32);
		err = write_user_shstk_32((u32 __user *)ssp, (u32)ret_addr);
	} else {
		ssp = token_addr - sizeof(u64);
		err = write_user_shstk_64((u64 __user *)ssp, (u64)ret_addr);
	}

	if (!err)
		*new_ssp = ssp;

	return err;
}

/*
 * Verify the user shadow stack has a valid token on it, and then set
 * *new_ssp according to the token.
 */
int shstk_check_rstor_token(bool proc32, unsigned long *new_ssp)
{
	unsigned long token_addr;
	unsigned long token;
	bool shstk32;

	token_addr = get_user_shstk_addr();
	if (!token_addr)
		return -EINVAL;

	if (get_user(token, (unsigned long __user *)token_addr))
		return -EFAULT;

	/* Is mode flag correct? */
	shstk32 = !(token & BIT(0));
	if (proc32 ^ shstk32)
		return -EINVAL;

	/* Is busy flag set? */
	if (token & BIT(1))
		return -EINVAL;

	/* Mask out flags */
	token &= ~3UL;

	/* Restore address aligned? */
	if ((!proc32 && !IS_ALIGNED(token, 8)) || !IS_ALIGNED(token, 4))
		return -EINVAL;

	/* Token placed properly? */
	if (((ALIGN_DOWN(token, 8) - 8) != token_addr) || token >= TASK_SIZE_MAX)
		return -EINVAL;

	*new_ssp = token;

	return 0;
}

int setup_signal_shadow_stack(int proc32, void __user *restorer)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	unsigned long new_ssp;
	void *xstate;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) || !shstk->size)
		return 0;

	err = shstk_setup_rstor_token(proc32, (unsigned long)restorer,
				      &new_ssp);
	if (err)
		return err;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);
	err = xsave_wrmsrl(xstate, MSR_IA32_PL3_SSP, new_ssp);
	end_update_xsave_msrs();

	return err;
}

int restore_signal_shadow_stack(void)
{
	struct thread_shstk *shstk = &current->thread.shstk;
	void *xstate;
	int proc32 = in_ia32_syscall();
	unsigned long new_ssp;
	int err;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) || !shstk->size)
		return 0;

	err = shstk_check_rstor_token(proc32, &new_ssp);
	if (err)
		return err;

	xstate = start_update_xsave_msrs(XFEATURE_CET_USER);
	err = xsave_wrmsrl(xstate, MSR_IA32_PL3_SSP, new_ssp);
	end_update_xsave_msrs();

	return err;
}

unsigned long cet_alloc_shstk(unsigned long len)
{
	unsigned long token;
	unsigned long addr, ssp;

	addr = alloc_shstk(round_up(len, PAGE_SIZE));

	if (IS_ERR_VALUE(addr))
		return addr;

	/* Restore token is 8 bytes and aligned to 8 bytes */
	ssp = addr + len;
	token = ssp;

	if (!in_ia32_syscall())
		token |= BIT(0);
	ssp -= 8;

	if (write_user_shstk_64((u64 __user *)ssp, (u64)token)) {
		vm_munmap(addr, len);
		return -EINVAL;
	}

	return addr;
}
