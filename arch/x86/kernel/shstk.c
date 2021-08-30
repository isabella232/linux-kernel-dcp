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

void shstk_free(struct task_struct *tsk)
{
	struct thread_shstk *shstk = &tsk->thread.shstk;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK) ||
	    !shstk->size ||
	    !shstk->base)
		return;

	if (!tsk->mm)
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
