// SPDX-License-Identifier: GPL-2.0

#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/prctl.h>
#include <linux/compat.h>
#include <linux/mman.h>
#include <linux/elfcore.h>
#include <linux/processor.h>
#include <asm/prctl.h>
#include <asm/cet.h>

/* See Documentation/x86/intel_cet.rst. */

static int elf_feat_copy_status_to_user(struct thread_shstk *shstk, u64 __user *ubuf)
{
	u64 buf[3] = {};

	if (shstk->size) {
		buf[0] = LINUX_X86_FEATURE_SHSTK;
		buf[1] = shstk->base;
		buf[2] = shstk->size;
	}
	if (shstk->wrss)
		buf[0] |= LINUX_X86_FEATURE_WRSS;

	return copy_to_user(ubuf, buf, sizeof(buf));
}

#ifdef CONFIG_X86_SHADOW_STACK
static int handle_alloc_shstk(u64 arg2)
{
	unsigned long addr, size;

	if (get_user(size, (unsigned long __user *)arg2))
		return -EFAULT;

	addr = cet_alloc_shstk(size);
	if (IS_ERR_VALUE(addr))
		return PTR_ERR((void *)addr);

	if (put_user((u64)addr, (u64 __user *)arg2)) {
		vm_munmap(addr, size);
		return -EFAULT;
	}

	return 0;
}
#endif


int prctl_elf_feature(int option, u64 arg2)
{
	struct thread_struct *thread = &current->thread;

	if (!cpu_feature_enabled(X86_FEATURE_SHSTK))
		return -EOPNOTSUPP;

	switch (option) {
	case ARCH_X86_FEATURE_STATUS:
		return elf_feat_copy_status_to_user(&thread->shstk, (u64 __user *)arg2);
	case ARCH_X86_FEATURE_DISABLE:
		if (arg2 & thread->feat_prctl_locked)
			return -EPERM;

		if (arg2 & LINUX_X86_FEATURE_SHSTK)
			shstk_disable();
		if (arg2 & LINUX_X86_FEATURE_WRSS)
			wrss_control(false);

		return 0;
	case ARCH_X86_FEATURE_ENABLE:
		if (arg2 & thread->feat_prctl_locked)
			return -EPERM;

		if (arg2 & LINUX_X86_FEATURE_WRSS)
			wrss_control(true);

		return 0;
	case ARCH_X86_FEATURE_LOCK:
		thread->feat_prctl_locked |= arg2;
		return 0;
#ifdef CONFIG_X86_SHADOW_STACK
	case ARCH_X86_CET_ALLOC_SHSTK:
		return handle_alloc_shstk(arg2);
#endif

	default:
		return -EINVAL;
	}
}
