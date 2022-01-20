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
			shstk_disable()
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

	default:
		return -EINVAL;
	}
}
