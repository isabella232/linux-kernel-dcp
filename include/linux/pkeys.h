/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PKEYS_H
#define _LINUX_PKEYS_H

#include <linux/mm.h>

#define ARCH_DEFAULT_PKEY	0

#ifdef CONFIG_ARCH_HAS_PKEYS
#include <asm/pkeys.h>
#else /* ! CONFIG_ARCH_HAS_PKEYS */
#define arch_max_pkey() (1)
#define execute_only_pkey(mm) (0)
#define arch_override_mprotect_pkey(vma, prot, pkey) (0)
#define PKEY_DEDICATED_EXECUTE_ONLY 0
#define ARCH_VM_PKEY_FLAGS 0

static inline int vma_pkey(struct vm_area_struct *vma)
{
	return 0;
}

static inline bool mm_pkey_is_allocated(struct mm_struct *mm, int pkey)
{
	return (pkey == 0);
}

static inline int mm_pkey_alloc(struct mm_struct *mm)
{
	return -1;
}

static inline int mm_pkey_free(struct mm_struct *mm, int pkey)
{
	return -EINVAL;
}

static inline int arch_set_user_pkey_access(struct task_struct *tsk, int pkey,
			unsigned long init_val)
{
	return 0;
}

static inline bool arch_pkeys_enabled(void)
{
	return false;
}

#endif /* ! CONFIG_ARCH_HAS_PKEYS */

#ifdef CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS
enum pks_pkey_consumers {
	PKS_KEY_DEFAULT = 0, /* Must be 0 for default PTE values */
	PKS_KEY_NR_CONSUMERS
};
extern u32 pkrs_init_value;

void pkrs_save_irq(struct pt_regs *regs);
void pkrs_restore_irq(struct pt_regs *regs);

#else /* !CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS */

static inline void pkrs_save_irq(struct pt_regs *regs) { }
static inline void pkrs_restore_irq(struct pt_regs *regs) { }

#endif /* CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS */

#endif /* _LINUX_PKEYS_H */
