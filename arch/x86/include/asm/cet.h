/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

struct thread_shstk {
	u64	base;
	u64	size;
};

#ifdef CONFIG_X86_SHADOW_STACK
int shstk_setup(void);
void shstk_free(struct task_struct *p);
int shstk_disable(void);
#else
static inline void shstk_setup(void) {}
static inline void shstk_free(struct task_struct *p) {}
static inline void shstk_disable(void) {}
#endif /* CONFIG_X86_SHADOW_STACK */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
