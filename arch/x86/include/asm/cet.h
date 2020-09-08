/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_CET_H
#define _ASM_X86_CET_H

#ifndef __ASSEMBLY__
#include <linux/types.h>

struct task_struct;

struct thread_shstk {
	u64	base;
	u64	size;
	bool	wrss;
};

#ifdef CONFIG_X86_SHADOW_STACK
int shstk_setup(void);
int shstk_alloc_thread_stack(struct task_struct *p, unsigned long clone_flags,
			     unsigned long stack_size);
void shstk_free(struct task_struct *p);
int shstk_disable(void);
int wrss_control(bool enable);
int shstk_setup_rstor_token(bool proc32, unsigned long restorer,
			    unsigned long *new_ssp);
int shstk_check_rstor_token(bool proc32, unsigned long *new_ssp);
int setup_signal_shadow_stack(int proc32, void __user *restorer);
int restore_signal_shadow_stack(void);
unsigned long cet_alloc_shstk(unsigned long size);
#else
static inline void shstk_setup(void) {}
static inline int shstk_alloc_thread_stack(struct task_struct *p,
					   unsigned long clone_flags,
					   unsigned long stack_size) { return 0; }
static inline void shstk_free(struct task_struct *p) {}
static inline void shstk_disable(void) {}
static inline void reset_thread_shstk(void) {}
static inline void wrss_control(bool enable) {}
static inline int shstk_setup_rstor_token(bool proc32, unsigned long restorer,
					  unsigned long *new_ssp) { return 0; }
static inline int shstk_check_rstor_token(bool proc32,
					  unsigned long *new_ssp) { return 0; }
static inline int setup_signal_shadow_stack(int proc32, void __user *restorer) { return 0; }
static inline int restore_signal_shadow_stack(void) { return 0; }
#endif /* CONFIG_X86_SHADOW_STACK */

#ifdef CONFIG_X86_SHADOW_STACK
int prctl_elf_feature(int option, u64 arg2);
#else
static inline int prctl_elf_feature(int option, u64 arg2) { return -EINVAL; }
#endif

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CET_H */
