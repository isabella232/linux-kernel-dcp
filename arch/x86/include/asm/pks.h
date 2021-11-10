/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PKS_H
#define _ASM_X86_PKS_H

#ifdef CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS

struct extended_pt_regs {
	u32 thread_pkrs;
	/* Keep stack 8 byte aligned */
	u32 pad;
	struct pt_regs pt_regs;
};

void setup_pks(void);
void pkrs_write_current(void);
void pks_init_task(struct task_struct *task);
void write_pkrs(u32 new_pkrs);

static inline struct extended_pt_regs *extended_pt_regs(struct pt_regs *regs)
{
	return container_of(regs, struct extended_pt_regs, pt_regs);
}

void show_extended_regs_oops(struct pt_regs *regs, unsigned long error_code);
int handle_abandoned_pks_value(struct pt_regs *regs);
bool handle_pks_key_callback(unsigned long address, bool write, u16 key);

#else /* !CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS */

static inline void setup_pks(void) { }
static inline void pkrs_write_current(void) { }
static inline void pks_init_task(struct task_struct *task) { }
static inline void write_pkrs(u32 new_pkrs) { }
static inline void show_extended_regs_oops(struct pt_regs *regs,
					   unsigned long error_code) { }
static inline int handle_abandoned_pks_value(struct pt_regs *regs)
{
	return 0;
}
static inline bool handle_pks_key_fault(struct pt_regs *regs,
					unsigned long hw_error_code,
					unsigned long address)
{
	return false;
}

#endif /* CONFIG_ARCH_ENABLE_SUPERVISOR_PKEYS */


#ifdef CONFIG_PKS_TEST

#define __static_or_pks_test

bool pks_test_callback(struct pt_regs *regs);

#else /* !CONFIG_PKS_TEST */

#define __static_or_pks_test static

static inline bool pks_test_callback(struct pt_regs *regs)
{
	return false;
}

#endif /* CONFIG_PKS_TEST */

#endif /* _ASM_X86_PKS_H */
