/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_MMAN_H
#define _ASM_X86_MMAN_H

#include <linux/mm.h>
#include <uapi/asm/mman.h>

#ifdef CONFIG_X86_SHADOW_STACK
static inline bool arch_validate_flags(unsigned long vm_flags)
{
	/*
	 * Shadow stack must not be executable, to help with W^X due to wrss.
	 */
	if ((vm_flags & VM_SHADOW_STACK) && (vm_flags & (VM_WRITE | VM_EXEC)))
		return false;

	return true;
}

#define arch_validate_flags(vm_flags) arch_validate_flags(vm_flags)

#endif /* CONFIG_X86_SHADOW_STACK */

#endif /* _ASM_X86_MMAN_H */
