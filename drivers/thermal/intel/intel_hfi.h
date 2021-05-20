/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _INTEL_HFI_H
#define _INTEL_HFI_H

#include <linux/bits.h>

/* Hardware Feedback Interface Enumeration */
#define CPUID_HFI_LEAF			6
#define CPUID_HFI_CAP_MASK		0xff
#define CPUID_HFI_TABLE_SIZE_MASK	0x0f00
#define CPUID_HFI_TABLE_SIZE_SHIFT	8
#define CPUID_HFI_CPU_INDEX_MASK	0xffff0000
#define CPUID_HFI_CPU_INDEX_SHIFT	16

/* Hardware Feedback Interface Pointer */
#define HFI_PTR_VALID_BIT		BIT(0)
#define HFI_PTR_ADDR_SHIFT		12

/* Hardware Feedback Interface Configuration */
#define HFI_CONFIG_ENABLE_BIT		BIT(0)

/* Hardware Feedback Interface Capabilities */
#define HFI_CAPABILITIES_MASK		0xff
#define HFI_CAPABILITIES_NR		8
#define HFI_CAPABILITIES_PERFORMANCE	BIT(0)
#define HFI_CAPABILITIES_ENERGY_EFF	BIT(1)

#if defined(CONFIG_INTEL_HFI)
void __init intel_hfi_init(void);
void intel_hfi_online(unsigned int cpu);
void intel_hfi_offline(unsigned int cpu);
void intel_hfi_process_event(__u64 pkg_therm_status_msr_val);
#else
static inline void intel_hfi_init(void) { }
static inline void intel_hfi_online(unsigned int cpu) { }
static inline void intel_hfi_offline(unsigned int cpu) { }
static inline void intel_hfi_process_event(__u64 pkg_therm_status_msr_val) { }
#endif

#endif /* _INTEL_HFI_H */
