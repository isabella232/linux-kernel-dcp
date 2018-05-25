// SPDX-License-Identifier: GPL-2.0-only
/*
 * Hardware Feedback Interface Driver
 *
 * Copyright (c) 2021, Intel Corporation.
 *
 * Authors: Aubrey Li <aubrey.li@linux.intel.com>
 *          Ricardo Neri <ricardo.neri-calderon@linux.intel.com>
 *
 *
 * The Hardware Feedback Interface provides a performance and energy efficiency
 * capability information for each CPU in the system. Depending on the processor
 * model, hardware may periodically update these capabilities as a result of
 * changes in the operating conditions (e.g., power limits or thermal
 * constraints). On other processor models, there is a single HFI update
 * at boot.
 *
 * This file provides functionality to process HFI updates and relay these
 * updates to userspace.
 */

#define pr_fmt(fmt)  "intel-hfi: " fmt

#include <linux/slab.h>

#include "intel_hfi.h"

/**
 * struct hfi_cpu_data - HFI capabilities per CPU
 * @perf_cap:		Performance capability
 * @ee_cap:		Energy efficiency capability
 *
 * Capabilities of a logical processor in the HFI table. These capabilities are
 * unitless.
 */
struct hfi_cpu_data {
	u8	perf_cap;
	u8	ee_cap;
} __packed;

/**
 * struct hfi_hdr - Header of the HFI table
 * @perf_updated:	Hardware updated performance capabilities
 * @ee_updated:		Hardware updated energy efficiency capabilities
 *
 * Properties of the data in an HFI table.
 */
struct hfi_hdr {
	u8 perf_updated;
	u8 ee_updated;
} __packed;

/**
 * struct hfi_instance - Representation of an HFI instance (i.e., a table)
 * @ts_counter:		Time stamp of the last update of the table
 * @hdr:		Base address of the table header
 * @data:		Base address of the table data
 *
 * A set of parameters to parse and navigate a specific HFI table.
 */
struct hfi_instance {
	u64			*ts_counter;
	void			*hdr;
	void			*data;
};

/**
 * struct hfi_features - Supported HFI features
 * @capabilities:	Bitmask of supported capabilities
 * @nr_table_pages:	Size of the HFI table in 4KB pages
 * @cpu_stride:		Stride size to locate capability data of a logical
 *			processor within the table (i.e., row stride)
 * @hdr_size:		Size of table header
 * @parsed:		True if HFI features have been parsed
 *
 * Parameters and supported features that are common to all HFI instances
 */
struct hfi_features {
	unsigned long	capabilities;
	unsigned int	nr_table_pages;
	unsigned int	cpu_stride;
	unsigned int	hdr_size;
	bool		parsed;
};

static int max_hfi_instances;
static struct hfi_instance *hfi_instances;

static struct hfi_features hfi_features;

static __init int hfi_parse_features(void)
{
	unsigned int nr_capabilities, reg;

	if (!boot_cpu_has(X86_FEATURE_INTEL_HFI))
		return -ENODEV;

	if (hfi_features.parsed)
		return 0;

	/*
	 * If we are here we know that CPUID_HFI_LEAF exists. Parse the
	 * supported capabilities and the size of the HFI table.
	 */
	reg = cpuid_edx(CPUID_HFI_LEAF);

	hfi_features.capabilities = reg & HFI_CAPABILITIES_MASK;
	if (!(hfi_features.capabilities & HFI_CAPABILITIES_PERFORMANCE)) {
		pr_err("Performance reporting not supported! Not using HFI\n");
		return -ENODEV;
	}

	/* The number of 4KB pages required by the table */
	hfi_features.nr_table_pages = ((reg & CPUID_HFI_TABLE_SIZE_MASK) >>
				      CPUID_HFI_TABLE_SIZE_SHIFT) + 1;

	/*
	 * The number of supported capabilities determines the number of
	 * columns in the HFI table.
	 */
	nr_capabilities = bitmap_weight(&hfi_features.capabilities,
					HFI_CAPABILITIES_NR);

	/*
	 * The header contains change indications for each supported feature.
	 * The size of the table header is rounded up to be a multiple of 8
	 * bytes.
	 */
	hfi_features.hdr_size = DIV_ROUND_UP(nr_capabilities, 8) * 8;

	/*
	 * Data of each logical processor is also rounded up to be a multiple
	 * of 8 bytes.
	 */
	hfi_features.cpu_stride = DIV_ROUND_UP(nr_capabilities, 8) * 8;

	hfi_features.parsed = true;
	return 0;
}

void __init intel_hfi_init(void)
{
	if (hfi_parse_features())
		return;

	max_hfi_instances = topology_max_packages() *
			    topology_max_die_per_package();

	/*
	 * This allocation may fail. CPU hotplug callbacks must check
	 * for a null pointer.
	 */
	hfi_instances = kcalloc(max_hfi_instances, sizeof(*hfi_instances),
				GFP_KERNEL);
}
