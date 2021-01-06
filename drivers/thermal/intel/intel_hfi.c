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

#include <linux/io.h>
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
 * @table_base:		Base of the local copy of the HFI table
 * @ts_counter:		Time stamp of the last update of the table
 * @hdr:		Base address of the table header
 * @data:		Base address of the table data
 * @die_id:		Logical die ID this HFI table instance
 * @cpus:		CPUs represented in this HFI table instance
 * @hw_table:		Pointer to the HFI table of this instance
 * @initialized:	True if this HFI instance has bee initialized
 *
 * A set of parameters to parse and navigate a specific HFI table.
 */
struct hfi_instance {
	void			*table_base;
	u64			*ts_counter;
	void			*hdr;
	void			*data;
	u16			die_id;
	struct cpumask		*cpus;
	void			*hw_table;
	bool			initialized;
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

/**
 * struct hfi_cpu_info - Per-CPU attributes to consume HFI data
 * @index:		Row of this CPU in its HFI table
 * @hfi_instance:	Attributes of the HFI table to which this CPU belongs
 *
 * Parameters to link a logical processor to an HFI table and a row within it.
 */
struct hfi_cpu_info {
	s16			index;
	struct hfi_instance	*hfi_instance;
};

static DEFINE_PER_CPU(struct hfi_cpu_info, hfi_cpu_info) = { .index = -1 };

static int max_hfi_instances;
static struct hfi_instance *hfi_instances;

static struct hfi_features hfi_features;
static DEFINE_MUTEX(hfi_lock);

static void init_hfi_cpu_index(unsigned int cpu)
{
	s16 hfi_idx;
	u32 edx;

	/* Do not re-read @cpu's index if it has already been initialized. */
	if (per_cpu(hfi_cpu_info, cpu).index > -1)
		return;

	edx = cpuid_edx(CPUID_HFI_LEAF);
	hfi_idx = (edx & CPUID_HFI_CPU_INDEX_MASK) >> CPUID_HFI_CPU_INDEX_SHIFT;

	per_cpu(hfi_cpu_info, cpu).index = hfi_idx;
}

/*
 * The format of the HFI table depends on the number of capabilities that the
 * hardware supports. Keep a data structure to navigate the table.
 */
static void init_hfi_instance(struct hfi_instance *hfi_instance)
{
	/* The HFI time-stamp is located at the base of the table. */
	hfi_instance->ts_counter = hfi_instance->table_base;

	/* The HFI header is below the time-stamp. */
	hfi_instance->hdr = hfi_instance->table_base +
			    sizeof(*hfi_instance->ts_counter);

	/* The HFI data starts below the header. */
	hfi_instance->data = hfi_instance->hdr + hfi_features.hdr_size;
}

/**
 * intel_hfi_online() - Enable HFI on @cpu
 * @cpu:	CPU in which the HFI will be enabled
 *
 * Enable the HFI to be used in @cpu. The HFI is enabled at the die/package
 * level. The first CPU in the die/package to come online does the full HFI
 * initialization. Subsequent CPUs will just link themselves to the HFI
 * instance of their die/package.
 */
void intel_hfi_online(unsigned int cpu)
{
	struct hfi_cpu_info *info = &per_cpu(hfi_cpu_info, cpu);
	u16 die_id = topology_logical_die_id(cpu);
	struct hfi_instance *hfi_instance;
	phys_addr_t hw_table_pa;
	u64 msr_val;

	if (!boot_cpu_has(X86_FEATURE_INTEL_HFI))
		return;

	init_hfi_cpu_index(cpu);

	/*
	 * The HFI instance of this @cpu may exist already but they have not
	 * been linked to @cpu.
	 */
	hfi_instance = info->hfi_instance;
	if (!hfi_instance) {
		if (!hfi_instances)
			return;

		if (die_id >= 0 && die_id < max_hfi_instances)
			hfi_instance = &hfi_instances[die_id];

		if (!hfi_instance)
			return;
	}

	/*
	 * Now check if the HFI instance of the package/die of this CPU has
	 * been initialized. In such case, all we have to do is link @cpu's info
	 * to the HFI instance of its die/package.
	 */
	mutex_lock(&hfi_lock);
	if (hfi_instance->initialized) {
		info->hfi_instance = hfi_instance;

		/*
		 * @cpu is the first one in its die/package to come back online.
		 * Use it to track the CPUs in the die/package.
		 */
		if (!hfi_instance->cpus)
			hfi_instance->cpus = topology_core_cpumask(cpu);

		mutex_unlock(&hfi_lock);
		return;
	}

	/*
	 * Hardware is programmed with the physical address of the first page
	 * frame of the table. Hence, the allocated memory must be page-aligned.
	 */
	hfi_instance->hw_table = alloc_pages_exact(hfi_features.nr_table_pages,
						   GFP_KERNEL | __GFP_ZERO);
	if (!hfi_instance->hw_table)
		goto err_out;

	hw_table_pa = virt_to_phys(hfi_instance->hw_table);

	hfi_instance->table_base = kzalloc(hfi_features.nr_table_pages << PAGE_SHIFT,
					   GFP_KERNEL);
	if (!hfi_instance->table_base)
		goto free_hw_table;

	/*
	 * Program the address of the feedback table of this die/package. On
	 * some processors, hardware remembers the old address of the HFI table
	 * even after having been reprogrammed and re-enabled. Thus, do not free
	 * pages allocated for the table or reprogram the hardware with a new
	 * base address. Namely, program the hardware only once.
	 */
	msr_val = hw_table_pa | HFI_PTR_VALID_BIT;
	wrmsrl(MSR_IA32_HW_FEEDBACK_PTR, msr_val);

	init_hfi_instance(hfi_instance);

	hfi_instance->die_id = die_id;

	/*
	 * We can use the core cpumask of any cpu in the die/package. Any of
	 * them will reflect all the CPUs the same package that are online.
	 */
	hfi_instance->cpus = topology_core_cpumask(cpu);
	info->hfi_instance = hfi_instance;
	hfi_instance->initialized = true;

	mutex_unlock(&hfi_lock);

	return;

free_hw_table:
	free_pages_exact(hfi_instance->hw_table, hfi_features.nr_table_pages);
err_out:
	mutex_unlock(&hfi_lock);
}

/**
 * intel_hfi_offline() - Disable HFI on @cpu
 * @cpu:	CPU in which the HFI will be disabled
 *
 * Remove @cpu from those covered by its HFI instance.
 *
 * On some processors, hardware remembers previous programming settings even
 * after being reprogrammed. Thus, keep HFI enabled even if all CPUs in the
 * die/package of @cpu are offline. See note in intel_hfi_online().
 */
void intel_hfi_offline(unsigned int cpu)
{
	struct cpumask *die_cpumask = topology_core_cpumask(cpu);
	struct hfi_cpu_info *info = &per_cpu(hfi_cpu_info, cpu);
	struct hfi_instance *hfi_instance;

	if (!boot_cpu_has(X86_FEATURE_INTEL_HFI))
		return;

	hfi_instance = info->hfi_instance;
	if (!hfi_instance)
		return;

	if (!hfi_instance->initialized)
		return;

	mutex_lock(&hfi_lock);

	/*
	 * We were using the core cpumask of @cpu to track CPUs in the same
	 * die/package. Now it is going offline and we need to find another
	 * CPU we can use.
	 */
	if (die_cpumask == hfi_instance->cpus) {
		int new_cpu;

		new_cpu = cpumask_any_but(hfi_instance->cpus, cpu);
		if (new_cpu >= nr_cpu_ids)
			/* All other CPUs in the package are offline. */
			hfi_instance->cpus = NULL;
		else
			hfi_instance->cpus = topology_core_cpumask(new_cpu);
	}

	mutex_unlock(&hfi_lock);
}

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
