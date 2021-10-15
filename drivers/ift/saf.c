// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/cpu_device_id.h>

#include "saf.h"

static const struct x86_cpu_id saf_cpu_ids[] __initconst = {
	X86_MATCH_INTEL_FAM6_MODEL(SAPPHIRERAPIDS_X,	1),
	{}
};

static int __init saf_init(void)
{
	const struct x86_cpu_id *m;
	u64 ia32_core_caps;
	int ret = -ENODEV;

	/* saf capability check */
	m = x86_match_cpu(saf_cpu_ids);
	if (!m)
		return ret;
	if (!boot_cpu_has(X86_FEATURE_CORE_CAPABILITIES))
		return ret;
	rdmsrl(MSR_IA32_CORE_CAPS, ia32_core_caps);
	if (!(ia32_core_caps & MSR_IA32_CORE_CAPS_INTEGRITY))
		return ret;

	return 0;
}

static void __exit saf_exit(void)
{
	pr_info("saf: unloaded 'Scan At Field' module\n");
}

MODULE_LICENSE("GPL");
MODULE_INFO(name, "saf");
MODULE_DESCRIPTION("saf");
module_init(saf_init);
module_exit(saf_exit);
