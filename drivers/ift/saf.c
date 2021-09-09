// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <asm/cpu_device_id.h>
#include <asm/microcode_intel.h>

#include "saf.h"

static const char *saf_path = "intel/ift/saf/";
static struct platform_device *saf_pdev;
struct saf_params saf_params;

static const struct x86_cpu_id saf_cpu_ids[] __initconst = {
	X86_MATCH_INTEL_FAM6_MODEL(SAPPHIRERAPIDS_X,	1),
	{}
};

static int scan_sanity_check(void *mc)
{
	struct microcode_header_intel *mc_header = mc;
	unsigned long total_size, data_size;
	u32 sum, i;

	total_size = get_totalsize(mc_header);
	data_size = get_datasize(mc_header);

	if (data_size + MC_HEADER_SIZE > total_size) {
		pr_err("saf: bad scan data file size.\n");
		return -EINVAL;
	}

	if (mc_header->ldrver != 1 || mc_header->hdrver != 1) {
		pr_err("saf: invalid/unknown scan update format.\n");
		return -EINVAL;
	}

	sum = 0;
	i = total_size / sizeof(u32);
	while (i--)
		sum += ((u32 *)mc)[i];

	if (sum) {
		pr_err("saf: bad scan data checksum, aborting.\n");
		return -EINVAL;
	}

	return 0;
}

static bool find_scan_matching_signature(struct ucode_cpu_info *uci, void *mc)
{
	struct microcode_header_intel *shdr;
	unsigned int mc_size;

	shdr = (struct microcode_header_intel *)mc;
	mc_size = get_totalsize(shdr);

	if (!mc_size || scan_sanity_check(shdr) < 0) {
		pr_err("saf: scan sanity check failure");
		return false;
	}

	if (!cpu_signatures_match(uci->cpu_sig.sig, uci->cpu_sig.pf, shdr->sig, shdr->pf)) {
		pr_err("saf: scan signature, pf not matching");
		return false;
	}

	return true;
}

static bool scan_image_sanity_check(void *data)
{
	struct ucode_cpu_info uci;

	collect_cpu_info_early(&uci);

	return find_scan_matching_signature(&uci, data);
}

static const struct firmware *load_binary(const char *path)
{
	const struct firmware *fw;
	int err;

	saf_pdev = platform_device_register_simple("saf", -1, NULL, 0);
	if (IS_ERR(saf_pdev)) {
		pr_err("saf: platform device register failed");
		return NULL;
	}
	err = request_firmware_direct(&fw, path, &saf_pdev->dev);
	if (err) {
		pr_err("saf: scan file %s load failed", path);
		goto out;
	}

	if (!scan_image_sanity_check((void *)fw->data)) {
		pr_err("saf: scan header sanity check failed");
		release_firmware(fw);
		fw = NULL;
	}
out:
	platform_device_unregister(saf_pdev);

	return fw;
}

/*
 * Compare the image version whenever loading a new image.
 * Load the new image only if it is later or equal than the current version.
 */
static bool has_newer_binary_image(int current_loaded_version, char *new_image_ptr)
{
	if (current_loaded_version >
	    *((unsigned int *)(new_image_ptr + HEADER_OFFSET_IMAGE_REVISION)))
		return false;

	return true;
}

/*
 * Load scan image. Before loading saf module, the scan image must be located
 * in /lib/firmware/intel/saf and named as {family/model/stepping}.scan.
 */
int load_scan_binary(void)
{
	int current_loaded_version, ret = -ENOENT;
	const struct firmware *scan_fw;
	char scan_path[256];

	snprintf(scan_path, sizeof(scan_path), "%s%02x-%02x-%02x.scan", saf_path,
		 boot_cpu_data.x86, boot_cpu_data.x86_model, boot_cpu_data.x86_stepping);

	scan_fw = load_binary(scan_path);
	if (!scan_fw)
		goto out;

	/* only reload new scan image for later version than currently loaded */
	current_loaded_version = saf_params.loaded_version;
	if (!has_newer_binary_image(current_loaded_version, (char *)scan_fw->data)) {
		ret = 0;
		goto out;
	}
	saf_params.header_ptr = (char *)scan_fw->data;
	saf_params.hash_ptr = (u64)(saf_params.header_ptr + HEADER_SIZE);

	ret = 0;
out:
	release_firmware(scan_fw);

	return ret;
}

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

	ret = load_scan_binary();
	if (ret) {
		pr_err("saf: loading scan binaries failed");
		return ret;
	}

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
