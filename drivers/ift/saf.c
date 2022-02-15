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
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/topology.h>
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

static const char * const scan_hash_status[] = {
	"Reserved",
	"Attempt to copy scan hashes when copy already in progress",
	"Secure Memory not set up correctly",
	"FuSaInfo.ProgramID does not match or ff-mm-ss does not match",
	"Reserved",
	"Integrity check failed",
	"Scan test is in progress"
};

static const char * const scan_authentication_status[] = {
	"No error reported",
	"Attempt to authenticate a chunk which is already marked as authentic",
	"Chunk authentication error. The hash of chunk did not match expected value"
};

/*
 * To copy scan hashes and authenticate test chunks, the initiating cpu must point
 * to the EDX:EAX to the test image in linear address.
 * Run wrmsr(MSR_COPY_SCAN_HASHES) for scan hash copy and run wrmsr(MSR_AUTHENTICATE_AND_COPY_CHUNK)
 * for scan hash copy and test chunk authetication.
 */
static int copy_hashes_authenticate_chunks(void *arg)
{
	u64 linear_addr, base;
	u32 eax, edx;
	int i;

	eax = lower_32_bits(saf_params.hash_ptr);
	edx = upper_32_bits(saf_params.hash_ptr);

	/* run scan hash copy */
	wrmsr(MSR_COPY_SCAN_HASHES, eax, edx);
	rdmsr(MSR_SCAN_HASHES_STATUS, eax, edx);

	/* enumerate the scan image information */
	saf_params.max_cores = GET_BITFIELD(edx, 19, 30) + 1;
	saf_params.num_chunks = GET_BITFIELD(eax, 16, 23);
	saf_params.chunk_size = GET_BITFIELD(eax, 0, 15) * 1024;
	saf_params.hash_valid = GET_BITFIELD(edx, 31, 31);

	if (!(saf_params.hash_valid)) {
		saf_params.loading_error = true;
		if (GET_BITFIELD(edx, 0, 7) >= ARRAY_SIZE(scan_hash_status)) {
			pr_err("saf: invalid error code for hash copy");
			return -EINVAL;
		}
		pr_err("saf: %s", scan_hash_status[GET_BITFIELD(edx, 0, 7)]);
		return -ENODEV;
	}
	pr_info("saf: the total chunk number: %d", saf_params.num_chunks);

	/* base linear address to the scan data */
	base = saf_params.test_image_ptr;

	/* scan data authentication and copy chunks to secured memory */
	for (i = 0; i < saf_params.num_chunks; i++) {
		linear_addr = base + i * saf_params.chunk_size;
		edx = upper_32_bits(linear_addr);
		eax = lower_32_bits(linear_addr);
		eax |= i;

		wrmsr(MSR_AUTHENTICATE_AND_COPY_CHUNK, eax, edx);
		rdmsr(MSR_CHUNKS_AUTHENTICATION_STATUS, eax, edx);

		saf_params.valid_chunks = GET_BITFIELD(eax, 0, 7);

		if (GET_BITFIELD(edx, 0, 7)) {
			if (GET_BITFIELD(edx, 0, 7) >= ARRAY_SIZE(scan_authentication_status)) {
				pr_err("saf: invalid error code for authentication");
				return -EINVAL;
			}
			saf_params.loading_error = true;
			pr_err("saf: %s", scan_authentication_status[GET_BITFIELD(edx, 0, 7)]);
			return -ENODEV;
		}
	}

	return 0;
}

/*
 * SAF requires scan chunks authenticated per each socket in the platform.
 * Once the test chunk is authenticated, it is automatically copied to secured memory
 * and proceed the authentication for the next chunk.
 */
static int scan_chunks_sanity_check(void)
{
	int metadata_size, total_size, test_size, curr_pkg, cpu, ret = -ENOMEM;
	char *aligned_buf, *test_ptr;
	bool *package_authenticated;

	package_authenticated = kcalloc(topology_max_packages(), sizeof(bool), GFP_KERNEL);
	if (!package_authenticated)
		return ret;

	metadata_size = *((unsigned int *)(saf_params.header_ptr + HEADER_OFFSET_METADATA_SIZE));
	total_size = *((unsigned int *)(saf_params.header_ptr + HEADER_OFFSET_TOTAL_SIZE));
	test_size = total_size - metadata_size - HEADER_SIZE;
	test_ptr = saf_params.header_ptr + HEADER_SIZE + metadata_size;

	/* scan test size is limited to 128MB */
	if (test_size > TEST_SIZE_LIMIT) {
		pr_err("saf: the test size is %u, the limit is 128MB", test_size);
		goto out;
	}

	/* the linear address to scan chunk must be 256B aligned */
	aligned_buf = vmalloc(test_size);
	if (!aligned_buf)
		goto out;

	memcpy(aligned_buf, test_ptr, test_size);
	saf_params.test_image_ptr = (u64)(u64 *)aligned_buf;
	saf_params.loaded_version = *((unsigned int *)(saf_params.header_ptr
						       + HEADER_OFFSET_IMAGE_REVISION));

	/* copy the scan hash and authenticate per package */
	cpus_read_lock();
	for_each_online_cpu(cpu) {
		curr_pkg = topology_physical_package_id(cpu);
		if (package_authenticated[curr_pkg])
			continue;
		package_authenticated[curr_pkg] = 1;
		ret = smp_call_function_single(cpu, (void *)copy_hashes_authenticate_chunks,
					       NULL, 1);
		if (ret || saf_params.loading_error) {
			ret = saf_params.loading_error ? -ENOMEM : ret;
			vfree(aligned_buf);
			goto out;
		}
	}
	cpus_read_unlock();
	vfree(aligned_buf);
out:
	kfree(package_authenticated);

	return ret;
}

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

	ret = scan_chunks_sanity_check();
	if (ret)
		pr_err("saf: authentication failed");
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
