/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#ifndef _SAF_H_
#define _SAF_H_

/* These bits are in the IA32_CORE_CAPABILITIES MSR */
#define MSR_IA32_CORE_CAPS_INTEGRITY_BIT	2
#define MSR_IA32_CORE_CAPS_INTEGRITY		BIT(MSR_IA32_CORE_CAPS_INTEGRITY_BIT)

#define HEADER_OFFSET_IMAGE_REVISION		4
#define HEADER_SIZE				48

/**
 * struct saf_params - global saf parameter for all cpus.
 * @header_ptr: the pointer to the scan binary header.
 * @loaded_version: stores the currently loaded scan image version.
 * @hash_ptr: the linear address that points to scan hash loaded.
 * @test_image_ptr: the 512B aligned linear address that points to scan test chunk loaded.
 */
struct saf_params {
	char *header_ptr;
	int loaded_version;
	u64 hash_ptr;
	u64 test_image_ptr;
};

#endif
