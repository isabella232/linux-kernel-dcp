/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#ifndef _SAF_H_
#define _SAF_H_

/*
 * Get a bit field at register value <val>, from bit <lo> to bit <hi>
 */
#define GET_BITFIELD(val, lo, hi) \
	(((val) & GENMASK_ULL((hi), (lo))) >> (lo))

/* These bits are in the IA32_CORE_CAPABILITIES MSR */
#define MSR_IA32_CORE_CAPS_INTEGRITY_BIT	2
#define MSR_IA32_CORE_CAPS_INTEGRITY		BIT(MSR_IA32_CORE_CAPS_INTEGRITY_BIT)

#define MSR_COPY_SCAN_HASHES			0x000002c2
#define MSR_SCAN_HASHES_STATUS			0x000002c3
#define MSR_AUTHENTICATE_AND_COPY_CHUNK		0x000002c4
#define MSR_CHUNKS_AUTHENTICATION_STATUS	0x000002c5
#define HEADER_OFFSET_IMAGE_REVISION		4
#define HEADER_OFFSET_METADATA_SIZE		28
#define HEADER_OFFSET_TOTAL_SIZE		32
#define HEADER_SIZE				48
#define TEST_SIZE_LIMIT				BIT(27)

/**
 * struct saf_params - global saf parameter for all cpus.
 * @header_ptr: the pointer to the scan binary header.
 * @loaded_version: stores the currently loaded scan image version.
 * @hash_ptr: the linear address that points to scan hash loaded.
 * @test_image_ptr: the 512B aligned linear address that points to scan test chunk loaded.
 * @num_chunks: the number of chunks in scan binary.
 * @chunk_size: shows the chunk size.
 * @max_cores: the maximum numbers of cores that scan test can run simultaneously.
 * @loading_error: set if error occurred during scan hashes or chunk authentication.
 * @hash_valid: set when scan hash copy completed.
 * @valid_chunks: the number of authenticated chunks.
 */
struct saf_params {
	char *header_ptr;
	int loaded_version;
	u64 hash_ptr;
	u64 test_image_ptr;
	int num_chunks;
	int chunk_size;
	int max_cores;
	bool loading_error;
	bool hash_valid;
	int valid_chunks;
};

#endif
