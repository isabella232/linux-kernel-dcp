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
#define MSR_ACTIVATE_SCAN			0x000002c6
#define MSR_SCAN_STATUS				0x000002c7
#define SCAN_TEST_BUSY				-1
#define SPINUNIT				100
#define HEADER_OFFSET_IMAGE_REVISION		4
#define HEADER_OFFSET_METADATA_SIZE		28
#define HEADER_OFFSET_TOTAL_SIZE		32
#define HEADER_SIZE				48
#define TEST_SIZE_LIMIT				BIT(27)
#define MAX_RETRY				5
#define MINIMUM_SAF_INTERVAL			60

/*
 * scan execution error code (edx stores error code after rdmsr(SCAN_STATUS))
 * 0x0: no error.
 * 0x1: scan did not start because all sibling threads did not join.
 * 0x2: scan did not start because interrupt occurred prior to scan coordination.
 * 0x3: scan did not start because power management conditions are inadequate.
 * 0x4: scan did not start because chunk range is set invalid
 * 0x5: scan did not start because of mismatches in arguments between sibling threads.
 * 0x6: scan did not start because core is not capable of performing scan currently.
 * 0x7: scan debug mode.
 * 0x8: scan did not start because of exceed number of cpus attempt to run scan.
 * 0x9: scan did not start because interrupt occurred prior to scan execution.
 * bit 30: scan controller error. the installed SAF image is not valid.
 * bit 31: scan signature error. the scan signature did not match expected value.
 */
#define SCAN_PASS				0x0
#define NOT_ENOUGH_THREADS_JOINED		0x1
#define INTERRUPTED_DURING_COORDINATION		0x2
#define POWER_MANAGEMENT_INADEQUATE_FOR_SCAN	0x3
#define INVALID_CHUNK_RANGE			0x4
#define MISMATCH_ARGUMENTS_BETWEEN_THREADS	0x5
#define CORE_NOT_CAPABLE_CURRENTLY		0x6
#define SAF_DEBUG_MODE				0x7
#define EXCEED_NUMBER_OF_THREADS_CONCURRENT	0x8
#define INTERRUPTED_BEFORE_EXECUTION		0x9
#define SCAN_CONTROLL_ERROR			BIT(30)
#define SCAN_SIGNATURE_ERROR			BIT(31)

/**
 * struct saf_params - global saf parameter for all cpus.
 * @header_ptr: the pointer to the scan binary header.
 * @loaded_version: stores the currently loaded scan image version.
 * @hash_ptr: the linear address that points to scan hash loaded.
 * @test_image_ptr: the 512B aligned linear address that points to scan test chunk loaded.
 * @num_chunks: the number of chunks in scan binary.
 * @chunk_size: shows the chunk size.
 * @max_parallel_tests: the maximum numbers of cores that scan test can run simultaneously.
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
	int max_parallel_tests;
	bool loading_error;
	bool hash_valid;
	int valid_chunks;
};

/**
 * struct saf_state - per-cpu saf parameter.
 * @scan_task: scan_task for kthread to run scan test on each cpu.
 * @start_index: scan test start chunk.
 * @stop_index: scan test stop chunk.
 * @retry_count: it holds the retry count remaining.
 * @last_executed: it holds the last time scan was executed.
 * @result: it holds 64bit raw result after each scan test.
 * @siblings_in: sibling count for joining rendesvous.
 * @siblings_out: sibling count for exiting rendesvous.
 * @test_remain: number of tests to be finished per core.
 * @scan_wq: kthread task wait queue.
 * @mask: triggering the test by setting the mask.
 * @test_thread_done: set when scan are done for all siblings threads.
 */
struct saf_state {
	struct task_struct *scan_task;
	int start_index;
	int stop_index;
	int retry_count;
	int last_executed;
	u64 result;
	atomic_t siblings_in;
	atomic_t siblings_out;
	atomic_t test_remain;
	wait_queue_head_t scan_wq;
	struct cpumask mask;
	struct completion test_thread_done;
};

DECLARE_PER_CPU(struct saf_state, saf_state);

int load_scan_binary(void);
extern struct saf_params saf_params;
extern struct semaphore *sems;
extern int saf_threads_per_core;

#endif
