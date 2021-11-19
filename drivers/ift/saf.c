// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/nmi.h>
#include <linux/platform_device.h>
#include <linux/semaphore.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/topology.h>
#include <asm/cpu_device_id.h>
#include <asm/microcode_intel.h>

#include "saf.h"
#include "saf_sysfs.h"

static const char *saf_path = "intel/ift/saf/";
static enum cpuhp_state cpuhp_scan_state;
static struct platform_device *saf_pdev;
static struct device *cpu_scan_device;
struct saf_params saf_params;
int saf_threads_per_core;
struct semaphore *sems;

DEFINE_PER_CPU(struct saf_state, saf_state);

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

static const char * const scan_test_status[] = {
	"SCAN pass",
	"Other thread could not join.",
	"Interrupt occurred prior to SCAN coordination.",
	"Core Abort SCAN Response due to power management condition.",
	"Non valid chunks in the range",
	"Mismatch in arguments between threads T0/T1.",
	"Core not capable of performing SCAN currently",
	"Debug Mode. ScanAt-Field results not to be trusted",
	"Exceeded number of Logical Processors (LP) allowed to run Scan-At-Field concurrently",
	"Interrupt occurred prior to SCAN start",
};

static inline unsigned long msec_to_tsc(unsigned long msec)
{
	return tsc_khz * 1000 * msec / MSEC_PER_SEC;
}

static void print_scan_test_status(int eax, int edx, int cpu)
{
	if (edx == 0)
		pr_info("cpu%d: %s", cpu, scan_test_status[edx]);
	else if (edx == SCAN_CONTROLL_ERROR)
		pr_info("cpu%d: %s", cpu,
			"The Installed SCAN program is not valid and must be reinstalled");
	else if (edx == SCAN_SIGNATURE_ERROR)
		pr_info("cpu%d: %s", cpu,
			"SCAN failed. The SCAN signature did not match expected value");
	else if (edx < ARRAY_SIZE(scan_test_status))
		pr_info("cpu%d: SCAN operation did not start. %s", cpu, scan_test_status[edx]);
}

static int wait_for_siblings(atomic_t *t, long long timeout)
{
	atomic_inc(t);
	while (atomic_read(t) < saf_threads_per_core) {
		if (timeout < SPINUNIT) {
			pr_err("Timeout while waiting for CPUs rendezvous, remaining: %d\n",
			       saf_threads_per_core - atomic_read(t));
			return 1;
		}

		ndelay(SPINUNIT);
		timeout -= SPINUNIT;

		touch_nmi_watchdog();
	}

	return 0;
}

/*
 * Initiating scan can be aborted under some conditions.
 * Check the retry SAF is needed from the error code.
 */
static inline bool saf_retry_needed(u32 edx)
{
	switch (edx) {
	case NOT_ENOUGH_THREADS_JOINED:
	case INTERRUPTED_DURING_COORDINATION:
	case POWER_MANAGEMENT_INADEQUATE_FOR_SCAN:
	case EXCEED_NUMBER_OF_THREADS_CONCURRENT:
	case INTERRUPTED_BEFORE_EXECUTION:
		return true;
	default:
		return false;
	}
}

/*
 * Scan test kthreads bound with each logical cpu.
 * Wait for the sibling thread to join before the execution.
 * Execute the scan test by running wrmsr(MSR_ACTIVATE_SCAN).
 */
static int scan_test_worker(void *info)
{
	u32 eax, edx, start, last, first;
	int cpu = smp_processor_id();

	while (1) {
		/* wait event until cpumask set from user */
		wait_event_interruptible(per_cpu(saf_state, cpu).scan_wq,
					 (cpumask_test_cpu(cpu, &per_cpu(saf_state, cpu).mask) ||
					 kthread_should_stop()));

		if (kthread_should_stop())
			break;

		/* wait for the sibling threads to join */
		first = cpumask_first(topology_sibling_cpumask(cpu));
		if (wait_for_siblings(&per_cpu(saf_state, first).siblings_in, NSEC_PER_SEC))
			return -1;

		/* disable interrupt during scan if noint set */
		if (noint)
			local_irq_disable();
		start = per_cpu(saf_state, cpu).start_index;
		last = per_cpu(saf_state, cpu).stop_index;
		eax = last << 8 | start;
retry:
		edx = (trigger_mce << 31) | msec_to_tsc(thread_wait);
		per_cpu(saf_state, cpu).result = SCAN_TEST_BUSY;

		/* scan start */
		wrmsr(MSR_ACTIVATE_SCAN, eax, edx);

		/*
		 * All logical CPUs on this core are now running SAF test. When it completes
		 * execution or is interrupted, the following RDMSR gets the scan status.
		 */

		rdmsr(MSR_SCAN_STATUS, eax, edx);

		/* retry when scan is aborted by interrupt or cpu power budget limitation */
		if (saf_retry_needed(edx) && per_cpu(saf_state, cpu).retry_count) {
			if (GET_BITFIELD(eax, 0, 7) == start)
				per_cpu(saf_state, cpu).retry_count -= 1;
			else
				per_cpu(saf_state, cpu).retry_count = MAX_RETRY;
			goto retry;
		}

		/* keep tracking the latest executed chunk */
		per_cpu(saf_state, cpu).start_index = GET_BITFIELD(eax, 0, 7);
		per_cpu(saf_state, cpu).result = ((u64)edx << 32) | eax;

		if (!quiet)
			print_scan_test_status(eax, edx, cpu);
		if (noint)
			local_irq_enable();

		/* log the last executed time */
		per_cpu(saf_state, cpu).last_executed = ktime_get_real_seconds();

		cpumask_clear_cpu(cpu, &per_cpu(saf_state, cpu).mask);
		if (atomic_dec_and_test(&per_cpu(saf_state, first).test_remain))
			complete(&per_cpu(saf_state, first).test_thread_done);

		if (wait_for_siblings(&per_cpu(saf_state, first).siblings_out, NSEC_PER_SEC))
			return -1;
	}

	return 0;
}

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
	saf_params.max_parallel_tests = GET_BITFIELD(edx, 19, 30) + 1;
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

	sems = vmalloc(sizeof(*sems) * topology_max_packages());
	if (!sems)
		goto out;

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
		sema_init(&sems[curr_pkg], saf_params.max_parallel_tests);
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

static int saf_online_cpu(unsigned int cpu)
{
	per_cpu(saf_state, cpu).scan_task = kthread_create_on_node(scan_test_worker, (void *)&cpu,
								   cpu_to_node(cpu), "safCpu/%u",
								   cpu);
	if (IS_ERR(per_cpu(saf_state, cpu).scan_task)) {
		pr_err("saf: scan_test_worker task create failed");
		return PTR_ERR(per_cpu(saf_state, cpu).scan_task);
	}
	kthread_bind(per_cpu(saf_state, cpu).scan_task, cpu);
	wake_up_process(per_cpu(saf_state, cpu).scan_task);

	return 0;
}

static int saf_offline_cpu(unsigned int cpu)
{
	struct task_struct *thread;

	thread = per_cpu(saf_state, cpu).scan_task;
	per_cpu(saf_state, cpu).scan_task = NULL;

	if (thread)
		kthread_stop(thread);

	return 0;
}

static int __init saf_init(void)
{
	const struct x86_cpu_id *m;
	struct device *root, *dev;
	u64 ia32_core_caps;
	int cpu, ret = -ENODEV;

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

	saf_threads_per_core = cpumask_weight(topology_sibling_cpumask(0));

	root = cpu_subsys.dev_root;
	cpu_scan_device = cpu_device_create(root, NULL, cpu_scan_attr_groups, "scan");

	cpus_read_lock();
	for_each_online_cpu(cpu) {
		/* create per-cpu sysfs */
		dev = get_cpu_device(cpu);
		ret = sysfs_create_group(&dev->kobj, &scan_attr_group);
		if (ret) {
			pr_err("saf: failed to create sysfs group");
			return ret;
		}
		/* initialize per-cpu variables */
		init_waitqueue_head(&(per_cpu(saf_state, cpu).scan_wq));
		cpumask_clear_cpu(cpu, &(per_cpu(saf_state, cpu).mask));
		init_completion(&per_cpu(saf_state, cpu).test_thread_done);

		/* set default start/stop chunk */
		per_cpu(saf_state, cpu).start_index = 0;
		per_cpu(saf_state, cpu).stop_index = saf_params.num_chunks - 1;
		per_cpu(saf_state, cpu).retry_count = MAX_RETRY;
	}
	cpus_read_unlock();
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "x86/saf:online",
				saf_online_cpu, saf_offline_cpu);

	if (ret < 0) {
		pr_err("saf: cpuhp_setup_failed");
		return ret;
	}
	cpuhp_scan_state = ret;

	return 0;
}

static void __exit saf_exit(void)
{
	struct task_struct *thread;
	struct device *dev;
	int cpu;

	vfree(sems);

	cpus_read_lock();
	for_each_online_cpu(cpu) {
		dev = get_cpu_device(cpu);
		sysfs_remove_group(&dev->kobj, &scan_attr_group);
		thread = per_cpu(saf_state, cpu).scan_task;
		per_cpu(saf_state, cpu).scan_task = NULL;
		if (thread)
			kthread_stop(thread);
	}
	device_unregister(cpu_scan_device);
	cpus_read_unlock();
	cpuhp_remove_state(cpuhp_scan_state);

	pr_info("saf: unloaded 'Scan At Field' module\n");
}

MODULE_LICENSE("GPL");
MODULE_INFO(name, "saf");
MODULE_DESCRIPTION("saf");
module_init(saf_init);
module_exit(saf_exit);
