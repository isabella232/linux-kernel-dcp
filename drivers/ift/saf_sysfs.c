// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#include <linux/delay.h>
#include <linux/cpu.h>
#include <linux/fs.h>

#include "saf_sysfs.h"
#include "saf.h"

static int core_delay = 1;
int trigger_mce;
int thread_wait = 0xFFFFFFF;
bool all_cores_busy;
bool quiet;
bool noint;

/*
 * Initiate per core test. It wakes up all sibling threads that belongs to the
 * target cpu. Once all sibling threads wake up, the scan test gets executed and
 * wait for all sibling threads to finish the scan test.
 */
static void do_core_test(int cpu)
{
	int sibling, first;

	/* all siblings update only first cpu completion variables */
	first = cpumask_first(topology_sibling_cpumask(cpu));
	reinit_completion(&per_cpu(saf_state, first).test_thread_done);
	atomic_set(&(per_cpu(saf_state, first).siblings_in), 0);
	atomic_set(&(per_cpu(saf_state, first).siblings_out), 0);
	atomic_set(&(per_cpu(saf_state, first).test_remain), 0);

	if (cpumask_weight(topology_sibling_cpumask(cpu)) != saf_threads_per_core) {
		pr_warn("saf: cpu%d not have enough siblings, skipping it\n", cpu);
		return;
	}
	for_each_cpu(sibling, topology_sibling_cpumask(cpu)) {
		cpumask_set_cpu(sibling, &per_cpu(saf_state, sibling).mask);
		atomic_inc(&per_cpu(saf_state, first).test_remain);
	}
	for_each_cpu(sibling, topology_sibling_cpumask(cpu))
		wake_up_interruptible(&per_cpu(saf_state, sibling).scan_wq);

	wait_for_completion_interruptible_timeout(&per_cpu(saf_state, first).test_thread_done, HZ);
}

/*
 * The sysfs interface to check the scan test result:
 * To check the result, for example, cpu0
 * cat /sys/devices/system/cpu/cpu0/scan/scan_result
 */
static ssize_t scan_result_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	unsigned int cpu = dev->id;

	return sprintf(buf, "%llx\n", per_cpu(saf_state, cpu).result);
}

static DEVICE_ATTR_RO(scan_result);

/*
 * The sysfs interface for single core testing
 * To start test, for example, cpu0
 * echo 1 > /sys/devices/system/cpu/cpu0/scan/scan_start
 * To check the result:
 * cat /sys/devices/system/cpu/cpu0/scan/scan_result
 * The sibling core gets tested at the same time.
 */
static ssize_t scan_start_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned int cpu = dev->id;
	u64 last_execution;
	int sibling, rc;
	bool var;

	rc = kstrtobool(buf, &var);
	if (rc || var != 1)
		return rc;

	if (all_cores_busy) {
		pr_warn("saf: All core test running, wait until it finishes");
		return -EINVAL;
	}
	for_each_cpu(sibling, topology_sibling_cpumask(cpu)) {
		if (per_cpu(saf_state, sibling).result == SCAN_TEST_BUSY) {
			pr_warn("saf: Test running in this core, wait until it finishes");
			return -EINVAL;
		}
	}
	/* the minimum wait time is to ensure that scan execution is not overlapped */
	last_execution = per_cpu(saf_state, cpu).last_executed;
	if ((ktime_get_real_seconds() - last_execution) < MINIMUM_SAF_INTERVAL) {
		pr_info("saf: the minimum saf interval is 1 min.");
		return count;
	}
	cpu_hotplug_disable();
	down(&sems[topology_physical_package_id(cpu)]);
	do_core_test(cpu);
	up(&sems[topology_physical_package_id(cpu)]);
	cpu_hotplug_enable();

	return count;
}

static DEVICE_ATTR_WO(scan_start);

/*
 * The current_chunk shows the last executed chunk before the
 * interrupt. If the scan test finishes gracefully, it shows the last chunk.
 */
static ssize_t current_chunk_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	unsigned int cpu = dev->id;

	return sprintf(buf, "%u\n", per_cpu(saf_state, cpu).start_index - 1);
}

static DEVICE_ATTR_RO(current_chunk);

/*
 * User can specify the start chunk of the scan test via sysfs.
 * The start chunk should be set before the test execution.
 */
static ssize_t start_chunk_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	unsigned int cpu = dev->id;
	int var, rc, sibling;

	rc = kstrtoint(buf, 10, &var);
	if (rc)
		return rc;

	if (var < 0 || var >= saf_params.num_chunks) {
		pr_err("saf: invalid start_chunk range");
		return -EINVAL;
	}
	for_each_cpu(sibling, topology_sibling_cpumask(cpu))
		per_cpu(saf_state, sibling).start_index = var;

	return count;
}

static ssize_t start_chunk_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	unsigned int cpu = dev->id;

	return sprintf(buf, "%u\n", per_cpu(saf_state, cpu).start_index);
}

static DEVICE_ATTR_RW(start_chunk);

/*
 * User can specify the stop chunk of the scan test via sysfs.
 * The stop chunk should be set before the test execution.
 */
static ssize_t stop_chunk_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	unsigned int cpu = dev->id;
	int var, rc, sibling;

	rc = kstrtoint(buf, 10, &var);
	if (rc)
		return rc;

	if (var < 0 || var >= saf_params.num_chunks) {
		pr_err("saf: invalid stop_chunk range");
		return -EINVAL;
	}
	for_each_cpu(sibling, topology_sibling_cpumask(cpu))
		per_cpu(saf_state, sibling).stop_index = var;

	return count;
}

static ssize_t stop_chunk_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	unsigned int cpu = dev->id;

	return sprintf(buf, "%u\n", per_cpu(saf_state, cpu).stop_index);
}

static DEVICE_ATTR_RW(stop_chunk);

/* per-cpu scan sysfs attributes */
static struct attribute *scan_attrs[] = {
	&dev_attr_scan_start.attr,
	&dev_attr_scan_result.attr,
	&dev_attr_current_chunk.attr,
	&dev_attr_start_chunk.attr,
	&dev_attr_stop_chunk.attr,
	NULL
};

const struct attribute_group scan_attr_group = {
	.attrs	= scan_attrs,
	.name = "scan",
};

/*
 * Reload the SAF image. When user wants to install new SAF image
 * image, reloading must be done.
 */
static ssize_t reload_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf, size_t count)
{
	bool var;
	int rc;

	rc = kstrtobool(buf, &var);
	if (rc < 0)
		return -EINVAL;

	rc = load_scan_binary();
	if (rc < 0) {
		pr_info("saf: error, failed to load scan hash and test");
		return -EINVAL;
	}

	return count;
}

static DEVICE_ATTR_WO(reload);

/*
 * The sysfs interface to execute scan test for all online cpus.
 * The test can be triggered as below:
 * echo 1 > /sys/devices/system/cpu/scan/run_test_all
 */
static ssize_t run_test_all_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct cpumask snapshot_mask;
	int rc, sibling, cpu = 0;
	u64 last_execution;
	bool var;

	rc = kstrtobool(buf, &var);
	if (rc < 0)
		return -EINVAL;

	/* the minimum wait time is to ensure that scan execution is not overlapped */
	last_execution = per_cpu(saf_state, cpu).last_executed;
	if ((ktime_get_real_seconds() - last_execution) < MINIMUM_SAF_INTERVAL) {
		pr_info("saf: the minimum saf interval is 1 min.");
		return count;
	}
	cpu_hotplug_disable();
	all_cores_busy = 1;

	/* since one test run for all sibling threads, snapshot_mask clears bits accordingly */
	cpumask_copy(&snapshot_mask, cpu_online_mask);
	for_each_cpu(cpu, &snapshot_mask) {
		/* the sibling thread should have the same test chunks setting */
		for_each_cpu(sibling, topology_sibling_cpumask(cpu)) {
			per_cpu(saf_state, sibling).start_index = 0;
			per_cpu(saf_state, sibling).stop_index = saf_params.num_chunks - 1;
		}
		do_core_test(cpu);
		for_each_cpu(sibling, topology_sibling_cpumask(cpu))
			cpumask_clear_cpu(sibling, &snapshot_mask);
		mdelay(core_delay);
	}
	all_cores_busy = 0;
	cpu_hotplug_enable();

	return count;
}

static DEVICE_ATTR_WO(run_test_all);

/*
 * The driver enumerates how many chunks the SAF image has.
 * User can decide to either test all chunks or partial chunks.
 */
static ssize_t num_chunks_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%u\n", saf_params.num_chunks);
}

static DEVICE_ATTR_RO(num_chunks);

/*
 * The driver enumerates how big each chunk size is in KBs.
 */
static ssize_t chunk_size_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%u\n", saf_params.chunk_size);
}

static DEVICE_ATTR_RO(chunk_size);

/*
 * The delay(ms) between each core test when all core tests are
 * running.
 */
static ssize_t core_delay_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%u\n", core_delay);
}

static ssize_t core_delay_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	int var, rc;

	rc = kstrtoint(buf, 10, &var);
	if (rc < 0)
		return -EINVAL;

	core_delay = var;

	return count;
}
static DEVICE_ATTR_RW(core_delay);

/*
 * If set, the interrupt is disabled during scan test.
 */
static ssize_t noint_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	return sprintf(buf, "%u\n", noint);
}

static ssize_t noint_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int var, rc;

	rc = kstrtoint(buf, 10, &var);
	if (rc < 0)
		return -EINVAL;

	noint = var;

	return count;
}
static DEVICE_ATTR_RW(noint);

/*
 * If set, it goes to non-verbose mode and it does not show logs.
 * User can still check the scan result via sysfs such as scan_result.
 */
static ssize_t quiet_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	return sprintf(buf, "%u\n", quiet);
}

static ssize_t quiet_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int var, rc;

	rc = kstrtoint(buf, 10, &var);
	if (rc < 0)
		return -EINVAL;

	quiet = var;

	return count;
}
static DEVICE_ATTR_RW(quiet);

/*
 * If set, on scan test error, it signals Machine Check Error.
 */
static ssize_t trigger_mce_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%u\n", trigger_mce);
}

static ssize_t trigger_mce_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	int var, rc;

	rc = kstrtoint(buf, 10, &var);
	if (rc < 0)
		return -EINVAL;

	trigger_mce = var;

	return count;
}
static DEVICE_ATTR_RW(trigger_mce);

/*
 * The maximum wait time (ms) for all sibling threads to join before running
 * scan test.
 */
static ssize_t thread_wait_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%u\n", thread_wait);
}

static ssize_t thread_wait_store(struct device *dev,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	int var, rc;

	rc = kstrtoint(buf, 10, &var);
	if (rc < 0)
		return -EINVAL;

	thread_wait = var;

	return count;
}
static DEVICE_ATTR_RW(thread_wait);

/*
 * The maximum number of cores that can run scan test simultaneously.
 */
static ssize_t max_parallel_tests_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf)
{
	return sprintf(buf, "%u\n", saf_params.max_parallel_tests);
}

static DEVICE_ATTR_RO(max_parallel_tests);

/*
 * The hash_valid is set when scan hash is successfully copied.
 */
static ssize_t hash_valid_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	return sprintf(buf, "%u\n", saf_params.hash_valid);
}

static DEVICE_ATTR_RO(hash_valid);

/*
 * Total number of authenticated chunks.
 */
static ssize_t valid_chunks_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	return sprintf(buf, "%u\n", saf_params.valid_chunks);
}

static DEVICE_ATTR_RO(valid_chunks);

/*
 * Currently loaded SAF image version.
 */
static ssize_t image_version_show(struct device *dev,
				  struct device_attribute *attr,
				  char *buf)
{
	return sprintf(buf, "%x\n", saf_params.loaded_version);
}

static DEVICE_ATTR_RO(image_version);

/* global scan sysfs attributes */
static struct attribute *cpu_scan_attrs[] = {
	&dev_attr_reload.attr,
	&dev_attr_run_test_all.attr,
	&dev_attr_num_chunks.attr,
	&dev_attr_chunk_size.attr,
	&dev_attr_core_delay.attr,
	&dev_attr_noint.attr,
	&dev_attr_quiet.attr,
	&dev_attr_trigger_mce.attr,
	&dev_attr_thread_wait.attr,
	&dev_attr_max_parallel_tests.attr,
	&dev_attr_hash_valid.attr,
	&dev_attr_valid_chunks.attr,
	&dev_attr_image_version.attr,
	NULL
};

const struct attribute_group cpu_scan_attr_group = {
	.attrs = cpu_scan_attrs,
};

const struct attribute_group *cpu_scan_attr_groups[] = {
	&cpu_scan_attr_group,
	NULL,
};
