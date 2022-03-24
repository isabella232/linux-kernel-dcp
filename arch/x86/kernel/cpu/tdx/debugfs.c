// SPDX-License-Identifier: GPL-2.0
/*
 * TDX-module debugfs
 * - tdx_seam/print_severity
 *   0: TRACE_ALL
 *   1: TRACE_WARN
 *   2: TRACE_ERROR
 *   1000: TRACE_CUSTOM
 * - tdx_seam/trace_target
 *   0: TRACE_BUFFER: output to buffer internal to TDX module
 *   1: TRACE_SERIAL_PORT: output to serial port
 *   2: TRACE_EXTERNAL_BUFFER: output to VMM buffer which is external
 *                             to TDX module
 * - tdx_seam/emergency
 *   0: noop
 *   1: set emergency buffer
 *
 * - tdx_seam/dump
 *   buffer from internal buffer of tdx seam module to VMM buffer
 *   only when trace_target is TRACE_BUFFER
 *
 * - tdx_seam/buffer_trace
 *   read the buffer for trace
 * - tdx_seam/buffer_dump
 *   read the buffer dumped from buffer internal to TDX module
 * - tdx_seam/buffer_emergency
 *   read the buffer for emergency dump
 *
 * Usage example:
 *   # change print_severity
 *   echo 0 > /sys/kernel/debug/tdx_seam/print_severity
 *
 *   # set buffer in KVM and read the trace
 *   echo 2 > /sys/kernel/debug/tdx_seam/trace_target
 *   cat /sys/kernel/debug/tdx_seam/buffer_trace
 *
 *   # make tdx module to record in its internal buffer
 *   # and dump it into KVM buffer
 *   echo 0 > /sys/kernel/debug/tdx_seam/trace_target
 *   echo 1 > /sys/kernel/debug/tdx_seam/dump
 *   cat /sys/kernel/debug/tdx_seam/buffer_dump
 *
 *   # set emergency buffer
 *   echo 1 > /sys/kernel/debug/tdx_seam/emergency
 *   # after tdx seam module panics
 *   cat /sys/kernel/debug/tdx_seam/buffer_emergency
 */

#include <linux/debugfs.h>
#include <linux/irqflags.h>
#include <linux/slab.h>

#include <asm/cpufeature.h>
#include <asm/trace/seam.h>
#include <asm/tdx_arch.h>
#include <asm/tdx_errno.h>
#include <asm/tdx_host.h>
#include <asm/virtext.h>

#include "seam.h"
#include "seamcall.h"
#include "tdx-ops.h"

/*
 * Enter VMX operation on current cpu (if not) and configure TDX module debug
 * sub-system via a seamcall and exit VMX operation (if vmxon was executed).
 */
static inline int do_tddebugconfig(u64 subleaf, u64 param1, u64 param2)
{
	u64 err;
	int ret = -EOPNOTSUPP;

	if (is_debug_seamcall_available) {
		preempt_disable();
		ret = cpu_vmx_get();
		if (ret) {
			preempt_enable();
			return ret;
		}
		err = tddebugconfig(subleaf, param1, param2);
		cpu_vmx_put();
		preempt_enable();
		if (err == TDX_OPERAND_INVALID) {
			pr_warn("TDX module doesn't support DEBUG TRACE SEAMCALL API\n");
			is_debug_seamcall_available = false;
			ret = -EOPNOTSUPP;
		} else if (err) {
			pr_err_ratelimited("SEAMCALL[TDDBUTCONFIG] failed on cpu %d: %s (0x%llx)\n",
					smp_processor_id(),
					tdx_seamcall_error_name(err), err);
			ret = -EIO;
		}
	}

	return ret;
}

static u64 trace_seamcalls;

static int print_severity_get(void *data, u64 *val)
{
	*val = trace_seamcalls;
	return 0;
}

static int print_severity_set(void *data, u64 val)
{
	int ret = -EINVAL;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EOPNOTSUPP;
	if (val == DEBUGCONFIG_TRACE_ALL ||
	    val == DEBUGCONFIG_TRACE_WARN ||
	    val == DEBUGCONFIG_TRACE_ERROR ||
	    val == DEBUGCONFIG_TRACE_CUSTOM ||
	    val == DEBUGCONFIG_TRACE_NONE) {
		do_tddebugconfig(DEBUGCONFIG_SET_TRACE_LEVEL, val, 0);
		trace_seamcalls = val;
		ret = 0;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(print_severity_fops,
			 print_severity_get, print_severity_set, "%llu\n");

static int trace_target = DEBUGCONFIG_TARGET_SERIAL_PORT;

#define TRACE_BUFFER_SIZE	4096
#define MAX_PRINT_LENGTH	256
#define BUFFER_SIZE		(TRACE_BUFFER_SIZE * MAX_PRINT_LENGTH)
static char *buffer_trace;

static int trace_target_get(void *data, u64 *val)
{
	*val = trace_target;
	return 0;
}

static int trace_target_set(void *data, u64 val)
{
	int ret = -EINVAL;
	u64 paddr = 0;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EOPNOTSUPP;

	switch (val) {
	case DEBUGCONFIG_TARGET_EXTERNAL_BUFFER:
		paddr = __pa(buffer_trace);
		fallthrough;
	case DEBUGCONFIG_TARGET_TRACE_BUFFER:
	case DEBUGCONFIG_TARGET_SERIAL_PORT:
		ret = do_tddebugconfig(DEBUGCONFIG_SET_TARGET, val, paddr);
		if (!ret)
			trace_target = val;
		break;
	default:
		/* nothing */
		break;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(trace_target_fops,
			 trace_target_get, trace_target_set, "%llu\n");

static char *buffer_emergency;
static bool emergency_configured;

static int emergency_get(void *data, u64 *val)
{
	*val = emergency_configured;
	return 0;
}

static int emergency_set(void *data, u64 val)
{
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_TDX))
		return -EOPNOTSUPP;

	/* emergency buffer can't be de-configured */
	if (!val && emergency_configured)
		return -EINVAL;

	memset(buffer_emergency, 0, BUFFER_SIZE);
	if (!emergency_configured) {
		ret = do_tddebugconfig(DEBUGCONFIG_SET_EMERGENCY_BUFFER,
				    __pa(buffer_emergency),
				    TRACE_BUFFER_SIZE);
		if (!ret)
			emergency_configured = true;
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(emergency_fops,
			 emergency_get, emergency_set, "%llu\n");

static char *buffer_dump;
static int dump_set(void *data, u64 val)
{
	int ret = -EINVAL;

	if (trace_target == DEBUGCONFIG_TARGET_TRACE_BUFFER) {
		memset(buffer_dump, 0, BUFFER_SIZE);
		ret = do_tddebugconfig(DEBUGCONFIG_DUMP_TRACE_BUFFER,
				    __pa(buffer_dump), TRACE_BUFFER_SIZE);
	}
	return ret;
}

DEFINE_DEBUGFS_ATTRIBUTE(dump_fops, NULL, dump_set, "%llu\n");

static void *buffer_start(struct seq_file *sfile, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;
	if (*pos > TRACE_BUFFER_SIZE)
		return NULL;
	return pos;
}

static void *buffer_next(struct seq_file *sfile, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos > TRACE_BUFFER_SIZE)
		return NULL;
	return pos;
}

static void buffer_stop(struct seq_file *sfile, void *v)
{
}

static int buffer_show(struct seq_file *sfile, void *v)
{
	char *buffer = sfile->private;

	if (v == SEQ_START_TOKEN) {
		if (buffer == buffer_trace)
			seq_puts(sfile, "------- trace buffer ------\n");
		else if (buffer == buffer_dump)
			seq_puts(sfile, "------- dump  buffer ------\n");
		else
			seq_puts(sfile, "------- emerg buffer ------\n");
	} else {
		int index = *((loff_t *)v) - 1;
		const char *buf = &buffer[MAX_PRINT_LENGTH * index];

		seq_printf(sfile, "%."__stringify(MAX_PRINT_LENGTH)"s", buf);
	}
	return 0;
}

static const struct seq_operations buffer_sops = {
	.start = buffer_start,
	.next = buffer_next,
	.stop = buffer_stop,
	.show = buffer_show,
};

DEFINE_SEQ_ATTRIBUTE(buffer);

static struct dentry *tdx_seam;

int __init tdx_debugfs_init(void)
{
	int ret = 0;

	if (!boot_cpu_has(X86_FEATURE_TDX) || !is_debug_seamcall_available)
		return 0;

	ret = -ENOMEM;
	buffer_trace = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_trace)
		goto err;

	buffer_emergency = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_emergency)
		goto err;

	buffer_dump = kcalloc(TRACE_BUFFER_SIZE, MAX_PRINT_LENGTH, GFP_KERNEL_ACCOUNT);
	if (!buffer_dump)
		goto err;

	tdx_seam = debugfs_create_dir("tdx_seam", NULL);

	debugfs_create_file("print_severity", 0600,
			    tdx_seam, NULL, &print_severity_fops);
	debugfs_create_file("trace_target", 0600,
			    tdx_seam, NULL, &trace_target_fops);
	debugfs_create_file("emergency", 0600,
			    tdx_seam, NULL, &emergency_fops);

	debugfs_create_file("dump", 0200,
			    tdx_seam, NULL, &dump_fops);
	debugfs_create_file("buffer_trace", 0400,
			    tdx_seam, buffer_trace, &buffer_fops);
	debugfs_create_file("buffer_dump", 0400,
			    tdx_seam, buffer_dump, &buffer_fops);
	debugfs_create_file("buffer_emergency", 0400,
			    tdx_seam, buffer_emergency, &buffer_fops);

	return 0;
err:
	kfree(buffer_trace);
	kfree(buffer_emergency);
	kfree(buffer_dump);
	return ret;
}
