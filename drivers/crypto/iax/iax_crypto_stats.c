// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2021 Intel Corporation. All rights rsvd. */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <uapi/linux/idxd.h>
#include <linux/idxd.h>
#include <linux/dmaengine.h>
#include <linux/intel-svm.h>
#include "../../dma/idxd/idxd.h"
#include <linux/debugfs.h>
#include <crypto/internal/acompress.h>
#include "iax_crypto.h"
#include "iax_crypto_stats.h"

static u64 total_comp_calls;
static u64 total_decomp_calls;
static u64 max_comp_delay_ns;
static u64 max_decomp_delay_ns;
static u64 max_acomp_delay_ns;
static u64 max_adecomp_delay_ns;
static u64 total_comp_bytes_out;
static u64 total_decomp_bytes_in;
static u64 total_completion_einval_errors;
static u64 total_completion_timeout_errors;
static u64 total_completion_comp_buf_overflow_errors;

static struct dentry *iax_crypto_debugfs_root;

void update_total_comp_calls(void)
{
	total_comp_calls++;
}

void update_total_comp_bytes_out(int n)
{
	total_comp_bytes_out += n;
}

void update_total_decomp_calls(void)
{
	total_decomp_calls++;
}

void update_total_decomp_bytes_in(int n)
{
	total_decomp_bytes_in += n;
}

void update_completion_einval_errs(void)
{
	total_completion_einval_errors++;
}

void update_completion_timeout_errs(void)
{
	total_completion_timeout_errors++;
}

void update_completion_comp_buf_overflow_errs(void)
{
	total_completion_comp_buf_overflow_errors++;
}

void update_max_comp_delay_ns(u64 start_time_ns)
{
	u64 time_diff;

	time_diff = ktime_get_ns() - start_time_ns;

	if (time_diff > max_comp_delay_ns)
		max_comp_delay_ns = time_diff;
}

void update_max_decomp_delay_ns(u64 start_time_ns)
{
	u64 time_diff;

	time_diff = ktime_get_ns() - start_time_ns;

	if (time_diff > max_decomp_delay_ns)
		max_decomp_delay_ns = time_diff;
}

void update_max_acomp_delay_ns(u64 start_time_ns)
{
	u64 time_diff;

	time_diff = ktime_get_ns() - start_time_ns;

	if (time_diff > max_acomp_delay_ns)
		max_acomp_delay_ns = time_diff;
}

void update_max_adecomp_delay_ns(u64 start_time_ns)
{
	u64 time_diff;

	time_diff = ktime_get_ns() - start_time_ns;

	if (time_diff > max_adecomp_delay_ns)

		max_adecomp_delay_ns = time_diff;
}

void update_wq_comp_calls(struct idxd_wq *idxd_wq)
{
	struct iax_wq *wq = idxd_wq->private_data;

	wq->comp_calls++;
	wq->iax_device->comp_calls++;
}

void update_wq_comp_bytes(struct idxd_wq *idxd_wq, int n)
{
	struct iax_wq *wq = idxd_wq->private_data;

	wq->comp_bytes += n;
	wq->iax_device->comp_bytes += n;
}

void update_wq_decomp_calls(struct idxd_wq *idxd_wq)
{
	struct iax_wq *wq = idxd_wq->private_data;

	wq->decomp_calls++;
	wq->iax_device->decomp_calls++;
}

void update_wq_decomp_bytes(struct idxd_wq *idxd_wq, int n)
{
	struct iax_wq *wq = idxd_wq->private_data;

	wq->decomp_bytes += n;
	wq->iax_device->decomp_bytes += n;
}

void reset_iax_crypto_stats(void)
{
	total_comp_calls = 0;
	total_decomp_calls = 0;
	max_comp_delay_ns = 0;
	max_decomp_delay_ns = 0;
	max_acomp_delay_ns = 0;
	max_adecomp_delay_ns = 0;
	total_comp_bytes_out = 0;
	total_decomp_bytes_in = 0;
	total_completion_einval_errors = 0;
	total_completion_timeout_errors = 0;
	total_completion_comp_buf_overflow_errors = 0;
}

static void reset_wq_stats(struct iax_wq *wq)
{
	wq->comp_calls = 0;
	wq->comp_bytes = 0;
	wq->decomp_calls = 0;
	wq->decomp_bytes = 0;
}

void reset_device_stats(struct iax_device *iax_device)
{
	struct iax_wq *iax_wq;

	iax_device->comp_calls = 0;
	iax_device->comp_bytes = 0;
	iax_device->decomp_calls = 0;
	iax_device->decomp_bytes = 0;

	list_for_each_entry(iax_wq, &iax_device->wqs, list)
		reset_wq_stats(iax_wq);
}

static void wq_show(struct seq_file *m, struct iax_wq *iax_wq)
{
	seq_printf(m, "    name: %s\n", iax_wq->wq->name);
	seq_printf(m, "    comp_calls: %llu\n", iax_wq->comp_calls);
	seq_printf(m, "    comp_bytes: %llu\n", iax_wq->comp_bytes);
	seq_printf(m, "    decomp_calls: %llu\n", iax_wq->decomp_calls);
	seq_printf(m, "    decomp_bytes: %llu\n\n", iax_wq->decomp_bytes);
}

void device_stats_show(struct seq_file *m, struct iax_device *iax_device)
{
	struct iax_wq *iax_wq;

	seq_puts(m, "iax device:\n");
	seq_printf(m, "  id: %d\n", iax_device->idxd->id);
	seq_printf(m, "  n_wqs: %d\n", iax_device->n_wq);
	seq_printf(m, "  comp_calls: %llu\n", iax_device->comp_calls);
	seq_printf(m, "  comp_bytes: %llu\n", iax_device->comp_bytes);
	seq_printf(m, "  decomp_calls: %llu\n", iax_device->decomp_calls);
	seq_printf(m, "  decomp_bytes: %llu\n", iax_device->decomp_bytes);
	seq_puts(m, "  wqs:\n");

	list_for_each_entry(iax_wq, &iax_device->wqs, list)
		wq_show(m, iax_wq);
}

void global_stats_show(struct seq_file *m)
{
	seq_puts(m, "global stats:\n");
	seq_printf(m, "  total_comp_calls: %llu\n", total_comp_calls);
	seq_printf(m, "  total_decomp_calls: %llu\n", total_decomp_calls);
	seq_printf(m, "  total_comp_bytes_out: %llu\n", total_comp_bytes_out);
	seq_printf(m, "  total_decomp_bytes_in: %llu\n", total_decomp_bytes_in);
	seq_printf(m, "  total_completion_einval_errors: %llu\n", total_completion_einval_errors);
	seq_printf(m, "  total_completion_timeout_errors: %llu\n", total_completion_timeout_errors);
	seq_printf(m, "  total_completion_comp_buf_overflow_errors: %llu\n\n", total_completion_comp_buf_overflow_errors);
}

static int wq_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, wq_stats_show, file);
}

const struct file_operations wq_stats_fops = {
	.open = wq_stats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

DEFINE_DEBUGFS_ATTRIBUTE(wq_stats_reset_fops, NULL, iax_crypto_stats_reset, "%llu\n");

int __init iax_crypto_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	iax_crypto_debugfs_root = debugfs_create_dir("iax_crypto", NULL);
	if (!iax_crypto_debugfs_root)
		return -ENOMEM;

	debugfs_create_u64("max_comp_delay_ns", 0644,
			   iax_crypto_debugfs_root, &max_comp_delay_ns);
	debugfs_create_u64("max_decomp_delay_ns", 0644,
			   iax_crypto_debugfs_root, &max_decomp_delay_ns);
	debugfs_create_u64("max_acomp_delay_ns", 0644,
			   iax_crypto_debugfs_root, &max_comp_delay_ns);
	debugfs_create_u64("max_adecomp_delay_ns", 0644,
			   iax_crypto_debugfs_root, &max_decomp_delay_ns);
	debugfs_create_u64("total_comp_calls", 0644,
			   iax_crypto_debugfs_root, &total_comp_calls);
	debugfs_create_u64("total_decomp_calls", 0644,
			   iax_crypto_debugfs_root, &total_decomp_calls);
	debugfs_create_u64("total_comp_bytes_out", 0644,
			   iax_crypto_debugfs_root, &total_comp_bytes_out);
	debugfs_create_u64("total_decomp_bytes_in", 0644,
			   iax_crypto_debugfs_root, &total_decomp_bytes_in);
	debugfs_create_file("wq_stats", 0644, iax_crypto_debugfs_root, NULL,
			    &wq_stats_fops);
	debugfs_create_file("wq_stats_reset", 0644, iax_crypto_debugfs_root, NULL,
			    &wq_stats_reset_fops);

	return 0;
}

void __exit iax_crypto_debugfs_cleanup(void)
{
	debugfs_remove_recursive(iax_crypto_debugfs_root);
}

MODULE_LICENSE("GPL v2");
