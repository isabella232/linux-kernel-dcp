/*
 * Copyright © 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * Authors: Jacob Pan <jacob.jun.pan@linux.intel.com>
 *
 */

#define pr_fmt(fmt)     "INTEL_IOMMU: " fmt
#include <linux/err.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/pm_runtime.h>
#include <linux/debugfs.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>
#include <linux/dmar.h>
#include <linux/pci.h>

#include "irq_remapping.h"

static DEFINE_MUTEX(iommu_debug_lock);

static struct dentry *iommu_debug_root;

#define TOTAL_BUS_NR (256) /* full bus range 256 */

static int intel_iommu_debug_show(struct seq_file *m, void *unused)
{
	struct intel_iommu *iommu;
	struct dmar_drhd_unit *drhd;
	struct context_entry *context;
	struct root_entry *root_tbl;
	int bus, idx, ctx;
	u64 rtaddr_reg;
	bool new_ext, ext;


	rcu_read_lock();
	for_each_active_iommu(iommu, drhd) {
		if (iommu) {
			rtaddr_reg = dmar_readq(iommu->reg + DMAR_RTADDR_REG);
			ext        = !!(rtaddr_reg & DMA_RTADDR_RTT);
			new_ext    = !!ecap_ecs(iommu->ecap);
			if (new_ext != ext) {
				seq_printf(m, "IOMMU %s: invalid ecs\n", iommu->name);
				return -EINVAL;
			}
			seq_printf(m, "IOMMU %s: Dump %s Context\n", iommu->name,
				ext ? "Extended" : "");
			for (bus = 0; bus < TOTAL_BUS_NR; bus++) {
				idx = ext ? bus * 2 : bus;
				if (!iommu->root_entry[bus].lo)
					continue;
				root_tbl = (struct root_entry *)phys_to_virt((rtaddr_reg & ~0xfff));
				seq_printf(m, "Root Table: L: %llx H: %llx\n",
					root_tbl->lo,
					root_tbl->hi);

				seq_printf(m, "Bus %d Root Table Reg:%llx L: %llx H: %llx\n",
					bus,
					rtaddr_reg,
					iommu->root_entry[bus].lo,
					iommu->root_entry[bus].hi);
				seq_printf(m, "[ID]\tB:D.F\tLow\t\tHigh\n");
				for (ctx = 0; ctx < 256; ctx++) {
					context = iommu_context_addr(iommu, bus, ctx, 0);
					if (context && (context->lo & 1)) {
						seq_printf(m, "[%d]\t%x:%x.%x\t%llx\t\t%llx\n",
							ctx,
							bus, PCI_SLOT(ctx), PCI_FUNC(ctx),
							context[0].lo, context[0].hi);
						if (ext) {
							seq_printf(m, "E[%d]\t%x:%x.%x\t%llx\t\t%llx\n",
								ctx,
								bus, PCI_SLOT(ctx), PCI_FUNC(ctx),
								context[1].lo, context[1].hi);
						}
					}
				}
			}
		}
	}
	rcu_read_unlock();

	rcu_read_lock();

	seq_printf(m,"IRTE for remapped interrupt:: vt-d 9.10 section\n");
	seq_printf(m,"SID\t\tDestination ID\tPresent\n");
        for_each_active_iommu(iommu, drhd) {
		if (iommu) {
			for (idx = 0; idx < INTR_REMAP_TABLE_ENTRIES; idx++) {
				if (iommu->ir_table->base[idx].present&&!iommu->ir_table->base[idx].p_pst)
					seq_printf(m,"%04x\t\t%08x\t%d \n",iommu->ir_table->base[idx].sid,
							iommu->ir_table->base[idx].dest_id,
							iommu->ir_table->base[idx].present);
			}

		  }

	}
	seq_printf(m,"IRTE for posted interrupt:: vt-d 9.11 section\n");
	seq_printf(m,"PID high\tPID low\t\tSID\t\tIM(1)\t\tPresent\n");
        for_each_active_iommu(iommu, drhd) {
		if (iommu) {
			for (idx = 0; idx < INTR_REMAP_TABLE_ENTRIES; idx++) {
				if (iommu->ir_table->base[idx].present&&iommu->ir_table->base[idx].p_pst)
					seq_printf(m,"%08x\t%08x\t%04x\t\t%d\t\t%d \n",iommu->ir_table->base[idx].pda_h,
							(iommu->ir_table->base[idx].pda_l)<<6,
							iommu->ir_table->base[idx].sid,
							iommu->ir_table->base[idx].p_pst,
							iommu->ir_table->base[idx].present);
			}

		  }
	}
        rcu_read_unlock();
	return 0;
}

static int intel_iommu_debug_open(struct inode *inode,
			struct file *file)
{
	return single_open(file, intel_iommu_debug_show, inode->i_private);
}

static const struct file_operations intel_iommu_debug_fops = {
	.open		= intel_iommu_debug_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.owner		= THIS_MODULE,
};

void __init intel_iommu_debugfs_init(void)
{
	iommu_debug_root = debugfs_create_dir("intel_iommu", NULL);

	if (!iommu_debug_root)
		pr_err("can't create debugfs dir\n");

	if (!debugfs_create_file("intel_iommu_ctx", S_IRUGO, iommu_debug_root,
					NULL, &intel_iommu_debug_fops))
		debugfs_remove_recursive(iommu_debug_root);

}

void __exit intel_iommu_debugfs_exit(void)
{
	debugfs_remove(iommu_debug_root);
}
