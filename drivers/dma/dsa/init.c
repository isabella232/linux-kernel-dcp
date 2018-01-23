/*
 * Intel I/OAT DMA Linux driver
 * Copyright(c) 2004 - 2015 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/dmaengine.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>
#include <linux/prefetch.h>
#include <linux/poll.h>
#include <linux/dca.h>
#include <linux/aer.h>
#include <linux/fs.h>
#include <linux/intel-svm.h>
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

MODULE_VERSION(DSA_DMA_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Intel Corporation");

#define DRV_NAME "dsa"

static struct pci_device_id dsa_pci_tbl[] = {
	/* DSA vr1.0 platforms */
	{ PCI_VDEVICE(INTEL, PCI_DEVICE_ID_INTEL_DSA_SPR0) },

	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dsa_pci_tbl);

/* This is a list of DSA devices in the platform. */
static struct list_head dsa_devices;
unsigned int num_dsa_devices = 0;

struct dsadma_device *get_dsadma_device_by_minor(unsigned int minor)
{
	struct dsadma_device *dsa;

	list_for_each_entry(dsa, &dsa_devices, list) {
		if (dsa->misc_dev.minor == minor)
			return dsa;
	}
	return NULL;
}


static int dsa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void dsa_remove(struct pci_dev *pdev);
static int dsa_init_wq(struct dsadma_device *dsa_dma, int idx);
static void dsa_enumerate_capabilities(struct dsadma_device *dsa_dma);
static int dsa_configure_groups(struct dsadma_device *dsa);
static int dsa_configure_work_queues(struct dsadma_device *dsa);

static int dsa_num_dwqs = 0;
module_param(dsa_num_dwqs, int, 0644);
MODULE_PARM_DESC(dsa_num_dwqs, "Number of DWQs");

static int dsa_num_swqs = 0;
module_param(dsa_num_swqs, int, 0644);
MODULE_PARM_DESC(dsa_num_swqs, "Number of SWQs");

static int selftest = 0;
module_param(selftest, int, 0644);
MODULE_PARM_DESC(selftest, "Perform Selftest");

static int dmachan = 1;
module_param(dmachan, int, 0644);
MODULE_PARM_DESC(dmachan, "Allocate a WQ for DMAEngine APIs");

int ms_to = 10000;
module_param(ms_to, int, 0644);
MODULE_PARM_DESC(ms_to, "Timeout in milliseconds for various ops");

static int enable_vdsa = 0;
module_param(enable_vdsa, int, 0644);
MODULE_PARM_DESC(enable_vdsa, "Set to 1 if dsa driver support virtualization");

struct kmem_cache *dsa_cache;

void dsa_change_wq_reg (struct dsadma_device *dsa, int wq_idx, int reg_offset,
		u32 val)
{
	unsigned int wq_offset;

	printk("change wq %d off %x val %x\n", wq_idx, reg_offset, val);
	/* Each WQCONFIG register is 32 bytes */
	wq_offset = dsa->wq_offset + wq_idx * 32 + reg_offset;

	writel(val, dsa->reg_base + wq_offset);
}


int dsa_enable_wq (struct dsadma_device *dsa, int wq_idx)
{
	int j;
	int iterations = ms_to * 10;
	union dsa_command_reg cmd;
	struct dsa_work_queue *wq = &dsa->wqs[wq_idx];
	u32 cmdsts;

	if (wq->wq_enabled == true)
		return 0;

	memset(&cmd, 0, sizeof(cmd));

	cmd.fields.cmd = DSA_ENABLE_WQ;
	cmd.fields.operand = wq_idx;

	spin_lock(&dsa->cmd_lock);
	writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

	for (j = 0; j < iterations; j++) {
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}
	spin_unlock(&dsa->cmd_lock);

	if ((j == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK)) {
		printk("Error enabling the wq %d %x\n", wq_idx,
				readl(dsa->reg_base + DSA_CMDSTS_OFFSET));
		return 1;
	}

	wq->wq_enabled = true;
	return 0;
}

/* We disable only 1 WQ at a time */
int dsa_disable_wq (struct dsadma_device *dsa, int wq_idx)
{
	int j;
	int iterations = ms_to * 10;
	union dsa_command_reg cmd;
	struct dsa_work_queue *wq = &dsa->wqs[wq_idx];
	u32 cmdsts;

	if (wq->wq_enabled == false)
		return 0;

	memset(&cmd, 0, sizeof(cmd));

	cmd.fields.cmd = DSA_DISABLE_WQ;
	cmd.fields.operand = 1 << wq_idx;

	spin_lock(&dsa->cmd_lock);
	writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

	for (j = 0; j < iterations; j++) {
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}

	spin_unlock(&dsa->cmd_lock);
	if ((j == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK))
		return 1;

	wq->wq_enabled = false;
	return 0;
}

/**
 * dsa_enable_system_pasid - configure a system PASID for use with kernel
 * virtual addresses. SWQ does not work without PASID.
 * @dsa_dma: dsa dma device
 */
static void dsa_enable_system_pasid(struct dsadma_device *dsa)
{
	int ret, pasid, flags = 0;
	struct dsa_context *ctx = &dsa->priv_ctx;

        /* Allocate and bind a PASID */
	flags |= SVM_FLAG_SUPERVISOR_MODE;

        ret = intel_svm_bind_mm(&dsa->pdev->dev, &pasid, flags, NULL);
	if (ret) {
		printk("sys pasid alloc failed %d: can't use SWQs\n", ret);
		dsa->pasid_enabled = false;
		return;
	}

	INIT_LIST_HEAD(&ctx->mm_list);
	INIT_LIST_HEAD(&ctx->wq_list);

	ctx->pasid = pasid;
	ctx->dsa = dsa;
        ctx->svm_dev = &dsa->pdev->dev;

	printk("system pasid %d\n", pasid);

	dsa->pasid_enabled = true;
	dsa->system_pasid = pasid;
}


static int dsa_disable_system_pasid(struct dsadma_device *dsa)
{
	int ret = 0;
	struct dsa_context *ctx = &dsa->priv_ctx;

        if (ctx->svm_dev) {
                dsa_ctx_drain_pasid(ctx, 0);

        	ret = intel_svm_unbind_mm(ctx->svm_dev, ctx->pasid);
		if (ret) {
			printk("sys pasid unbind failed %d\n", ret);
			return ret;
		}
        }

	dsa->pasid_enabled = false;

	return ret;
}

/**
 * dsa_disable_device - disable the device and its work queues
 * @dsa_dma: dsa dma device
 */
static int dsa_disable_device(struct dsadma_device *dsa)
{
	int i, err = 0;
	union dsa_command_reg cmd;
	u32 cmdsts;
	struct device *dev = &dsa->pdev->dev;
	int iterations = ms_to * 10;

	memset(&cmd, 0, sizeof(cmd));

	/* Enable the device first */
	cmd.fields.cmd = DSA_DISABLE;

	spin_lock(&dsa->cmd_lock);
	writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

	for (i = 0; i < iterations; i++) {
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}

	spin_unlock(&dsa->cmd_lock);
	if ((i == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK)) {
		dev_err(dev, "Error disabling the device %d %x\n", i,
						cmdsts & DSA_CMD_ERRCODE_MASK);
		err = -ENODEV;
	} else {
		for (i = 0; i < dsa->num_wqs; i++)
			dsa->wqs[i].wq_enabled = false;
	}

	return err;
}

static int dsa_enable_wqs(struct dsadma_device *dsa)
{
	int i, err = 0;
	union dsa_command_reg cmd;
	u32 cmdsts;
	struct device *dev = &dsa->pdev->dev;
	int iterations = ms_to * 10;

	memset(&cmd, 0, sizeof(cmd));

	/* Enable the WQs */
	cmd.fields.cmd = DSA_ENABLE_WQ;
	for (i = 0; i < dsa->num_wqs; i++) {
		int j;

		cmd.fields.operand = i;

		spin_lock(&dsa->cmd_lock);
		writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

		for (j = 0; j < iterations; j++) {
			cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
			if (!(cmdsts & DSA_CMD_ACTIVE))
				break;
		}

		spin_unlock(&dsa->cmd_lock);
		if ((j == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK)) {
			dev_err(dev, "Error enabling the wq %d %d %x\n", i, j,
						cmdsts & DSA_CMD_ERRCODE_MASK);
			err = -ENODEV;
		} else
			dsa->wqs[i].wq_enabled = true;
	}
	return err;
}

/**
 * dsa_enable_device - enable the device and its work queues
 * @dsa_dma: dsa dma device
 */
static int dsa_enable_device(struct dsadma_device *dsa)
{
	int i, err = 0;
	union dsa_command_reg cmd;
	u32 cmdsts;
	struct device *dev = &dsa->pdev->dev;
	int iterations = ms_to * 10;

	memset(&cmd, 0, sizeof(cmd));

	/* Enable the device */
	cmd.fields.cmd = DSA_ENABLE;

	spin_lock(&dsa->cmd_lock);
	writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

	for (i = 0; i < iterations; i++) {
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}

	spin_unlock(&dsa->cmd_lock);
	if ((i == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK)) {
		dev_err(dev, "Error enabling the device %d %x\n", i,
						cmdsts & DSA_CMD_ERRCODE_MASK);
		err = -ENODEV;
	}

	return err;
}

/**
 * dsa_dma_setup_interrupts - setup interrupt handler
 * @dsa_dma: dsa dma device
 */
int dsa_dma_setup_interrupts(struct dsadma_device *dsa)
{
	struct pci_dev *pdev = dsa->pdev;
	struct device *dev = &pdev->dev;
	struct msix_entry *msix;
	struct dsa_irq_entry *irq_entry;
	int i, j, msixcnt;
	int err = -EINVAL;
	u32 genctrl = 0;
	unsigned long data;

	/* The number of MSI-X vectors should equal the number of channels */
	msixcnt = pci_msix_vec_count(pdev);

	if (msixcnt < 0) {
		dev_err(dev, "not MSI-X interrupt capable\n");
		goto err_no_irq;
	}

	dsa->msix_entries = devm_kzalloc(dev, sizeof(struct msix_entry) *
						msixcnt, GFP_KERNEL);

	if (dsa->msix_entries == NULL) {
		dev_err(dev, "Allocating %d MSI-X entries!\n", msixcnt);
		err = -ENOMEM;
		goto err_no_irq;
	}

	for (i = 0; i < msixcnt; i++)
		dsa->msix_entries[i].entry = i;

	dsa->allocated_ims = devm_kzalloc(dev, sizeof(unsigned long) *
				BITS_TO_LONGS(dsa->ims_size), GFP_KERNEL);

	if (dsa->allocated_ims == NULL) {
		dev_err(dev, "Alloc bitmap %d ims entries!\n", dsa->ims_size);
		err = -ENOMEM;
		goto err_no_irq;
	}

	err = pci_enable_msix_exact(pdev, dsa->msix_entries, msixcnt);
	if (err) {
		dev_err(dev, "Enabling %d MSI-X entries!\n", msixcnt);
		goto err_no_irq;
	}

	/* we implement 1 completion ring per MSI-X entry except for entry 0 */
	dsa->irq_entries = devm_kzalloc(dev, sizeof(struct dsa_irq_entry) *
						msixcnt, GFP_KERNEL);

	/* first MSI-X entry is not for wq interrupts */
	dsa->num_wq_irqs = msixcnt - 1;
	atomic_set(&dsa->irq_wq_next, 0);
	atomic_set(&dsa->num_allocated_ims, 0);

	if (dsa->irq_entries == NULL) {
		dev_err(dev, "Allocating %d irq entries!\n", msixcnt);
		err = -ENOMEM;
		goto err_no_irq;
	}

	for (i = 0; i < msixcnt; i++) {
		msix = &dsa->msix_entries[i];
		irq_entry = &dsa->irq_entries[i];

		data = (unsigned long)irq_entry;
		irq_entry->dsa = dsa;
		irq_entry->int_src = i;
		spin_lock_init(&irq_entry->cleanup_lock);
		INIT_LIST_HEAD(&irq_entry->irq_wait_head);
		rwlock_init(&irq_entry->irq_wait_lock);

		if (i == 0) {
			err = devm_request_irq(dev, msix->vector,
				       dsa_misc_interrupt, 0,
				       "dsa-msix", irq_entry);
			tasklet_init(&irq_entry->cleanup_task, dsa_misc_cleanup,
								data);
		} else {
			err = devm_request_irq(dev, msix->vector,
				       dsa_wq_completion_interrupt, 0,
				       "dsa-msix", irq_entry);
			tasklet_init(&irq_entry->cleanup_task, dsa_wq_cleanup,
							data);
		}
		if (err) {
			for (j = 0; j < i; j++) {
				msix = &dsa->msix_entries[j];
				irq_entry = &dsa->irq_entries[i];
				devm_free_irq(dev, msix->vector, irq_entry);
				tasklet_kill(&irq_entry->cleanup_task);
			}
			goto err_no_irq;
		}
	}
	genctrl = DSA_GENCTRL_HWERR_ENABLE | DSA_GENCTRL_SWERR_ENABLE;
	writel(genctrl, dsa->reg_base + DSA_GENCTRL_OFFSET);

	return 0;

err_no_irq:
	/* Disable all interrupt generation */
	writel(0, dsa->reg_base + DSA_GENCTRL_OFFSET);
	dev_err(dev, "no usable interrupts\n");
	return err;
}

static void dsa_disable_interrupts(struct dsadma_device *dsa_dma)
{
	/* Disable all interrupt generation */
	writeb(0, dsa_dma->reg_base + DSA_GENCTRL_OFFSET);
}

static int dsa_probe(struct dsadma_device *dsa_dma)
{
	int err = -ENODEV;
	struct dma_device *dma = &dsa_dma->dma_dev;
	struct pci_dev *pdev = dsa_dma->pdev;

	dsa_dma->completion_pool = pci_pool_create("completion_pool", pdev,
						    32,
						    SMP_CACHE_BYTES,
						    SMP_CACHE_BYTES);

	if (!dsa_dma->completion_pool) {
		err = -ENOMEM;
		goto err_completion_pool;
	}

	dsa_enable_system_pasid(dsa_dma);

	dsa_enumerate_capabilities(dsa_dma);

	err = dsa_configure_work_queues(dsa_dma);

	if (err)
		goto err_enable_pasid;

	err = dsa_configure_groups(dsa_dma);

	if (err)
		goto err_enable_pasid;

	dma->dev = &pdev->dev;

	err = dsa_dma_setup_interrupts(dsa_dma);
	if (err)
		goto err_enable_pasid;

	err = dsa_enable_device(dsa_dma);
	if (err)
		goto err_enable_device;

	err = dsa_enable_wqs(dsa_dma);
	if (err)
		goto err_self_test;

	printk("DSA device enabled successfully\n");

	if (selftest) {
		err = dsa_dma_self_test(dsa_dma);
		if (err)
			goto err_self_test;
	}
	return 0;

err_self_test:
	dsa_disable_device(dsa_dma);
err_enable_device:
	dsa_disable_interrupts(dsa_dma);
err_enable_pasid:
	dsa_disable_system_pasid(dsa_dma);
	pci_pool_destroy(dsa_dma->completion_pool);
err_completion_pool:
	return err;
}

static int dsa_register(struct dsadma_device *dsa_dma)
{
	int err = dma_async_device_register(&dsa_dma->dma_dev);

	printk("dsa chancnt %d\n", dsa_dma->dma_dev.chancnt);
	if (err) {
		dsa_disable_interrupts(dsa_dma);
		pci_pool_destroy(dsa_dma->completion_pool);
	}

	return err;
}

static void dsa_dma_remove(struct dsadma_device *dsa_dma)
{
	struct dma_device *dma = &dsa_dma->dma_dev;

	dsa_disable_system_pasid(dsa_dma);

	/* disable DSA and all the WQs */
	dsa_disable_device(dsa_dma);

	dsa_disable_interrupts(dsa_dma);

	dsa_kobject_del(dsa_dma);

	if (dsa_dma->num_kern_dwqs)
		dma_async_device_unregister(dma);

	pci_pool_destroy(dsa_dma->completion_pool);

	INIT_LIST_HEAD(&dma->channels);
}

/* FIXME: Find a good place for this constant */
#define DVSEC_INTEL_SCALABLE_IOV_ID 0x5

static int dsa_ims_supported (struct dsadma_device *dsa)
{
	int pos;
	u16 vid, dvsec_id;
	u32 capabilities;
	struct pci_dev *pdev = dsa->pdev;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_DVSEC);

	if (!pos)
		return 0;

	pci_read_config_word(pdev, pos + PCI_SIOV_VENDOR_ID, &vid);

	if (vid != 0x8086)
		return 0;

	pci_read_config_word(pdev, pos + PCI_SIOV_DVSEC_ID, &dvsec_id);

	if (dvsec_id != DVSEC_INTEL_SCALABLE_IOV_ID)
		return 0;

	pci_read_config_dword(pdev, pos + PCI_SIOV_CAPABILITIES, &capabilities);

	if (capabilities & PCI_SIOV_CAPABILITY_IMS)
		return 1;

	return 0;
}

/**
 * dsa_enumerate_capabilities - enumerate the device's capabilities
 * @dsa_dma: the dsa dma device to be enumerated
 */
static void dsa_enumerate_capabilities(struct dsadma_device *dsa_dma)
{
	struct dma_device *dma = &dsa_dma->dma_dev;

	dsa_dma->gencap = readq(dsa_dma->reg_base + DSA_GENCAP_OFFSET);

	dsa_dma->max_xfer_bits = (dsa_dma->gencap & DSA_CAP_MAX_XFER_MASK) >> 
						DSA_CAP_MAX_XFER_SHIFT;
	dsa_dma->max_xfer_size = 1 << dsa_dma->max_xfer_bits;

	dsa_dma->max_batch_size = (dsa_dma->gencap & DSA_CAP_MAX_BATCH_MASK) >>
					DSA_CAP_MAX_BATCH_SHIFT;

	dsa_dma->max_batch_size = 1 << dsa_dma->max_batch_size;

	dsa_dma->cfg_support = !!(dsa_dma->gencap & DSA_CAP_CONFIG);

	dsa_dma->ims_support = dsa_ims_supported(dsa_dma);
	/* If IMS table supported read its size */
	if (dsa_dma->ims_support) {
		dsa_dma->ims_size = (dsa_dma->gencap & DSA_CAP_IMS_MASK) >>
					DSA_CAP_IMS_SHIFT;

		dsa_dma->ims_size = dsa_dma->ims_size * DSA_CAP_IMS_MULTIPLIER;
	}

	dsa_dma->grpcap = readq(dsa_dma->reg_base + DSA_GRPCAP_OFFSET);

	dsa_dma->max_grps = dsa_dma->grpcap & DSA_CAP_MAX_GRP_MASK;

	dsa_dma->engcap = readq(dsa_dma->reg_base + DSA_ENGCAP_OFFSET);

	dsa_dma->max_engs = dsa_dma->engcap & DSA_CAP_MAX_ENG_MASK;

	dsa_dma->opcap = readq(dsa_dma->reg_base + DSA_OPCAP_OFFSET);

	dsa_dma->table_offsets = readq(dsa_dma->reg_base + DSA_TABLE_OFFSET);

	dsa_dma->grp_offset = dsa_dma->table_offsets & DSA_TABLE_GRPCFG_MASK;

	dsa_dma->grp_offset  = dsa_dma->grp_offset * 0x100;

	dsa_dma->wq_offset = (dsa_dma->table_offsets & DSA_TABLE_WQCFG_MASK) >>
			DSA_TABLE_WQCFG_SHIFT;

	dsa_dma->wq_offset = dsa_dma->wq_offset * 0x100;

	dsa_dma->msix_perm_offset = (dsa_dma->table_offsets &
			DSA_TABLE_MSIX_PERM_MASK) >> DSA_TABLE_MSIX_PERM_SHIFT;

	dsa_dma->msix_perm_offset = dsa_dma->msix_perm_offset * 0x100;

	dsa_dma->ims_offset = (dsa_dma->table_offsets & DSA_TABLE_IMS_MASK) >>
			DSA_TABLE_IMS_SHIFT;

	dsa_dma->ims_offset = dsa_dma->ims_offset * 0x100;

	dma_cap_set(DMA_PRIVATE, dma->cap_mask);

	printk("gencap %llx opcap %llx ims %d\n", dsa_dma->gencap,
			dsa_dma->opcap, dsa_dma->ims_support);
	if (MEMMOVE_SUPPORT(dsa_dma->opcap))
		dma_cap_set(DMA_MEMCPY, dma->cap_mask);
	if (MEMFILL_SUPPORT(dsa_dma->opcap))
		dma_cap_set(DMA_MEMSET, dma->cap_mask);
}

static int dsa_configure_groups(struct dsadma_device *dsa)
{
	struct dsa_work_queue *wq;
	int grp_offset;
	int i;

	if (dsa->cfg_support == 0) {
		/* can't configure the GRPs. grpcfg has already been read */
		return 0;
	}

	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &dsa->wqs[i];
		dsa->grpcfg[wq->grp_id].wq_bits[i / BITS_PER_LONG] |= 
						(1 << (i % BITS_PER_LONG));
	}

	/* FIXME: Currently only two groups are configured. All the engines are
	 * equally divided among the two groups. */
	for (i = 0; i < dsa->max_engs; i++) {
		if (!(i % dsa->num_grps))
			dsa->grpcfg[0].eng_bits |= (1 << i);
		else
			dsa->grpcfg[1].eng_bits |= (1 << i);
	}

	for (i = 0; i < dsa->num_grps; i++) {
		int j;

		grp_offset = dsa->grp_offset + i * 64;
		for (j = 0; j < 4; j++)
			if (dsa->grpcfg[i].wq_bits[j])
				writeq(dsa->grpcfg[i].wq_bits[j],
					dsa->reg_base + grp_offset + j * 8);
		writeq(dsa->grpcfg[i].eng_bits, dsa->reg_base + grp_offset+32);

		/* FIXME: No GRPFLAGS configuration for now */
	}
	return 0;
}

void dsa_wq_free (struct dsa_work_queue *wq)
{
        /* FIXME: Implement ref counting for SWQ clients */
	if (wq->dedicated) {
		wq->available = 1;
		wq->allocated = 0;
	}
}

struct dsa_work_queue *dsa_wq_alloc (struct dsadma_device *dsa, int dedicated)
{
	struct dsa_work_queue *wq;
	int i;

        if (dsa->num_wqs == 0)
                return NULL;

        /* FIXME: Use proper locks to provide mutual exclusion b/w processes */
        for (i = 0; i < dsa->num_wqs; i++) {
                wq = &dsa->wqs[i];
                if (dedicated == wq->dedicated && wq->available)
                        break;
        }

        if (i == dsa->num_wqs)
                return NULL;

        /* FIXME: Implement ref counting for SWQ clients */
        if (wq->dedicated) {
                wq->available = 0;
                wq->allocated = 1;
	}

	return wq;
}

void dsa_free_irq_event(struct dsa_irq_event *ev)
{
	struct dsa_irq_entry *irq_entry = ev->irq_entry;
	unsigned long flags;

	/* delete this completion ring from list of IRQ waiters */
	write_lock_irqsave(&irq_entry->irq_wait_lock, flags);
	list_del(&ev->irq_wait_chain);
	write_unlock_irqrestore(&irq_entry->irq_wait_lock, flags);
}

void dsa_free_descriptors (struct dsa_completion_ring *dring)
{

	dsa_free_irq_event(&dring->ev);

	dsa_free_client_buffers(dring);

	if (dring->callback_ring_buf)
		kfree(dring->callback_ring_buf);

	kfree(dring);
}

void dsa_setup_irq_event (struct dsa_irq_event *ev, struct dsa_irq_entry
			*irq_entry, struct dsa_completion_ring *dring,
			void (*isr_cb)(struct dsa_completion_ring *dring))
{
	unsigned long flags;

	memset(ev, 0, sizeof(struct dsa_irq_event));

	ev->dring = dring;
	ev->irq_entry = irq_entry;

	INIT_LIST_HEAD(&ev->irq_wait_chain);
	init_waitqueue_head(&ev->waitq);

	if (isr_cb)
		ev->isr_cb = isr_cb;
	else
		ev->use_waitq = 1;

	/* add this completion ring to list of IRQ waiters */
	write_lock_irqsave(&irq_entry->irq_wait_lock, flags);
	list_add(&ev->irq_wait_chain, &irq_entry->irq_wait_head);
	write_unlock_irqrestore(&irq_entry->irq_wait_lock, flags);
}

static int dsa_get_int_handle (struct dsadma_device *dsa, bool ims, int idx)
{
	int j;
	int iterations = ms_to * 10;
	union dsa_command_reg cmd;
	u32 cmdsts;

	memset(&cmd, 0, sizeof(cmd));

	cmd.fields.cmd = DSA_INT_HANDLE;
	cmd.fields.operand = (ims << 16) | (idx & 0xffff);

	spin_lock(&dsa->cmd_lock);
	writel(cmd.val, dsa->reg_base + DSA_CMD_OFFSET);

	for (j = 0; j < iterations; j++) {
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}
	spin_unlock(&dsa->cmd_lock);

	if ((j == iterations) || (cmdsts & DSA_CMD_ERRCODE_MASK))
		return -1;

	return (cmdsts >> 8) & 0xffff;
}

static struct dsa_completion_ring *
dsa_alloc_descriptors (struct dsa_work_queue *wq,
			void (*isr_cb)(struct dsa_completion_ring *dring))
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_irq_entry *irq_entry;
	u16 msix_idx;

        dring = kzalloc(sizeof(*dring), GFP_KERNEL);
        if (!dring)
		return NULL;

	dring->dsa = dsa;
	dring->wq = wq;

	dring->head = 0;
	dring->tail = 0;
	dring->issued = 0;
	dring->dmacount = 0;
	dring->completed = 0;
	spin_lock_init(&dring->space_lock);

	/* If a SWQ, the the completion ring size is (total wq size * 2).
	 * If a DWQ, the completion size is equal to the size of WQ.
	 */
	if (wq->dedicated)
		dring->num_entries = wq->wq_size;
	else
		dring->num_entries = dsa->tot_wq_size * 2;

	dring->comp_ring_size = dring->num_entries *
				sizeof(struct dsa_completion_record);

	if (dsa_alloc_client_buffers(dring, GFP_KERNEL)) {
		kfree(dring);
		return NULL;
	}

	msix_idx = dsa_get_msix_index(dsa);

	/* irq_entry 0 is not used for WQ completion interrupts */
	irq_entry = &dsa->irq_entries[msix_idx];

	dsa_setup_irq_event(&dring->ev, irq_entry, dring, isr_cb);

	dring->wq_reg = dsa->wq_reg_base +
		dsa_get_wq_portal_offset(wq->idx, false, false);

	dring->int_idx = msix_idx;
	return dring;
}

static void dsa_configure_msix_perm_table (struct dsa_completion_ring *dring)
{
	struct dsadma_device *dsa = dring->dsa;
	unsigned int perm_offset;
	u32 perm_val = (1 << 3) | (dsa->system_pasid << 12);

	perm_offset = dsa->msix_perm_offset + dring->int_idx * 8;

	writel(perm_val, dsa->reg_base + perm_offset);
}

static int dsa_init_wq (struct dsadma_device *dsa, int wq_idx)
{
	struct dsa_work_queue *wq = &dsa->wqs[wq_idx];
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 32 bytes */
	wq_offset = dsa->wq_offset + wq_idx * 32;

	wqcfg.a.a_fields.wq_size = wq->wq_size;
	writel(wqcfg.a.val, dsa->reg_base + wq_offset);

	/* If the WQ size is 0, there is nothing else to do */
	if (wq->wq_size == 0)
		return 0;

	printk("init wq %d dedicated %d sz %d grp %d\n", wq_idx, wq->dedicated,
						wq->wq_size, wq->grp_id);

	wqcfg.b.b_fields.threshold = wq->threshold;
	writel(wqcfg.b.val, dsa->reg_base + wq_offset + 4);

	wqcfg.c.c_fields.mode = wq->dedicated ? 1 : 0;
	/* Enable the BOF if it is supported */
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT) {
		wqcfg.c.c_fields.bof_en = 1;
		wq->bof_enabled = 1;
	}

	wqcfg.c.c_fields.priority = wq->priority;
	wqcfg.c.c_fields.priv = 1;

	/* SWQ can only work if PASID is enabled */
	if (!wq->dedicated && dsa->pasid_enabled)
		wqcfg.c.c_fields.paside = 1;
	else 
		wqcfg.c.c_fields.paside = 0;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);

	/* Set the same max_xfer_bits as the GENCAP */
	wq->max_xfer_bits = dsa->max_xfer_bits;
	wq->max_batch_bits = (dsa->gencap &
			DSA_CAP_MAX_BATCH_MASK) >> DSA_CAP_MAX_BATCH_SHIFT;

	wqcfg.d.d_fields.max_xfer_bits = wq->max_xfer_bits;
	wqcfg.d.d_fields.max_batch_bits = wq->max_batch_bits;

	writel(wqcfg.d.val, dsa->reg_base + wq_offset + 12);

	wqcfg.e.val = 0;
	writel(wqcfg.e.val, dsa->reg_base + wq_offset + 16);

	return 0;
}

int dsa_wq_disable_pasid (struct dsadma_device *dsa, int wq_idx)
{
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	/* First disable the WQ */
	if (dsa_disable_wq(dsa, wq_idx)) {
		printk("Error disabling the wq %d %x\n", wq_idx,
				readl(dsa->reg_base + DSA_CMDSTS_OFFSET));
		return -ENODEV;
	}

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 32 bytes */
	wq_offset = dsa->wq_offset + wq_idx * 32;

	/* Change the PASID */
	wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);

	wqcfg.c.c_fields.priv = 1;
	wqcfg.c.c_fields.paside = 0;
	wqcfg.c.c_fields.pasid = 0;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);

	/* Now re-enable the WQ */
	if (dsa_enable_wq(dsa, wq_idx))
		return -ENODEV;

	return 0;
}

int dsa_wq_set_pasid (struct dsadma_device *dsa, int wq_idx, int pasid,
				bool privilege)
{
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	/* First disable the WQ */
	if (dsa_disable_wq(dsa, wq_idx)) {
		printk("Error disabling the wq %d %x\n", wq_idx,
				readl(dsa->reg_base + DSA_CMDSTS_OFFSET));
		return -ENODEV;
	}

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 32 bytes */
	wq_offset = dsa->wq_offset + wq_idx * 32;

	/* Change the PASID */
	wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);

	wqcfg.c.c_fields.priv = privilege;
	wqcfg.c.c_fields.paside = 1;
	wqcfg.c.c_fields.pasid = pasid;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);

	/* Now re-enable the WQ */
	if (dsa_enable_wq(dsa, wq_idx))
		return -ENODEV;

	return 0;
}

static int dsa_get_wq_grp_config(struct dsadma_device *dsa)
{
	struct dsa_work_queue_reg wqcfg;
	struct dsa_work_queue *wq;
	unsigned int wq_offset;
	unsigned int grp_offset;
	int i, j;

	memset(&wqcfg, 0, sizeof(wqcfg));

	dsa->num_wqs = dsa->max_wqs;

	for (i = 0; i < dsa->max_grps; i++) {
		int j;

		grp_offset = dsa->grp_offset + i * 64;
		for (j = 0; j < 4; j++)
			dsa->grpcfg[i].wq_bits[j] =
				readq(dsa->reg_base + grp_offset + j * 8);

		if (dsa->grpcfg[i].wq_bits[0] || dsa->grpcfg[i].wq_bits[1] ||
			dsa->grpcfg[i].wq_bits[2] || dsa->grpcfg[i].wq_bits[3]) 
			dsa->num_grps++;

		dsa->grpcfg[i].eng_bits = readq(dsa->reg_base + grp_offset +32);

		/* FIXME: Do we need to read the GRPFLAGS as well? */
	}

	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &dsa->wqs[i];

		/* Each WQCONFIG reg is 16 bytes (A, B, C, and D registers) */
		wq_offset = dsa->wq_offset + i * 32;

		wqcfg.a.val = readl(dsa->reg_base + wq_offset);
		wqcfg.b.val = readl(dsa->reg_base + wq_offset + 4);
		wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);
		wqcfg.d.val = readl(dsa->reg_base + wq_offset + 12);
		wqcfg.e.val = readl(dsa->reg_base + wq_offset + 16);
		wqcfg.f.val = readl(dsa->reg_base + wq_offset + 20);

		for (j = 0; j < 4; j++)
			if (dsa->grpcfg[j].wq_bits[i / BITS_PER_LONG] &
						(1 << (i % BITS_PER_LONG)))
				wq->grp_id = j;

		wq->dedicated = wqcfg.c.c_fields.mode;
		wq->wq_size = wqcfg.a.a_fields.wq_size;
		wq->threshold = wqcfg.b.b_fields.threshold;
		wq->priority = wqcfg.c.c_fields.priority;
		wq->mode_support = wqcfg.f.f_fields.mode_support;
		/* Set the same max_xfer_bits as the GENCAP */
		wq->max_xfer_bits = dsa->max_xfer_bits;
		wq->max_batch_bits = (dsa->gencap &
			DSA_CAP_MAX_BATCH_MASK) >> DSA_CAP_MAX_BATCH_SHIFT;

		wq->idx = i;

		if (dsa->wqs[i].dedicated)
			dsa->num_dwqs++;

		printk("init wq %d dedicated %d sz %d grp %d mode_s %d\n", i,
		wq->dedicated, wq->wq_size, wq->grp_id, wq->mode_support);
	}

	printk("wq configs %d %d %d %d\n", dsa_num_swqs, dsa_num_dwqs, dsa->num_wqs, dsa->num_dwqs);
	if ((dsa_num_swqs + dsa_num_dwqs) == 0)
		return 0;

	if ((dsa_num_swqs + dsa_num_dwqs) != dsa->num_wqs) {
		printk("[%d:%d] Num WQs != MAX WQs\n",
			dsa_num_swqs + dsa_num_dwqs, dsa->num_wqs);
		return -EINVAL;
	}

	while (dsa_num_swqs > (dsa->num_wqs - dsa->num_dwqs)) {
		/* convert some DWQs to SWQs */
		for (i = 0; i < dsa->num_wqs; i++) {
			wq = &dsa->wqs[i];

			if (wq->mode_support && wq->dedicated) {
				wq_offset = dsa->wq_offset + i * 32 + 4;

				wq->threshold = (wq->wq_size * 8)/10;
				wqcfg.b.b_fields.threshold = wq->threshold;
				writel(wqcfg.b.val, dsa->reg_base + wq_offset);

				wq_offset += 4;
				wqcfg.c.val = readl(dsa->reg_base + wq_offset);
				wqcfg.c.c_fields.mode = 0;
				wqcfg.c.c_fields.paside = 1;
				writel(wqcfg.c.val, dsa->reg_base + wq_offset);

				wq->dedicated = 0;
				dsa->num_dwqs--;
				break;
			}
		}
		if (i == dsa->num_wqs)
			return 1;
	}

	while (dsa_num_dwqs > dsa->num_dwqs) {
		/* convert some SWQs to DWQs if we can */
		for (i = 0; i < dsa->num_wqs; i++) {
			wq = &dsa->wqs[i];

			if (wq->mode_support && !wq->dedicated) {
				wq_offset = dsa->wq_offset + i * 32 + 8;

				wqcfg.c.val = readl(dsa->reg_base + wq_offset);
				wqcfg.c.c_fields.mode = 1;
				wqcfg.c.c_fields.paside = 0;
				writel(wqcfg.c.val, dsa->reg_base + wq_offset);

				wq->dedicated = 1;
				dsa->num_dwqs++;
				break;
			}
		}
		if (i == dsa->num_wqs)
			return 1;
	}

	return 0;
}

/**
 * dsa_configure_work_queues - configure the device's work queues
 * @dsa_dma: the dsa dma device to be enumerated
 */
static int dsa_configure_work_queues(struct dsadma_device *dsa)
{
	struct device *dev = &dsa->pdev->dev;
	struct dma_device *dma = &dsa->dma_dev;
	int i ;
	unsigned int wq_size, allocated_size;

	dsa->wqcap = readq(dsa->reg_base + DSA_WQCAP_OFFSET);

	dsa->tot_wq_size = (dsa->wqcap & DSA_CAP_WQ_SIZE_MASK);

	dsa->max_wqs = (dsa->wqcap & DSA_CAP_MAX_WQ_MASK) >>
						DSA_CAP_MAX_WQ_SHIFT;

	dsa->wqs = devm_kzalloc(dev, sizeof(struct dsa_work_queue) *
						dsa->max_wqs, GFP_KERNEL);

	if (dsa->wqs == NULL) {
		dev_err(dev, "Allocating %d WQ structures!\n", dsa->max_wqs);
		return -ENOMEM;
	}

	dsa->grpcfg = devm_kzalloc(dev, sizeof(struct dsa_grpcfg_reg) *
						dsa->max_grps, GFP_KERNEL);
	if (dsa->grpcfg == NULL) {
		dev_err(dev, "Allocating %d grpcfg structs!\n", dsa->max_grps);
		return -ENOMEM;
	}

	if (!(dsa->wqcap & DSA_CAP_SWQ) && !(dsa->wqcap & DSA_CAP_DWQ))
		return -EINVAL;

	/* We can't use SWQs if PASID was not enabled */
	if (!dsa->pasid_enabled || !(dsa->wqcap & DSA_CAP_SWQ))
		dsa_num_swqs = 0;

	if (!(dsa->wqcap & DSA_CAP_DWQ))
		dsa_num_dwqs = 0;

	if (dsa->cfg_support == 0) {
		/* Read the WQ config */
		if (dsa_get_wq_grp_config(dsa))
			return -EINVAL;

		goto skip_wq_config;
	}

	dsa->num_wqs += dsa_num_dwqs;
	dsa->num_wqs += dsa_num_swqs;

	/* by default #WQs = #Engines, and #DWQs = #SWQs */
	if (dsa->num_wqs == 0) {
		dsa->num_wqs = dsa->max_engs;
		dsa_num_swqs = dsa->max_engs/2;
		if (!dsa->pasid_enabled || !(dsa->wqcap & DSA_CAP_SWQ))
			dsa_num_swqs = 0;
		dsa_num_dwqs = dsa->max_engs - dsa_num_swqs;
	}

	/* The current logic is to divide the total WQ size such that each SWQ
	 * has twice the size of each DWQ. All SWQs are equal in size and all
	 * DWQs are equal in size. */

	wq_size = dsa->tot_wq_size/(dsa_num_swqs * 2 + dsa_num_dwqs);
	allocated_size = 0;

	if (dsa->num_wqs > dsa->max_wqs) {
		dev_err(dev, "[%d:%d] Num WQs > MAX WQs\n", dsa->num_wqs,
							dsa->max_wqs);
		return -EINVAL;
	}

	/* FIXME: currently all SWQs are in one group and all DWQs in another.
	 * All WQ are assigned priorities (wq_id + 1) */
	if (dsa_num_dwqs > 0) {
		for (i = 0; i < dsa_num_dwqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 1;
			dsa->wqs[i].wq_size = wq_size;
			dsa->wqs[i].threshold = 0; /* N/A for DWQ */
			dsa->wqs[i].priority = i + 1;
			dsa->wqs[i].idx = i;
			allocated_size += wq_size;
		}
		dsa->num_grps++;
		if (dsa_num_swqs == 0) {
			/* readjust last WQ to account for integer arithmatic */
			dsa->wqs[i-1].wq_size += dsa->tot_wq_size -
							allocated_size;
		}
		dsa->num_dwqs = dsa_num_dwqs;
	}
	if (dsa_num_swqs > 0) {	
		for (i = dsa_num_dwqs; i < dsa->num_wqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 0;
			dsa->wqs[i].wq_size = wq_size * 2;
			dsa->wqs[i].threshold = (dsa->wqs[i].wq_size * 8)/10;
			dsa->wqs[i].priority = i + 1;
			dsa->wqs[i].idx = i;
			allocated_size += (wq_size * 2);
		}
		/* readjust the last SWQ to account for integer arithmatic */
		dsa->wqs[i-1].wq_size += dsa->tot_wq_size - allocated_size;
		dsa->wqs[i-1].threshold = (dsa->wqs[i - 1].wq_size * 8)/10;
		dsa->num_grps++;
	}

	if (dsa->num_grps > dsa->max_grps) {
		dev_err(dev, "[%d:%d] Num GRPs > MAX GRPs\n", dsa->num_grps,
							dsa->max_grps);
		return -EINVAL;
	}

	for (i = 0; i < dsa->max_wqs; i++) {
		dsa_init_wq(dsa, i);
	}

skip_wq_config:
	INIT_LIST_HEAD(&dma->channels);

	/* Currently, report first DWQ only to the kernel to be used by the DMA
	 * APIs. The rest of the WQs are for SVM clients */
	for (i = 0; i < dsa->max_wqs; i++) {
		struct dsa_work_queue *wq = &dsa->wqs[i];

		wq->dsa = dsa;
		spin_lock_init(&wq->lock);

		wq->dma_chan.device = dma;
		dma_cookie_init(&wq->dma_chan);
#if 0 /* replace timer apis */
		init_timer(&wq->timer);
		wq->timer.function = dsa_timer_event;
       		wq->timer.data = (unsigned long)wq;
#endif
		timer_setup(&wq->timer, dsa_timer_event, 0);

		if (wq->dedicated && !dsa->num_kern_dwqs && dmachan) {
			list_add_tail(&wq->dma_chan.device_node,&dma->channels);
			dsa->num_kern_dwqs++;
			wq->available = 0;
			wq->allocated = 1;
			dsa->system_wq_idx = i;
		} else {
			wq->available = 1;
			wq->allocated = 0;
		}
	}

	return 0;
}

struct dsa_completion_ring *dsa_alloc_svm_resources(struct dsa_work_queue *wq)
{
	struct dsa_completion_ring *dring;

	dring = dsa_alloc_descriptors(wq, dsa_svm_completion_cleanup);

	if (!dring)
		return NULL;

	/* Configure the MSI-X permission table if we are using PASID */
	dsa_configure_msix_perm_table(dring);

	if (dring->dsa->gencap & DSA_CAP_INT_HANDLE) {
		if ((dring->int_idx = dsa_get_int_handle(dring->dsa, false,
							dring->int_idx)) < 0) {
			printk("int handle allocation failed\n");
			dsa_free_descriptors(dring);
			return NULL;
		}
	}

        /* allocate the array to hold the callback descriptors */
        dring->callback_ring_buf = kcalloc(dring->num_entries,
			sizeof(struct dsa_callback_descriptor), GFP_KERNEL);
        if (!dring->callback_ring_buf) {
		dsa_free_descriptors(dring);
                return NULL;
	}

	dsa_init_completion_ring(dring);

	return dring;
}

/**
 * dsa_free_chan_resources - release all the descriptors
 * @chan: the channel to be cleaned
 */
static void dsa_free_chan_resources(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;

	if (dring)
		dsa_free_descriptors(dring);

	/* FIXME: Is there something else to be done here? */
	return;
}

/* dsa_alloc_chan_resources - allocate/initialize dsa descriptor ring
 * @chan: channel to be initialized
 */
/* FIXME: We should use Batch descriptors to satisfy DMA APIs */
static int dsa_alloc_chan_resources(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct pci_dev *dev = wq->dsa->pdev;
	struct dsa_completion_ring *dring;

	dring = dsa_alloc_descriptors(wq, dsa_dma_completion_cleanup);

	if (!dring)
		return -EFAULT;

	if (dring->dsa->gencap & DSA_CAP_INT_HANDLE) {
		if ((dring->int_idx = dsa_get_int_handle(dring->dsa, false,
							dring->int_idx)) < 0) {
			printk("int handle allocation failed\n");
			dsa_free_descriptors(dring);
			return -EFAULT;
		}
	}

	wq->dring = dring;

        /* allocate the array to hold the async tx descriptors */
        dring->callback_ring_buf = kcalloc(dring->num_entries,
			sizeof(struct dma_async_tx_descriptor), GFP_KERNEL);
        if (!dring->callback_ring_buf) {
		dsa_free_descriptors(dring);
                return -ENOMEM;
	}

        /* map completion ring to create DMA addresses.
         */
	dring->comp_base = pci_map_single(dev, dring->completion_ring_buf,
				dring->comp_ring_size, PCI_DMA_FROMDEVICE);

	if (dring->comp_base == 0) {
		dsa_free_descriptors(dring);
		return -EFAULT;
	}

	dsa_init_completion_ring(dring);

	return dring->num_entries;
}

static int dsa_dma_probe(struct dsadma_device *dsa_dma)
{
	struct dma_device *dma;
	int err;

	dma = &dsa_dma->dma_dev;
	dma->device_prep_dma_memcpy = dsa_dma_prep_memcpy;
	dma->device_prep_dma_memset = dsa_dma_prep_memset;
	dma->device_issue_pending = dsa_issue_pending;
	dma->device_alloc_chan_resources = dsa_alloc_chan_resources;
	dma->device_free_chan_resources = dsa_free_chan_resources;

	dma_cap_set(DMA_INTERRUPT, dma->cap_mask);
	dma->device_prep_dma_interrupt = dsa_prep_interrupt_lock;

	dma->device_tx_status = dsa_tx_status;

	err = dsa_probe(dsa_dma);
	if (err)
		return err;

	if (dsa_dma->num_kern_dwqs) {
		err = dsa_register(dsa_dma);
		if (err)
			return err;
	}

	dsa_kobject_add(dsa_dma, &dsa_ktype);

	return 0;
}

static void dsa_shutdown(struct pci_dev *pdev)
{
	struct dsadma_device *dsa = pci_get_drvdata(pdev);
	int i;

	if (!dsa)
		return;

	for (i = 0; i < dsa->num_wqs; i++) {
		/* FIXME: */

	}

	/* disable DSA and all the WQs */
	dsa_disable_device(dsa);

	dsa_disable_interrupts(dsa);
}

void dsa_resume(struct dsadma_device *dsa)
{
	int i;

	for (i = 0; i < dsa->num_wqs; i++) {
		/* no need to reset as shutdown already did that */
		/* FIXME: */
	}
}

static pci_ers_result_t dsa_pcie_error_detected(struct pci_dev *pdev,
						 enum pci_channel_state error)
{
	dev_dbg(&pdev->dev, "%s: PCIe AER error %d\n", DRV_NAME, error);

	/* quiesce and block I/O */
	dsa_shutdown(pdev);

	return PCI_ERS_RESULT_NEED_RESET;
}

static pci_ers_result_t dsa_pcie_error_slot_reset(struct pci_dev *pdev)
{
	pci_ers_result_t result = PCI_ERS_RESULT_RECOVERED;
	int err;

	dev_dbg(&pdev->dev, "%s post reset handling\n", DRV_NAME);

	if (pci_enable_device_mem(pdev) < 0) {
		dev_err(&pdev->dev,
			"Failed to enable PCIe device after reset.\n");
		result = PCI_ERS_RESULT_DISCONNECT;
	} else {
		pci_set_master(pdev);
		pci_restore_state(pdev);
		pci_save_state(pdev);
		pci_wake_from_d3(pdev, false);
	}

	err = pci_cleanup_aer_uncorrect_error_status(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"AER uncorrect error status clear failed: %#x\n", err);
	}

	return result;
}

static void dsa_pcie_error_resume(struct pci_dev *pdev)
{
	struct dsadma_device *dsa_dma = pci_get_drvdata(pdev);

	dev_dbg(&pdev->dev, "%s: AER handling resuming\n", DRV_NAME);

	/* initialize and bring everything back */
	dsa_resume(dsa_dma);
}

static const struct pci_error_handlers dsa_err_handler = {
	.error_detected = dsa_pcie_error_detected,
	.slot_reset = dsa_pcie_error_slot_reset,
	.resume = dsa_pcie_error_resume,
};

static struct pci_driver dsa_pci_driver = {
	.name		= DRV_NAME,
	.id_table	= dsa_pci_tbl,
	.probe		= dsa_pci_probe,
	.remove		= dsa_remove,
	.shutdown	= dsa_shutdown,
	.err_handler	= &dsa_err_handler,
};

static struct dsadma_device *
alloc_dsadma(struct pci_dev *pdev, void __iomem * const *iomap)
{
	struct device *dev = &pdev->dev;
	struct dsadma_device *d = devm_kzalloc(dev, sizeof(*d), GFP_KERNEL);

	if (!d)
		return NULL;
	d->pdev = pdev;
	d->reg_base = iomap[DSA_MMIO_BAR];
	d->wq_reg_base = iomap[DSA_WQ_BAR];

	spin_lock_init(&d->cmd_lock);

	return d;
}

static int dsa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	void __iomem * const *iomap;
	struct device *dev = &pdev->dev;
	struct dsadma_device *device;
	int err;
	int msk;

	err = pcim_enable_device(pdev);
	if (err)
		return err;

	msk = (1 << DSA_MMIO_BAR) | (1 << DSA_WQ_BAR);
	err = pcim_iomap_regions(pdev, msk, DRV_NAME);
	if (err)
		return err;
	iomap = pcim_iomap_table(pdev);
	if (!iomap)
		return -ENOMEM;

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err)
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
	if (err)
		return err;

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err)
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
	if (err)
		return err;

	device = alloc_dsadma(pdev, iomap);
	if (!device)
		return -ENOMEM;

	pci_set_master(pdev);
	pci_set_drvdata(pdev, device);

	device->version = readw(device->reg_base + DSA_VER_OFFSET);
	if (device->version >= DSA_VER_1_0) {
		err = dsa_dma_probe(device);
		pci_enable_pcie_error_reporting(pdev);
	} else
		return -ENODEV;

	if (err) {
		dev_err(dev, "Intel(R) DSA DMA Engine init failed\n");
		pci_disable_pcie_error_reporting(pdev);
		return -ENODEV;
	}

	device->index = num_dsa_devices;

	/* Create user interface only if PASID is enabled */
	if (device->pasid_enabled)
		err = dsa_usr_add(device);
#if 0 //JP: no mdev for now
	if (enable_vdsa) {
		dsa_host_init(device);
	}
#endif
	list_add(&device->list, &dsa_devices);
	num_dsa_devices++;

	return err;
}

static void dsa_remove(struct pci_dev *pdev)
{
	struct dsadma_device *device = pci_get_drvdata(pdev);

	if (!device)
		return;

	dev_err(&pdev->dev, "Removing dma services\n");

	pci_disable_pcie_error_reporting(pdev);
#if 0
	dsa_host_exit(device);
#endif
	if (device->pasid_enabled)
		misc_deregister(&device->misc_dev);

	dsa_dma_remove(device);
}

static int __init dsa_init_module(void)
{
	int err = -ENOMEM;

	pr_info("%s: Intel(R) Data Streaming Accelerator Driver %s\n",
		DRV_NAME, DSA_DMA_VERSION);

	dsa_cache = kmem_cache_create("dsa", 64/*sizeof(struct dsa_descriptor)*/,
					0, SLAB_HWCACHE_ALIGN, NULL);
	if (!dsa_cache)
		return -ENOMEM;

	INIT_LIST_HEAD(&dsa_devices);

	err = pci_register_driver(&dsa_pci_driver);
	if (err)
		goto err_dsa_cache;

	return 0;

 err_dsa_cache:
	kmem_cache_destroy(dsa_cache);

	return err;
}
module_init(dsa_init_module);

static void __exit dsa_exit_module(void)
{
	pci_unregister_driver(&dsa_pci_driver);
	kmem_cache_destroy(dsa_cache);
}
module_exit(dsa_exit_module);
