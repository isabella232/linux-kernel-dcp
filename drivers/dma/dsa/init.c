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
static int dsa_enumerate_work_queues(struct dsadma_device *dsa);

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

struct kmem_cache *dsa_cache;

static int dsa_enable_wq (struct dsadma_device *dsa, int wq_offset,
				struct dsa_work_queue_reg *wqcfg)
{
	int j;
	int iterations = ms_to * 10;

	wqcfg->d.d_fields.wq_enable = 1;

	writel(wqcfg->d.val, dsa->reg_base + wq_offset + 0xC);

	for (j = 0; j < iterations; j++) {
		wqcfg->d.val = readl(dsa->reg_base + wq_offset + 0xC);
		if ((wqcfg->d.d_fields.wq_enabled) ||
				(wqcfg->d.d_fields.wq_err))
			break;
	}

	if ((j == iterations) || wqcfg->d.d_fields.wq_err)
		return 1;

	return 0;
}

static int dsa_disable_wq (struct dsadma_device *dsa, int wq_offset,
				struct dsa_work_queue_reg *wqcfg)
{
	int j;
	int iterations = ms_to * 10;

	wqcfg->d.d_fields.wq_enable = 0;

	writel(wqcfg->d.val, dsa->reg_base + wq_offset + 0xC);

	for (j = 0; j < iterations; j++) {
		wqcfg->d.val = readl(dsa->reg_base + wq_offset + 0xC);
		if (!wqcfg->d.d_fields.wq_enabled)
			break;
	}

	if ((j == iterations) || wqcfg->d.d_fields.wq_err) {
		return 1;
	}
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
	u32 enabled = 0;
	struct device *dev = &dsa->pdev->dev;
	int iterations = ms_to * 10;

	writel(0, dsa->reg_base + DSA_ENABLE_OFFSET);

	for (i = 0; i < iterations; i++) {
		enabled = readl(dsa->reg_base + DSA_ENABLE_OFFSET);
		if (!(enabled & DSA_ENABLED_BIT) || (enabled & DSA_ERR_BITS))
			break;
	}

	if ((i == iterations) || (enabled & DSA_ERR_BITS)) {
		dev_err(dev, "Error disabling the device %d %x\n", i,
						enabled & DSA_ERR_BITS);
		err = -ENODEV;
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
	u32 enable = 0;
	struct dsa_work_queue_reg wqcfg;
	struct device *dev = &dsa->pdev->dev;
	unsigned int wq_offset;
	int iterations = ms_to * 10;

	enable |= DSA_ENABLE_BIT;

	writel(enable, dsa->reg_base + DSA_ENABLE_OFFSET);

	for (i = 0; i < iterations; i++) {
		enable = readl(dsa->reg_base + DSA_ENABLE_OFFSET);
		if ((enable & DSA_ENABLED_BIT) || (enable & DSA_ERR_BITS))
			break;
	}

	if ((i == iterations) || (enable & DSA_ERR_BITS)) {
		dev_err(dev, "Error enabling the device %d %x\n", i,
						enable & DSA_ERR_BITS);
		err = -ENODEV;
	}

	for (i = 0; i < dsa->num_wqs; i++) {
		int j;
		wq_offset = DSA_WQCFG_OFFSET + i * 16;

		wqcfg.d.val = 0;
		wqcfg.d.d_fields.wq_enable = 1;

		writel(wqcfg.d.val, dsa->reg_base + wq_offset + 0xC);

		for (j = 0; j < iterations; j++) {
			wqcfg.d.val = readl(dsa->reg_base + wq_offset + 0xC);
			if ((wqcfg.d.d_fields.wq_enabled) ||
					(wqcfg.d.d_fields.wq_err))
				break;
		}

		if ((j == iterations) || wqcfg.d.d_fields.wq_err) {
			dev_err(dev, "Error enabling the wq %d %d %x\n", i, j,
						wqcfg.d.d_fields.wq_err);
			err = -ENODEV;
		}
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

	/* If IMS and Guest Portals supported, map them */
	if (dsa_dma->gencap & DSA_CAP_IMS) {
		void __iomem * const *iomap;
		int msk = (1 << DSA_GUEST_WQ_BAR);

		err = pcim_iomap_regions(pdev, msk, DRV_NAME);
		if (err)
			goto err_enable_pasid;

		iomap = pcim_iomap_table(pdev);
		if (!iomap)
			goto err_enable_pasid;

		dsa_dma->gwq_reg_base = iomap[DSA_GUEST_WQ_BAR];
	}

	err = dsa_enumerate_work_queues(dsa_dma);

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

	dma_async_device_unregister(dma);

	pci_pool_destroy(dsa_dma->completion_pool);

	INIT_LIST_HEAD(&dma->channels);
}

/**
 * dsa_enumerate_capabilities - enumerate the device's capabilities
 * @dsa_dma: the dsa dma device to be enumerated
 */
static void dsa_enumerate_capabilities(struct dsadma_device *dsa_dma)
{
	struct dma_device *dma = &dsa_dma->dma_dev;
	u32 max_xfer_bits;

	dsa_dma->gencap = readq(dsa_dma->reg_base + DSA_GENCAP_OFFSET);

	max_xfer_bits = (dsa_dma->gencap & DSA_CAP_MAX_XFER_MASK) >> 
						DSA_CAP_MAX_XFER_SHIFT;
	dsa_dma->max_xfer_bits = max_xfer_bits + 16;
	dsa_dma->max_xfer_size = 1 << dsa_dma->max_xfer_bits;

	dsa_dma->max_batch_size = (dsa_dma->gencap & DSA_CAP_MAX_BATCH_MASK) >>
					DSA_CAP_MAX_BATCH_SHIFT;

	dsa_dma->ims_size = (dsa_dma->gencap & DSA_CAP_IMS_MASK) >>
					DSA_CAP_IMS_SHIFT;

	dsa_dma->ims_size = dsa_dma->ims_size * DSA_CAP_IMS_MULTIPLIER;

	dsa_dma->opcap = readq(dsa_dma->reg_base + DSA_OPCAP_OFFSET);

	dma_cap_set(DMA_PRIVATE, dma->cap_mask);

	printk("gencap %llx opcap %llx\n", dsa_dma->gencap, dsa_dma->opcap);
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

	if (dsa->wq_cfg_support == 0) {
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

		grp_offset = DSA_GRPCFG_OFFSET + i * 64;
		for (j = 0; j < 4; j++)
			if (dsa->grpcfg[i].wq_bits[j])
				writeq(dsa->grpcfg[i].wq_bits[j],
					dsa->reg_base + grp_offset + j * 8);
		writeq(dsa->grpcfg[i].eng_bits, dsa->reg_base + grp_offset+32);
	}
	/* FIXME: need to configure VCs, bandwidth tokens, etc. */
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

	dring->wq_reg = dsa_get_wq_reg(wq->dsa, wq->idx, msix_idx, 1);

	return dring;
}


static int dsa_init_wq (struct dsadma_device *dsa, int wq_idx)
{
	struct dsa_work_queue *wq = &dsa->wqs[wq_idx];
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 16 bytes (A, B, C, and D registers) */
	wq_offset = DSA_WQCFG_OFFSET + wq_idx * 16;

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
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		wqcfg.c.c_fields.bof_en = 1;

	wqcfg.c.c_fields.priority = wq->priority;
	wqcfg.c.c_fields.u_s = 1;

	/* SWQ can only work if PASID is enabled */
	if (!wq->dedicated && dsa->pasid_enabled)
		wqcfg.c.c_fields.paside = 1;
	else 
		wqcfg.c.c_fields.paside = 0;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);
	
	return 0;
}

int dsa_wq_disable_pasid (struct dsadma_device *dsa, int wq_idx)
{
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 16 bytes (A, B, C, and D registers) */
	wq_offset = DSA_WQCFG_OFFSET + wq_idx * 16;

	wqcfg.d.val = readl(dsa->reg_base + wq_offset + 0xC);

	/* First disable the WQ */
	if (dsa_disable_wq(dsa, wq_offset, &wqcfg)) {
		printk("Error disabling the wq %d %x\n", wq_idx,
					wqcfg.d.d_fields.wq_err);
		return -ENODEV;
	}

	/* Change the PASID */
	wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);

	wqcfg.c.c_fields.u_s = 1;
	wqcfg.c.c_fields.paside = 0;
	wqcfg.c.c_fields.pasid = 0;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);

	/* Now re-enable the WQ */
	if (dsa_enable_wq(dsa, wq_offset, &wqcfg)) {
		printk("Error re-enabling the wq %d %x\n", wq_idx,
					wqcfg.d.d_fields.wq_err);
		return -ENODEV;
	}

	return 0;
}

int dsa_wq_set_pasid (struct dsadma_device *dsa, int wq_idx, int pasid,
				bool privilege)
{
	struct dsa_work_queue_reg wqcfg;
	unsigned int wq_offset;

	memset(&wqcfg, 0, sizeof(wqcfg));

	/* Each WQCONFIG register is 16 bytes (A, B, C, and D registers) */
	wq_offset = DSA_WQCFG_OFFSET + wq_idx * 16;

	wqcfg.d.val = readl(dsa->reg_base + wq_offset + 0xC);

	/* First disable the WQ */
	if (dsa_disable_wq(dsa, wq_offset, &wqcfg)) {
		printk("Error disabling the wq %d %x\n", wq_idx,
					wqcfg.d.d_fields.wq_err);
		return -ENODEV;
	}

	/* Change the PASID */
	wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);

	wqcfg.c.c_fields.u_s = privilege;
	wqcfg.c.c_fields.paside = 1;
	wqcfg.c.c_fields.pasid = pasid;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);

	/* Now re-enable the WQ */
	if (dsa_enable_wq(dsa, wq_offset, &wqcfg)) {
		printk("Error re-enabling the wq %d %x\n", wq_idx,
					wqcfg.d.d_fields.wq_err);
		return -ENODEV;
	}

	return 0;
}

static void dsa_get_wq_grp_config(struct dsadma_device *dsa)
{
	struct dsa_work_queue_reg wqcfg;
	struct dsa_work_queue *wq;
	unsigned int wq_offset;
	unsigned int grp_offset;
	int i, j;

	memset(&wqcfg, 0, sizeof(wqcfg));

	dsa->num_wqs = dsa->max_wqs;

	for (i = 0; i < dsa->max_engs; i++) {
		int j;

		grp_offset = DSA_GRPCFG_OFFSET + i * 64;
		for (j = 0; j < 4; j++)
			dsa->grpcfg[i].wq_bits[j] =
				readq(dsa->reg_base + grp_offset + j * 8);

		if (dsa->grpcfg[i].wq_bits[0] || dsa->grpcfg[i].wq_bits[1] ||
			dsa->grpcfg[i].wq_bits[2] || dsa->grpcfg[i].wq_bits[3]) 
			dsa->num_grps++;

		dsa->grpcfg[i].eng_bits = readq(dsa->reg_base + grp_offset +32);
	}

	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &dsa->wqs[i];

		/* Each WQCONFIG reg is 16 bytes (A, B, C, and D registers) */
		wq_offset = DSA_WQCFG_OFFSET + i * 16;

		wqcfg.a.val = readl(dsa->reg_base + wq_offset);
		wqcfg.b.val = readl(dsa->reg_base + wq_offset + 4);
		wqcfg.c.val = readl(dsa->reg_base + wq_offset + 8);

		for (j = 0; j < 4; j++)
			if (dsa->grpcfg[j].wq_bits[i / BITS_PER_LONG] &
						(1 << (i % BITS_PER_LONG)))
				wq->grp_id = j;

		wq->dedicated = wqcfg.c.c_fields.mode;
		wq->wq_size = wqcfg.a.a_fields.wq_size;
		wq->threshold = wqcfg.b.b_fields.threshold;
		wq->priority = wqcfg.c.c_fields.priority;
		wq->idx = i;

		if (dsa->wqs[i].dedicated)
			dsa->num_dwqs++;

		printk("init wq %d dedicated %d sz %d grp %d\n", i,
				wq->dedicated, wq->wq_size, wq->grp_id);
	}
}

/**
 * dsa_enumerate_work_queues - configure the device's work queues
 * @dsa_dma: the dsa dma device to be enumerated
 */
static int dsa_enumerate_work_queues(struct dsadma_device *dsa)
{
	struct device *dev = &dsa->pdev->dev;
	struct dma_device *dma = &dsa->dma_dev;
	int i ;
	unsigned int wq_size, allocated_size;

	dsa->wqcap = readq(dsa->reg_base + DSA_WQCAP_OFFSET);

	dsa->tot_wq_size = (dsa->wqcap & DSA_CAP_WQ_SIZE_MASK);

	dsa->max_wqs = (dsa->wqcap & DSA_CAP_MAX_WQ_MASK) >>
						DSA_CAP_MAX_WQ_SHIFT;
	dsa->max_engs = (dsa->wqcap & DSA_CAP_MAX_ENG_MASK) >>
						DSA_CAP_MAX_ENG_SHIFT;

	dsa->wq_cfg_support = (dsa->wqcap & DSA_CAP_WQ_CFG_MASK) >>
				DSA_CAP_WQ_CFG_SHIFT;

	dsa->wqs = devm_kzalloc(dev, sizeof(struct dsa_work_queue) *
						dsa->max_wqs, GFP_KERNEL);

	if (dsa->wqs == NULL) {
		dev_err(dev, "Allocating %d WQ structures!\n", dsa->max_wqs);
		return -ENOMEM;
	}

	dsa->grpcfg = devm_kzalloc(dev, sizeof(struct dsa_grpcfg_reg) *
						dsa->max_engs, GFP_KERNEL);
	if (dsa->grpcfg == NULL) {
		dev_err(dev, "Allocating %d grpcfg structures!\n", dsa->max_engs);
		return -ENOMEM;
	}

	if (dsa->wq_cfg_support == 0) {
		/* can't configure the WQs. so read the WQ config */
		dsa_get_wq_grp_config(dsa);

		goto skip_wq_config;
	}
	/* We can't use SWQs if PASID was not enabled */
	if (!dsa->pasid_enabled)
		dsa_num_swqs = 0;

	if (dsa_num_dwqs)
		dsa->num_wqs += dsa_num_dwqs;
	if (dsa_num_swqs)
		dsa->num_wqs += dsa_num_swqs;

	/* by default #WQs = #Engines, and #DWQs = #SWQs */
	if (dsa->num_wqs == 0) {
		dsa->num_wqs = dsa->max_engs;
		dsa_num_swqs = dsa->max_engs/2;
		if (!dsa->pasid_enabled)
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

	/* FIXME: currently all SWQs are in one group and all DWQs in another */
	if (dsa_num_dwqs > 0) {	
		for (i = 0; i < dsa_num_dwqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 1;
			dsa->wqs[i].wq_size = wq_size;
			dsa->wqs[i].idx = i;
			dsa->wqs[i].threshold = (dsa->wqs[i].wq_size * 8)/10;
			allocated_size += wq_size;
		}
		dsa->num_grps++;
		if (dsa_num_swqs == 0) {
			/* readjust last WQ to account for integer arithmatic */
			dsa->wqs[i-1].wq_size += dsa->tot_wq_size -
							allocated_size;
			dsa->wqs[i-1].threshold = (dsa->wqs[i - 1].wq_size * 8)/
							10;
		}
		dsa->num_dwqs = dsa_num_dwqs;
	}
	if (dsa_num_swqs > 0) {	
		for (i = dsa_num_dwqs; i < dsa->num_wqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 0;
			dsa->wqs[i].wq_size = wq_size * 2;
			dsa->wqs[i].threshold = (dsa->wqs[i].wq_size * 8)/10;
			dsa->wqs[i].priority = i;
			dsa->wqs[i].idx = i;
			allocated_size += (wq_size * 2);
		}
		/* readjust the last SWQ to account for integer arithmatic */
		dsa->wqs[i-1].wq_size += dsa->tot_wq_size - allocated_size;
		dsa->wqs[i-1].threshold = (dsa->wqs[i - 1].wq_size * 8)/10;
		dsa->num_grps++;
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
		init_timer(&wq->timer);
		wq->timer.function = dsa_timer_event;
       		wq->timer.data = (unsigned long)wq;

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

	err = dsa_register(dsa_dma);
	if (err)
		return err;

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

	dsa_host_init(device);

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

	dsa_host_exit(device);

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
