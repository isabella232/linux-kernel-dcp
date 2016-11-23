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
#include <linux/dca.h>
#include <linux/aer.h>
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

MODULE_VERSION(DSA_DMA_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Intel Corporation");

static struct pci_device_id dsa_pci_tbl[] = {
	/* DSA vr1.0 platforms */
	{ PCI_VDEVICE(INTEL, PCI_DEVICE_ID_INTEL_DSA_SPR0) },

	{ 0, }
};
MODULE_DEVICE_TABLE(pci, dsa_pci_tbl);

static int dsa_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void dsa_remove(struct pci_dev *pdev);
static int dsa_init_wq(struct dsadma_device *dsa_dma, int idx);
static void dsa_enumerate_capabilities(struct dsadma_device *dsa_dma);
static int dsa_configure_groups(struct dsadma_device *dsa);
static int dsa_enumerate_work_queues(struct dsadma_device *dsa);
static int dsa_dma_memcpy_self_test(struct dsadma_device *dsa_dma);
static int dsa_init_completion_ring(struct dsadma_device *dsa, int ring_idx);

static int dsa_num_dwqs = 0;
module_param(dsa_num_dwqs, int, 0644);
MODULE_PARM_DESC(dsa_num_dwqs, "Number of DWQs");

static int dsa_num_swqs = 0;
module_param(dsa_num_swqs, int, 0644);
MODULE_PARM_DESC(dsa_num_swqs, "Number of SWQs");

int dsa_pending_level = 4;
module_param(dsa_pending_level, int, 0644);
MODULE_PARM_DESC(dsa_pending_level,
		 "high-water mark for pushing dsa descriptors (default: 4)");

struct kmem_cache *dsa_cache;

/*
 * Perform a DSA transaction to verify the HW works.
 */
#define DSA_TEST_SIZE 2000

static void dsa_dma_test_callback(void *dma_async_param)
{
	struct completion *cmp = dma_async_param;

	complete(cmp);
}

static int dsa_dma_batch_memcpy_self_test(struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src;
	u8 *dest;
	struct dsa_dma_descriptor *batch;
	struct dsa_completion_record *comp_rec;
	struct dma_device *dma = &dsa->dma_dev;
	struct device *dev = &dsa->pdev->dev;
	struct dma_chan *dma_chan;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dest, dma_src, dma_batch, dma_compl;
	dma_cookie_t cookie;
	int err = 0;
	struct completion cmp;
	unsigned long tmo = 0;
	unsigned long flags;
	int order, buf_size, batch_size, cr_size;

	num_descs = dsa->max_batch_size;

	batch_size = sizeof(struct dsa_dma_descriptor) * num_descs;
	batch = kzalloc(batch_size, GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	cr_size = sizeof(struct dsa_completion_record) * num_descs;
	comp_rec = kzalloc(cr_size, GFP_KERNEL);
	if (!comp_rec) {
		kfree(batch);
		return -ENOMEM;
	}

	printk("testing batch test for max batch size %d base %p comp %p\n", num_descs, batch, comp_rec);

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	src = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src) {
		kfree(batch);
		kfree(comp_rec);
		return -ENOMEM;
	}

	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		kfree(batch);
		kfree(comp_rec);
		free_pages((unsigned long)src, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++)
		src[i] = (u8)i;

	/* Test copy, using each DMA channel */
	list_for_each_entry(dma_chan, &dma->channels, device_node) {
		memset(dest, 0, buf_size);
		memset(comp_rec, 0, cr_size);

		printk("testing memcpy using wq dedicated %d idx %d \n", to_dsa_wq(dma_chan)->dedicated, to_dsa_wq(dma_chan)->idx);

		dma_src = dma_map_single(dev, src, buf_size, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_src)) {
			dev_err(dev, "mapping src buffer failed %d\n", i);
			goto out;
		}
		dma_dest = dma_map_single(dev, dest, buf_size, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed %d\n", i);
			goto unmap_src;
		}

		dma_batch = dma_map_single(dev, batch, batch_size, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_batch)) {
			dev_err(dev, "mapping batch buffer failed\n");
			goto unmap_dest;
		}

		dma_compl = dma_map_single(dev, comp_rec, cr_size, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_compl)) {
			dev_err(dev, "mapping Comp Rec buffer failed\n");
			goto unmap_batch;
		}

		for (i = 0; i < num_descs; i++) {
			dma_addr_t  compl_addr = dma_compl + (i * sizeof(struct
					dsa_completion_record));
			dma_addr_t  dma_src_page = dma_src + (i << PAGE_SHIFT);
			dma_addr_t  dma_dst_page = dma_dest + (i << PAGE_SHIFT);

			dsa_dma_prep_batch_memcpy(dma_chan, dma_dst_page,
		      	dma_src_page, &batch[i], compl_addr, PAGE_SIZE, flags);
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa_dma_prep_batch(dma_chan, dma_batch, num_descs, flags);
		if (!tx) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		async_tx_ack(tx);
		init_completion(&cmp);
		tx->callback = dsa_dma_test_callback;
		tx->callback_param = &cmp;
		cookie = tx->tx_submit(tx);
		if (cookie < 0) {
			dev_err(dev, "Self-test setup failed, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		dma->device_issue_pending(dma_chan);

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(200));

		if (tmo == 0 ||
	    	dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		for (i = 0; i < num_descs; i++) {
			struct dsa_completion_record *comp = &comp_rec[i];

			if (comp->status == DSA_COMP_SUCCESS) {
				if (memcmp(src + (i << PAGE_SHIFT), dest +
					(i << PAGE_SHIFT), PAGE_SIZE)) {
					dev_err(dev, "Self-test Batch copy page %d failed compare, disabling\n", i);
					err = -ENODEV;
					goto unmap_dma;
				}
			} else if (comp->status) {
				printk("desc %d operation %d failure %d\n", i, batch[i].opcode, comp->status);
			} else {
				printk("desc %d operation %d abandoned\n", i, batch[i].opcode);
			}
		}
unmap_dma:
		dma_unmap_single(dev, dma_compl, cr_size, DMA_FROM_DEVICE);
unmap_batch:
		dma_unmap_single(dev, dma_batch, batch_size, DMA_TO_DEVICE);
unmap_dest:
		dma_unmap_single(dev, dma_dest, buf_size, DMA_FROM_DEVICE);
unmap_src:
		dma_unmap_single(dev, dma_src, buf_size, DMA_TO_DEVICE);
	}
out:
	free_pages((unsigned long)src, order);
	free_pages((unsigned long)dest, order);
	kfree(batch);
	kfree(comp_rec);
	return err;
}

/**
 * dsa_dma_self_test - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_memcpy_self_test(struct dsadma_device *dsa)
{
	int i;
	u8 *src;
	u8 *dest;
	struct dma_device *dma = &dsa->dma_dev;
	struct device *dev = &dsa->pdev->dev;
	struct dma_chan *dma_chan;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dest, dma_src;
	dma_cookie_t cookie;
	int err = 0;
	struct completion cmp;
	unsigned long tmo = 0;
	unsigned long flags;

	src = kzalloc(sizeof(u8) * DSA_TEST_SIZE, GFP_KERNEL);
	if (!src)
		return -ENOMEM;
	dest = kzalloc(sizeof(u8) * DSA_TEST_SIZE, GFP_KERNEL);
	if (!dest) {
		kfree(src);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < DSA_TEST_SIZE; i++)
		src[i] = (u8)i;

	/* Test copy, using each DMA channel */
	list_for_each_entry(dma_chan, &dma->channels, device_node) {
		memset(dest, 0, DSA_TEST_SIZE);

		printk("testing memcpy using wq dedicated %d idx %d \n", to_dsa_wq(dma_chan)->dedicated, to_dsa_wq(dma_chan)->idx);

		if (dma->device_alloc_chan_resources(dma_chan) < 1) {
			dev_err(dev, "selftest cannot allocate chan resource\n");
			err = -ENODEV;
			goto out;
		}

		dma_src = dma_map_single(dev, src, DSA_TEST_SIZE, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_src)) {
			dev_err(dev, "mapping src buffer failed\n");
			goto free_resources;
		}
		dma_dest = dma_map_single(dev, dest, DSA_TEST_SIZE, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed\n");
			goto unmap_src;
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa->dma_dev.device_prep_dma_memcpy(dma_chan, dma_dest,
						      dma_src, DSA_TEST_SIZE,
						      flags);
		if (!tx) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}

		async_tx_ack(tx);
		init_completion(&cmp);
		tx->callback = dsa_dma_test_callback;
		tx->callback_param = &cmp;
		cookie = tx->tx_submit(tx);
		if (cookie < 0) {
			dev_err(dev, "Self-test setup failed, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		dma->device_issue_pending(dma_chan);

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(100));

		if (tmo == 0 ||
	    	dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		if (memcmp(src, dest, DSA_TEST_SIZE)) {
			dev_err(dev, "Self-test copy failed compare, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
unmap_dma:
		dma_unmap_single(dev, dma_dest, DSA_TEST_SIZE, DMA_FROM_DEVICE);
unmap_src:
		dma_unmap_single(dev, dma_src, DSA_TEST_SIZE, DMA_TO_DEVICE);
free_resources:
		dma->device_free_chan_resources(dma_chan);
	}
out:
	kfree(src);
	kfree(dest);
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

	enable |= DSA_ENABLE_BIT;

	writel(enable, dsa->reg_base + DSA_ENABLE_OFFSET);

	for (i = 0; i < 200000; i++) {
		enable = readl(dsa->reg_base + DSA_ENABLE_OFFSET);
		if ((enable & DSA_ENABLED_BIT) || (enable & DSA_ERR_BITS))
			break;
	}

	if ((i == 200000) || (enable & DSA_ERR_BITS)) {
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

		for (j = 0; j < 200000; j++) {
			wqcfg.d.val = readl(dsa->reg_base + wq_offset + 0xC);
			if ((wqcfg.d.d_fields.wq_enabled) ||
					(wqcfg.d.d_fields.wq_err))
				break;
		}

		if ((j == 200000) || wqcfg.d.d_fields.wq_err) {
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
	struct dsa_completion_ring *dsa_ring;
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

	err = pci_enable_msix_exact(pdev, dsa->msix_entries, msixcnt);
	if (err) {
		dev_err(dev, "Enabling %d MSI-X entries!\n", msixcnt);
		goto err_no_irq;
	}

	/* we implement 1 completion ring per MSI-X entry except for entry 0 */
	dsa->comp_rings = devm_kzalloc(dev, sizeof(struct dsa_completion_ring) *
						msixcnt - 1, GFP_KERNEL);

	dsa->msixcnt = msixcnt;
	if (dsa->comp_rings == NULL) {
		dev_err(dev, "Allocating %d completion rings!\n", msixcnt);
		err = -ENOMEM;
		goto err_no_irq;
	}

	/* No need to initialize the first completion ring because MSIX entry 0
	 * is not used for WQ completion interrupts. MSI-X entry 0 is used for
	 * other miscellaneous interrupts. */
	for (i = 1; i < msixcnt; i++)
		dsa_init_completion_ring(dsa, i);

	for (i = 0; i < msixcnt; i++) {
		msix = &dsa->msix_entries[i];
		dsa_ring = &dsa->comp_rings[i];

		data = (unsigned long)dsa_ring;

		if (i == 0) {
			err = devm_request_irq(dev, msix->vector,
				       dsa_misc_interrupt, 0,
				       "dsa-msix", dsa_ring);
			tasklet_init(&dsa_ring->cleanup_task, dsa_misc_cleanup,
								data);
		} else {
			err = devm_request_irq(dev, msix->vector,
				       dsa_wq_completion_interrupt, 0,
				       "dsa-msix", dsa_ring);
			tasklet_init(&dsa_ring->cleanup_task, dsa_wq_cleanup,
							data);
		}
		if (err) {
			for (j = 0; j < i; j++) {
				msix = &dsa->msix_entries[j];
				dsa_ring = &dsa->comp_rings[i];
				devm_free_irq(dev, msix->vector, dsa_ring);
				tasklet_kill(&dsa_ring->cleanup_task);
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

	dsa_enumerate_capabilities(dsa_dma);

	dsa_enumerate_work_queues(dsa_dma);

	dsa_configure_groups(dsa_dma);

	dma->dev = &pdev->dev;

	err = dsa_dma_setup_interrupts(dsa_dma);
	if (err)
		goto err_setup_interrupts;

	err = dsa_enable_device(dsa_dma);
	if (err)
		goto err_self_test;

	printk("DSA device enabled successfully\n");
	err = dsa_dma_memcpy_self_test(dsa_dma);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_memcpy_self_test(dsa_dma);
	if (err)
		goto err_self_test;
	return 0;

err_self_test:
	dsa_disable_interrupts(dsa_dma);
err_setup_interrupts:
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

	dsa_dma->max_batch_size = (dsa_dma->gencap & DSA_CAP_MAX_BATCH_MASK) >>
					DSA_CAP_MAX_BATCH_SHIFT;
	dsa_dma->ims_size = (dsa_dma->gencap & DSA_CAP_IMS_MASK) >>
					DSA_CAP_IMS_SHIFT;

	dsa_dma->opcap = readq(dsa_dma->reg_base + DSA_OPCAP_OFFSET);

	dma_cap_set(DMA_PRIVATE, dma->cap_mask);

	printk("opcap %llx\n", dsa_dma->opcap);
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
	/* FIXME: need to configure VCs */
	return 0;
}

static int dsa_init_completion_ring(struct dsadma_device *dsa, int ring_idx)
{
	struct dsa_completion_ring *dring = &dsa->comp_rings[ring_idx];

	dring->dsa = dsa;

	spin_lock_init(&dring->cleanup_lock);
	dring->head = 0;
	dring->tail = 0;
	dring->idx = ring_idx;
	dring->dmacount = 0;
	dring->completed = 0;

	/* FIXME: currently we allocate a completion ring per WQ. If a SWQ, the
	 * the ring size is (maximum wq size * 2). If a DWQ, the ring size is
	 * equal to the size of size of SWQ.
	 */
	if (ring_idx > dsa->num_wqs || !dsa->wqs[ring_idx].dedicated)
		dring->num_entries = dsa->tot_wq_size * 2;
	else
		dring->num_entries = dsa->wqs[ring_idx].wq_size;

	dring->comp_ring_size = dring->num_entries * sizeof(struct dsa_completion_record);
	dring->desc_ring_size = dring->num_entries * sizeof(struct dsa_dma_descriptor);
	return dsa_alloc_completion_ring(dring, GFP_KERNEL);
}


static int dsa_init_wq (struct dsadma_device *dsa, int wq_idx)
{
	struct dsa_work_queue *wq = &dsa->wqs[wq_idx];
	struct dsa_work_queue_reg wqcfg;
	struct dma_device *dma = &dsa->dma_dev;
	unsigned long data = (unsigned long) wq;
	unsigned int wq_offset;

	memset(&wqcfg, 0, sizeof(wqcfg));

	printk("init wq %d dedicated %d sz %d\n", wq_idx, wq->dedicated, wq->wq_size);
	wq->dsa = dsa;
	spin_lock_init(&wq->lock);
	wq->dma_chan.device = dma;
	dma_cookie_init(&wq->dma_chan);
	list_add_tail(&wq->dma_chan.device_node, &dma->channels);
	init_timer(&wq->timer);
	wq->timer.function = dsa_timer_event;
        wq->timer.data = data;

	/* Each WQCONFIG register is 16 bytes (A, B, C, and D registers) */
	wq_offset = DSA_WQCFG_OFFSET + wq_idx * 16;

	wqcfg.c.c_fields.mode = wq->dedicated ? 1 : 0;
	/* Enable the BOF if it is supported */
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		wqcfg.c.c_fields.bof_en = 1;

	wqcfg.c.c_fields.priority = wq->priority;
	wqcfg.c.c_fields.u_s = 1;

	writel(wqcfg.c.val, dsa->reg_base + wq_offset + 8);
	
	wqcfg.b.b_fields.threshold = wq->threshold;

	writel(wqcfg.b.val, dsa->reg_base + wq_offset + 4);

	wqcfg.a.a_fields.wq_size = wq->wq_size;

	writel(wqcfg.a.val, dsa->reg_base + wq_offset);

	return 0;
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
	unsigned int dwq_size, allocated_size;

	dsa->wqcap = readq(dsa->reg_base + DSA_WQCAP_OFFSET);

	dsa->tot_wq_size = (dsa->wqcap & DSA_CAP_WQ_SIZE_MASK);

	dsa->max_wqs = (dsa-> wqcap & DSA_CAP_MAX_WQ_MASK) >>
						DSA_CAP_MAX_WQ_SHIFT;
	dsa->max_engs = (dsa-> wqcap & DSA_CAP_MAX_ENG_MASK) >>
						DSA_CAP_MAX_ENG_SHIFT;

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

	if (dsa_num_dwqs)
		dsa->num_wqs += dsa_num_dwqs;
	if (dsa_num_swqs)
		dsa->num_wqs += dsa_num_swqs;

	if (dsa->num_wqs > dsa->max_wqs) {
		dev_err(dev, "Can't config more than %d WQs.\n", dsa->max_wqs);
		return -EINVAL;
	}

	/* by default #WQs = #Engines, and #DWQs = #SWQs */
	if (dsa->num_wqs == 0) {
		dsa->num_wqs = dsa->max_engs;
		dsa_num_dwqs = dsa->max_engs/2;
		dsa_num_swqs = dsa->max_engs - dsa_num_dwqs;
	}

	/* The current logic is to divide the total WQ size such that each SWQ
	 * has twice the size of each DWQ. All SWQs are equal in size and all
	 * DWQs are equal in size. */

	dwq_size = dsa->tot_wq_size/(dsa_num_swqs * 2 + dsa_num_dwqs);
	allocated_size = 0;

	if (dsa->num_wqs > dsa->max_engs) {
		dev_err(dev, "[%d:%d] Num WQs > Num Engines\n", dsa->num_wqs,
							dsa->max_engs);
		return -EINVAL;
	}

	/* FIXME: currently all SWQs are in one group and all DWQs in another */
	if (dsa_num_dwqs > 0) {	
		for (i = 0; i < dsa_num_dwqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 1;
			dsa->wqs[i].wq_size = dwq_size;
			dsa->wqs[i].idx = i;
			dsa->wqs[i].threshold = (dsa->wqs[i].wq_size * 8)/10;
			allocated_size += dwq_size;
		}
		dsa->num_grps++;
	}
	if (dsa_num_swqs > 0) {	
		for (i = dsa_num_dwqs; i < dsa->num_wqs; i++) {
			dsa->wqs[i].grp_id = dsa->num_grps;
			dsa->wqs[i].dedicated = 0;
			dsa->wqs[i].wq_size = dwq_size * 2;
			dsa->wqs[i].threshold = (dsa->wqs[i].wq_size * 8)/10;
			dsa->wqs[i].priority = i;
			dsa->wqs[i].idx = i;
			allocated_size += (dwq_size * 2);
		}
		/* readjust the last SWQ to account for integer arithmatic */
		dsa->wqs[i-1].wq_size += dsa->tot_wq_size - allocated_size;
		dsa->wqs[i-1].threshold = (dsa->wqs[i - 1].wq_size * 8)/10;
		dsa->num_grps++;
	}

	INIT_LIST_HEAD(&dma->channels);
	dma->chancnt = dsa->num_wqs;

	for (i = 0; i < dsa->num_wqs; i++) {
		dsa_init_wq(dsa, i);
		spin_lock_init(&dsa->wqs[i].lock);
	}
	return 0;
}

/**
 * dsa_free_chan_resources - release all the descriptors
 * @chan: the channel to be cleaned
 */
static void dsa_free_chan_resources(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;

	dring = dsa_get_completion_ring(dsa, wq->idx);

	/* FIXME: Is there something to be done here? */
	return;
}

/* dsa_alloc_chan_resources - allocate/initialize dsa descriptor ring
 * @chan: channel to be initialized
 */
static int dsa_alloc_chan_resources(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring;

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);
	/* have we already been set up? */
	if (dring)
		return dring->num_entries;

	return -EFAULT;
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

#define DRV_NAME "dsadma"

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
	d->gwq_reg_base = iomap[DSA_GUEST_WQ_BAR];
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

	msk = (1 << DSA_MMIO_BAR) | (1 << DSA_WQ_BAR) | (1 << DSA_GUEST_WQ_BAR);
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

	return 0;
}

static void dsa_remove(struct pci_dev *pdev)
{
	struct dsadma_device *device = pci_get_drvdata(pdev);

	if (!device)
		return;

	dev_err(&pdev->dev, "Removing dma services\n");

	pci_disable_pcie_error_reporting(pdev);
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
