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
#include <linux/miscdevice.h>
#include <linux/dca.h>
#include <linux/aer.h>
#include <linux/fs.h>
#include <linux/intel-svm.h>
#include "svm.h"
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

extern int ms_to;

static void dsa_dma_test_callback(void *dma_async_param)
{
	struct completion *cmp = dma_async_param;

	complete(cmp);
}

/*
 * Perform a DSA transaction to verify the HW works.
 */
#define DSA_TEST_SIZE 20000

static struct completion cmp;

static int dsa_dma_batch_memcpy_self_test_swq (struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src;
	u8 *dest;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *compl;
	struct dsa_ring_ent *desc;
	struct dsa_batch *batch;
	struct dsa_completion_ring *dring;
	struct device *dev = &dsa->pdev->dev;
	int err = 0, tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	num_descs = dsa->max_batch_size;

	batch = dsa_alloc_batch_resources(dring, num_descs);

	if (!batch) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;

	}

	printk("testing batch of memcpy: batch size %d, wq %d dedicated %d\n",
		num_descs, wq->idx, wq->dedicated);

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	src = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		free_pages((unsigned long)src, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++)
		src[i] = (u8)i;

	memset(dest, 0, buf_size);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	for (i = 0; i < num_descs; i++) {
		u8  *src_page = src + (i << PAGE_SHIFT);
		u8  *dst_page = dest + (i << PAGE_SHIFT);

		__dsa_prep_batch_memcpy(batch, i, (u64)dst_page, (u64)src_page,
				PAGE_SIZE, flags);
	}

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	desc = __dsa_prep_batch(dring, (u64)batch->descs, num_descs, flags);
	if (!desc) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

	if (tmo < 0) {
		dev_err(dev, "Self-test copy timed out, disabling %d\n", tmo);
		err = -ENODEV;
		goto out;
	}

	compl = desc->completion;

	if (compl->status == DSA_COMP_SUCCESS) {
		printk("operation %d success\n", desc->hw.opcode);
	} else if (compl->status == DSA_COMP_BATCH_FAIL) {
		printk("batch failed completed %d\n", compl->bytes_completed);
	} else if (compl->status == DSA_COMP_BATCH_PAGE_FAULT) {
		printk("Unrecoverable PF on batch\n");
	} else
		printk("Operation %d invalid status %d\n",
				desc->hw.opcode, compl->status);

	dsa_free_desc(dring, desc);

	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &batch->comp[i];

		if (comp->status == DSA_COMP_SUCCESS) {
			if (memcmp(src + (i << PAGE_SHIFT), dest +
				(i << PAGE_SHIFT), PAGE_SIZE)) {
				dev_err(dev, "Self-test Batch copy page %d"
					" failed compare, disabling\n", i);
				err = -ENODEV;
				goto out;
			}
		} else if (comp->status) {
			printk("desc %d failure %d\n", i, comp->status);
		} else {
			printk("desc %d abandoned\n", i);
		}
	}
out:
	free_pages((unsigned long)src, order);
	free_pages((unsigned long)dest, order);
	dsa_free_batch_resources(batch);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	return err;
}

static int dsa_dma_batch_memcpy_self_test(struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src;
	u8 *dest;
	struct dsa_batch *batch;
	struct dma_device *dma = &dsa->dma_dev;
	struct device *dev = &dsa->pdev->dev;
	struct dma_chan *dma_chan;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dest, dma_src;
	dma_cookie_t cookie;
	int err = 0;
	unsigned long tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;

	num_descs = dsa->max_batch_size;

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	src = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src)
		return -ENOMEM;

	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		free_pages((unsigned long)src, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++)
		src[i] = (u8)i;

	/* Test copy, using each DMA channel */
	list_for_each_entry(dma_chan, &dma->channels, device_node) {

		printk("test batch copy: batch sz %d wq %d ded %d\n", num_descs,
		to_dsa_wq(dma_chan)->idx, to_dsa_wq(dma_chan)->dedicated);

		if (dma->device_alloc_chan_resources(dma_chan) < 0)
			goto out;

		batch = dsa_dma_alloc_batch_resources(dma_chan, num_descs);

		if (!batch) {
			dma->device_free_chan_resources(dma_chan);
			goto out;
		}

		memset(dest, 0, buf_size);

		dma_src = dma_map_single(dev, src, buf_size, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_src)) {
			dev_err(dev, "mapping src buffer failed %d\n", i);
			goto unmap_resources;
		}
		dma_dest = dma_map_single(dev, dest, buf_size, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed %d\n", i);
			goto unmap_src;
		}

		for (i = 0; i < num_descs; i++) {
			dma_addr_t  dma_src_page = dma_src + (i << PAGE_SHIFT);
			dma_addr_t  dma_dst_page = dma_dest + (i << PAGE_SHIFT);

			dsa_dma_prep_batch_memcpy(dma_chan, i, dma_dst_page,
				dma_src_page, PAGE_SIZE, flags);
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa_dma_prep_batch(dma_chan, batch->dma_batch, num_descs,
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

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(ms_to));

		if (tmo == 0 ||
	    	dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		for (i = 0; i < num_descs; i++) {
			struct dsa_completion_record *comp = &batch->comp[i];

			if (comp->status == DSA_COMP_SUCCESS) {
				if (memcmp(src + (i << PAGE_SHIFT), dest +
					(i << PAGE_SHIFT), PAGE_SIZE)) {
					dev_err(dev, "Self-test Batch copy page"
					" %d failed, disabling\n", i);
					err = -ENODEV;
					goto unmap_dma;
				}
			} else if (comp->status) {
				printk("desc %d status %d\n", i, comp->status);
			} else {
				printk("desc %d abandoned\n", i);
			}
		}
unmap_dma:
		dma_unmap_single(dev, dma_dest, buf_size, DMA_FROM_DEVICE);
unmap_src:
		dma_unmap_single(dev, dma_src, buf_size, DMA_TO_DEVICE);
unmap_resources:
		dsa_dma_free_batch_resources(batch);
		dma->device_free_chan_resources(dma_chan);
	}
out:
	free_pages((unsigned long)src, order);
	free_pages((unsigned long)dest, order);
	return err;
}

/**
 * dsa_dma_self_test_svm - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_memcpy_self_test_swq (struct dsadma_device *dsa)
{
	int i, len = DSA_TEST_SIZE;
	u8 *src, *src1;
	u8 *dest, *dest1;
	struct device *dev = &dsa->pdev->dev;
	struct dsa_work_queue *wq;
	struct dsa_ring_ent *desc;
	struct dsa_completion_ring *dring;
	struct dsa_completion_record *compl;
	int err = 0, tmo, num_descs;
	unsigned long flags;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	src1 = src = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!src) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}
	dest1 = dest = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!dest) {
		kfree(src);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < len; i++)
		src[i] = (u8)i;

	memset(dest, 0, len);

	printk("testing memcpy: dedicated %d wq %d\n", wq->dedicated, wq->idx);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	num_descs = len / (PAGE_SIZE *2) + !!(len % (PAGE_SIZE *2));

	for (i = 0; i < num_descs; i++) {
		int copy;
		copy = (len <= (PAGE_SIZE *2))? len: (PAGE_SIZE *2);
retry:
		desc = __dsa_prep_memcpy(dring, (u64)dest, (u64)src, copy,
						flags);
		if (desc == NULL) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
		src += copy;
		dest += copy;
		len = len - copy;

		tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

		if (tmo < 0) {
			dev_err(dev, "Self-test copy timed out %d\n", tmo);
			err = -ENODEV;
			goto out;
		}

		compl = desc->completion;

		if (compl->status == DSA_COMP_SUCCESS) {
			printk("operation %d success\n", desc->hw.opcode);
		} else if (compl->status == DSA_COMP_PAGE_FAULT) {
			int *addr = (int *)compl->fault_addr;
			int temp;
			printk("PF addr %llx dir %d bc %d\n", compl->fault_addr,
				compl->result, compl->bytes_completed);

			copy -= compl->bytes_completed;
			if (compl->result == 0) {
				src += compl->bytes_completed;
				dest += compl->bytes_completed;
			}
			/* resolve the page fault by touching the page */
			temp = *addr;
			dsa_free_desc(dring, desc);
			goto retry;
		} else
			printk("memcpy failed with status %d\n", compl->status);
		dsa_free_desc(dring, desc);
	}

	if (memcmp(src1, dest1, DSA_TEST_SIZE)) {
		dev_err(dev, "Self-test copy failed, disabling\n");
		err = -ENODEV;
		goto out;
	}
out:
	kfree(src1);
	kfree(dest1);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
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

		printk("testing memcpy: dedicated %d wq %d\n",
		to_dsa_wq(dma_chan)->dedicated, to_dsa_wq(dma_chan)->idx);

		if (dma->device_alloc_chan_resources(dma_chan) < 1) {
			dev_err(dev, "selftest can't allocate chan resource\n");
			err = -ENODEV;
			goto out;
		}

		dma_src = dma_map_single(dev, src, DSA_TEST_SIZE,DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_src)) {
			dev_err(dev, "mapping src buffer failed\n");
			goto free_resources;
		}
		dma_dest = dma_map_single(dev, dest, DSA_TEST_SIZE,
							DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed\n");
			goto unmap_src;
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa->dma_dev.device_prep_dma_memcpy(dma_chan, dma_dest,
					dma_src, DSA_TEST_SIZE, flags);
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

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(ms_to));

		if (tmo == 0 || dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		if (memcmp(src, dest, DSA_TEST_SIZE)) {
			dev_err(dev, "Self-test copy failed, disabling\n");
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


static int dsa_dma_batch_memset_self_test_swq (struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *dest;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *compl;
	struct dsa_ring_ent *desc;
	struct dsa_batch *batch;
	struct dsa_completion_ring *dring;
	struct device *dev = &dsa->pdev->dev;
	int err = 0, tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;
	u64 val = 0xcdef090234872389;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	num_descs = dsa->max_batch_size;

	batch = dsa_alloc_batch_resources(dring, num_descs);

	if (!batch) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;

	}

	printk("testing batch memset: batch size %d wq %d dedicated %d\n",
		num_descs, wq->idx, wq->dedicated);

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	/* Fill in dest buffer */
	for (i = 0; i < buf_size; i++)
		dest[i] = (u8)i;

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	for (i = 0; i < num_descs; i++) {
		u8  *dst_page = dest + (i << PAGE_SHIFT);

		__dsa_prep_batch_memset(batch, i, (u64)dst_page, val,
				PAGE_SIZE, flags);
	}

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	desc = __dsa_prep_batch(dring, (u64)batch->descs, num_descs, flags);
	if (!desc) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

	if (tmo < 0) {
		dev_err(dev, "Self-test copy timed out, disabling %d\n", tmo);
		err = -ENODEV;
		goto out;
	}

	compl = desc->completion;

	if (compl->status == DSA_COMP_SUCCESS) {
		printk("operation %d success\n", desc->hw.opcode);
	} else if (compl->status == DSA_COMP_BATCH_FAIL) {
		printk("batch failed completed %d\n", compl->bytes_completed);
	} else if (compl->status == DSA_COMP_BATCH_PAGE_FAULT) {
		printk("Unrecoverable PF on batch\n");
	} else
		printk("Batch failed with invalid status %d\n", compl->status);

	dsa_free_desc(dring, desc);

	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &batch->comp[i];

		if (comp->status == DSA_COMP_SUCCESS) {
			int j;
			u64 *ptr = (u64 *)dest;
			for (j = 0; j < buf_size; j+=8, ptr++) {
				if (*ptr != val) {
				dev_err(dev, "Self-test Batch fill page %d"
					" failed, disabling\n", i);
				err = -ENODEV;
				goto out;
				}
			}
		} else if (comp->status) {
			printk("desc %d fail status %d\n", i, comp->status);
		} else {
			printk("desc %d abandoned\n", i);
		}
	}
out:
	free_pages((unsigned long)dest, order);
	dsa_free_batch_resources(batch);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	return err;
}

static int dsa_dma_batch_memset_self_test(struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *dest;
	struct dsa_batch *batch;
	struct dma_device *dma = &dsa->dma_dev;
	struct device *dev = &dsa->pdev->dev;
	struct dma_chan *dma_chan;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dest;
	dma_cookie_t cookie;
	int err = 0;
	unsigned long tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;
	u64 val = 0x34872389;

	num_descs = dsa->max_batch_size;

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		return -ENOMEM;
	}

	/* Fill in dest buffer */
	for (i = 0; i < buf_size; i++)
		dest[i] = (u8)i;

	/* Test copy, using each DMA channel */
	list_for_each_entry(dma_chan, &dma->channels, device_node) {
		if (dma->device_alloc_chan_resources(dma_chan) < 0)
			goto out;

		batch = dsa_dma_alloc_batch_resources(dma_chan, num_descs);

		if (!batch) {
			dma->device_free_chan_resources(dma_chan);
			goto out;

		}

		printk("test batch memset: sz %d ded %d wq %d\n", num_descs,
		to_dsa_wq(dma_chan)->dedicated, to_dsa_wq(dma_chan)->idx);

		dma_dest = dma_map_single(dev, dest, buf_size, DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed %d\n", i);
			goto unmap_resources;
		}

		for (i = 0; i < num_descs; i++) {
			dma_addr_t  dma_dst_page = dma_dest + (i << PAGE_SHIFT);

			dsa_dma_prep_batch_memset(dma_chan, i, dma_dst_page,
					val, PAGE_SIZE, flags);
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa_dma_prep_batch(dma_chan, batch->dma_batch, num_descs,
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

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(ms_to));

		if (tmo == 0 ||
		dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		for (i = 0; i < num_descs; i++) {
			struct dsa_completion_record *comp = &batch->comp[i];

			if (comp->status == DSA_COMP_SUCCESS) {
				int j;
				u32 *ptr = (u32 *)dest;
				for (j = 0; j < buf_size; j+=4, ptr++) {
					if (*ptr != val) {
					dev_err(dev, "Self-test Batch fill page"
					" %d failed, disabling\n", i);
					err = -ENODEV;
					goto unmap_dma;
					}
				}
			} else if (comp->status) {
				printk("desc %d failure %d\n", i, comp->status);
			} else {
				printk("desc %d abandoned\n", i);
			}
		}
unmap_dma:
		dma_unmap_single(dev, dma_dest, buf_size, DMA_FROM_DEVICE);
unmap_resources:
		dsa_dma_free_batch_resources(batch);
		dma->device_free_chan_resources(dma_chan);
	}
out:
	free_pages((unsigned long)dest, order);
	return err;
}

/**
 * dsa_dma_self_test_svm - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_memset_self_test_swq (struct dsadma_device *dsa)
{
	int i, len = DSA_TEST_SIZE;
	u8 *dest, *dest1;
	struct device *dev = &dsa->pdev->dev;
	struct dsa_work_queue *wq;
	struct dsa_ring_ent *desc;
	struct dsa_completion_ring *dring;
	struct dsa_completion_record *compl;
	int err = 0, tmo, num_descs;
	unsigned long flags;
	u64 val = 0xcdef090234872389;
	int j;
	u64 *ptr;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	dest1 = dest = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!dest) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	/* Fill in dest buffer */
	for (i = 0; i < len; i++)
		dest[i] = (u8)i;

	printk("testing memset: dedicated %d wq %d \n", wq->dedicated, wq->idx);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	num_descs = len / (PAGE_SIZE *2) + !!(len % (PAGE_SIZE *2));

	for (i = 0; i < num_descs; i++) {
		int copy;
		copy = (len <= (PAGE_SIZE *2))? len: (PAGE_SIZE *2);
retry:
		desc = __dsa_prep_memset(dring, (u64)dest, val, copy, flags);
		if (desc == NULL) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
		dest += copy;
		len = len - copy;

		tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

		if (tmo < 0) {
			dev_err(dev, "Self-test copy timed out %d\n", tmo);
			err = -ENODEV;
			goto out;
		}

		compl = desc->completion;

		if (compl->status == DSA_COMP_SUCCESS) {
			printk("operation %d success\n", desc->hw.opcode);
		} else if (compl->status == DSA_COMP_PAGE_FAULT) {
			int *addr = (int *)compl->fault_addr;
			int temp;
			printk("PF addr %llx dir %d bc %d\n", compl->fault_addr,
				compl->result, compl->bytes_completed);

			copy -= compl->bytes_completed;
			if (compl->result == 0) {
				dest += compl->bytes_completed;
			}
			/* resolve the page fault by touching the page */
			temp = *addr;
			dsa_free_desc(dring, desc);
			goto retry;
		} else
			printk("Desc failed with status %d\n", compl->status);
		dsa_free_desc(dring, desc);

	}

	ptr = (u64 *)dest1;
	for (j = 0; j < DSA_TEST_SIZE; j+=8, ptr++) {
		if (*ptr != val) {
			dev_err(dev, "Self-test memset failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
	}
out:
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	kfree(dest1);
	return err;
}

/**
 * dsa_dma_self_test - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_memset_self_test(struct dsadma_device *dsa)
{
	int i;
	u8 *dest;
	struct dma_device *dma = &dsa->dma_dev;
	struct device *dev = &dsa->pdev->dev;
	struct dma_chan *dma_chan;
	struct dma_async_tx_descriptor *tx;
	dma_addr_t dma_dest;
	dma_cookie_t cookie;
	int err = 0;
	unsigned long tmo = 0;
	unsigned long flags;
	u32 val = 0x34872389;
	int j;
	u32 *ptr;

	dest = kzalloc(sizeof(u8) * DSA_TEST_SIZE, GFP_KERNEL);
	if (!dest) {
		return -ENOMEM;
	}

	/* Fill in dest buffer */
	for (i = 0; i < DSA_TEST_SIZE; i++)
		dest[i] = (u8)i;

	/* Test copy, using each DMA channel */
	list_for_each_entry(dma_chan, &dma->channels, device_node) {

		printk("testing memset dedicated %d wq %d \n",
		to_dsa_wq(dma_chan)->dedicated, to_dsa_wq(dma_chan)->idx);

		if (dma->device_alloc_chan_resources(dma_chan) < 1) {
			dev_err(dev, "selftest can't allocate chan resource\n");
			err = -ENODEV;
			goto out;
		}

		dma_dest = dma_map_single(dev, dest, DSA_TEST_SIZE,
					DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_dest)) {
			dev_err(dev, "mapping dest buffer failed\n");
			goto free_resources;
		}
		flags = DMA_PREP_INTERRUPT;
		tx = dsa->dma_dev.device_prep_dma_memset(dma_chan, dma_dest,
						val, DSA_TEST_SIZE, flags);
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

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(ms_to));

		if (tmo == 0 || dma->device_tx_status(dma_chan, cookie, NULL)
						!= DMA_COMPLETE) {
			dev_err(dev, "Self-test copy timed out, disabling\n");
			err = -ENODEV;
			goto unmap_dma;
		}
		ptr = (u32 *)dest;
		for (j = 0; j < DSA_TEST_SIZE; j+=4, ptr++) {
			if (*ptr != val) {
				dev_err(dev, "Self-test memset failed\n");
				err = -ENODEV;
				goto out;
			}
		}
unmap_dma:
		dma_unmap_single(dev, dma_dest, DSA_TEST_SIZE, DMA_FROM_DEVICE);
free_resources:
		dma->device_free_chan_resources(dma_chan);
	}
out:
	kfree(dest);
	return err;
}

static int dsa_dma_batch_compare_self_test_swq (struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src1;
	u8 *src2;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *compl;
	struct dsa_ring_ent *desc;
	struct dsa_batch *batch;
	struct dsa_completion_ring *dring;
	struct device *dev = &dsa->pdev->dev;
	int err = 0, tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	num_descs = dsa->max_batch_size;

	batch = dsa_alloc_batch_resources(dring, num_descs);

	if (!batch) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;

	}

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	src1 = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src1) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	src2 = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src2) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		free_pages((unsigned long)src1, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++) {
		src1[i] = (u8)i;
		src2[i] = (u8)i;
	}

	printk("testing batch compare: batch sz %d wq %d dedicated %d \n",
		num_descs, wq->idx, wq->dedicated);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	for (i = 0; i < num_descs; i++) {
		u8  *src1_page = src1 + (i << PAGE_SHIFT);
		u8  *src2_page = src2 + (i << PAGE_SHIFT);

		__dsa_prep_batch_compare(batch, i, (u64)src1_page, (u64)src2_page,
				PAGE_SIZE, flags);
	}

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	desc = __dsa_prep_batch(dring, (u64)batch->descs, num_descs, flags);
	if (!desc) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

	if (tmo < 0) {
		dev_err(dev, "Self-test comp timed out, disabling %d\n", tmo);
		err = -ENODEV;
		goto out;
	}

	compl = desc->completion;

	printk("operation %d status %d\n", desc->hw.opcode, compl->status);
	if (compl->status != DSA_COMP_SUCCESS)
		printk("batch failed completed %d\n", compl->bytes_completed);

	dsa_free_desc(dring, desc);

	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &batch->comp[i];

		if (comp->status != DSA_COMP_SUCCESS || comp->result != 0) {
			dev_err(dev, "Self-test %d status %d res %d match %d",
			i, comp->status, comp->result, comp->bytes_completed);
			err = -ENODEV;
			goto out;
		}
		comp->status = comp->result = 0;
	}
	/* test again but this time the buffers are not equal */
	src1[8] = 0;
	desc = __dsa_prep_batch(dring, (u64)batch->descs, num_descs, flags);
	if (!desc) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

	if (tmo < 0) {
		dev_err(dev, "Self-test copy timed out, disabling %d\n", tmo);
		err = -ENODEV;
		goto out;
	}

	compl = desc->completion;

	printk("operation %d status %d\n", desc->hw.opcode, compl->status);
	if (compl->status != DSA_COMP_SUCCESS)
		printk("batch failed completed %d\n", compl->bytes_completed);

	dsa_free_desc(dring, desc);

	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &batch->comp[i];

		if (comp->result != 0)
			dev_err(dev, "Self-test %d status %d match %d",
				i, comp->status, comp->bytes_completed);
		comp->status = comp->result = 0;
	}
out:
	free_pages((unsigned long)src1, order);
	free_pages((unsigned long)src2, order);
	dsa_free_batch_resources(batch);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	return err;
}

/**
 * dsa_dma_self_test_svm - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_compare_self_test_swq (struct dsadma_device *dsa)
{
	int i, len = DSA_TEST_SIZE;
	u8 *src1, *src1_base;
	u8 *src2, *src2_base;
	struct device *dev = &dsa->pdev->dev;
	struct dsa_work_queue *wq;
	struct dsa_ring_ent *desc;
	struct dsa_completion_ring *dring;
	struct dsa_completion_record *compl;
	int err = 0, tmo, num_descs;
	unsigned long flags;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring)
		return -ENOMEM;

	src1 = src1_base = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!src1)
		return -ENOMEM;
	src2 = src2_base = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!src2) {
		kfree(src1);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < len; i++) {
		src1[i] = (u8)i;
		src2[i] = (u8)i;
	}

	printk("testing compare: wq %d dedicated %d\n", wq->idx, wq->dedicated);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	num_descs = len / (PAGE_SIZE *2) + !!(len % (PAGE_SIZE *2));

	for (i = 0; i < num_descs; i++) {
		int comp;
		comp = (len <= (PAGE_SIZE *2))? len: (PAGE_SIZE *2);
retry:
		desc = __dsa_prep_compare(dring, (u64)src2, (u64)src1, comp,
						flags);
		if (desc == NULL) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
		src1 += comp;
		src2 += comp;
		len = len - comp;

		tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

		if (tmo < 0) {
			dev_err(dev, "Self-test compare timed out %d\n", tmo);
			err = -ENODEV;
			goto out;
		}

		compl = desc->completion;

		printk("Op %d status %d\n", desc->hw.opcode, compl->status);
		if (compl->status == DSA_COMP_PAGE_FAULT) {
			int *addr = (int *)compl->fault_addr;
			int temp;
			printk("PF addr %llx dir %d bc %d\n", compl->fault_addr,
				compl->result, compl->bytes_completed);

			comp -= compl->bytes_completed;
			if (compl->result == 0) {
				src1 += compl->bytes_completed;
				src2 += compl->bytes_completed;
			}
			/* resolve the page fault by touching the page */
			temp = *addr;
			dsa_free_desc(dring, desc);
			goto retry;
		}
		dsa_free_desc(dring, desc);

		if (compl->status != DSA_COMP_SUCCESS || compl->result != 0) {
			dev_err(dev, "Self-test %d stat %d res %d match %d", i,
			compl->status, compl->result, compl->bytes_completed);
			err = -ENODEV;
			goto out;
		}
		compl->status = compl->result = 0;
	}
	/* test again but this time the buffers are not equal */
	src1_base[8] = 0;
	src1 = src1_base;
	src2 = src2_base;
	len = DSA_TEST_SIZE;
	for (i = 0; i < num_descs; i++) {
		int copy;
		copy = (len <= (PAGE_SIZE *2))? len: (PAGE_SIZE *2);
retry1:
		desc = __dsa_prep_compare(dring, (u64)src2, (u64)src1, copy,
						flags);
		if (desc == NULL) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
		src1 += copy;
		src2 += copy;
		len = len - copy;

		tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

		if (tmo < 0) {
			dev_err(dev, "Self-test compare timed out %d\n", tmo);
			err = -ENODEV;
			goto out;
		}

		compl = desc->completion;

		printk("Op %d status %d\n", desc->hw.opcode, compl->status);
		if (compl->status == DSA_COMP_PAGE_FAULT) {
			int *addr = (int *)compl->fault_addr;
			int temp;
			printk("PF addr %llx dir %d bc %d\n", compl->fault_addr,
				compl->result, compl->bytes_completed);

			copy -= compl->bytes_completed;
			if (compl->result == 0) {
				src1 += compl->bytes_completed;
				src2 += compl->bytes_completed;
			}
			/* resolve the page fault by touching the page */
			temp = *addr;
			dsa_free_desc(dring, desc);
			goto retry1;
		}
		dsa_free_desc(dring, desc);
		if (compl->result != 0)
			dev_err(dev, "Self-test compare %d status %d match %d",
				i, compl->status, compl->bytes_completed);
		compl->status = compl->result = 0;
	}
out:
	kfree(src1_base);
	kfree(src2_base);
	return err;
}

static int dsa_dma_batch_dualcast_self_test_swq (struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src;
	u8 *dest1, *dest2;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *compl;
	struct dsa_ring_ent *desc;
	struct dsa_batch *batch;
	struct dsa_completion_ring *dring;
	struct device *dev = &dsa->pdev->dev;
	int err = 0, tmo = 0;
	unsigned long flags = 0;
	int order, buf_size;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	num_descs = dsa->max_batch_size;

	batch = dsa_alloc_batch_resources(dring, num_descs);

	if (!batch) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;

	}

	buf_size = num_descs * PAGE_SIZE;

	order = get_order(buf_size);
	src = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!src) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	dest1 = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest1) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		free_pages((unsigned long)src, order);
		return -ENOMEM;
	}

	dest2 = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest2) {
		dsa_free_batch_resources(batch);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		free_pages((unsigned long)src, order);
		free_pages((unsigned long)dest1, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++)
		src[i] = (u8)i;

	memset(dest1, 0, buf_size);
	memset(dest2, 0, buf_size);

	printk("testing batch dualcast: batch size %d wq %d dedicated %d\n",
		num_descs, wq->idx, wq->dedicated);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	for (i = 0; i < num_descs; i++) {
		u8  *src_page = src + (i << PAGE_SHIFT);
		u8  *dst1_page = dest1 + (i << PAGE_SHIFT);
		u8  *dst2_page = dest2 + (i << PAGE_SHIFT);

		__dsa_prep_batch_dualcast(batch, i, (u64)dst1_page,
			(u64)dst2_page, (u64)src_page, PAGE_SIZE, flags);
	}

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	desc = __dsa_prep_batch(dring, (u64)batch->descs, num_descs, flags);
	if (!desc) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

	if (tmo < 0) {
		dev_err(dev, "Self-test dcast timed out, disabling %d\n", tmo);
		err = -ENODEV;
		goto out;
	}

	compl = desc->completion;

	if (compl->status == DSA_COMP_SUCCESS) {
		printk("operation %d success\n", desc->hw.opcode);
	} else if (compl->status == DSA_COMP_BATCH_FAIL) {
		printk("batch failed completed %d\n", compl->bytes_completed);
	} else if (compl->status == DSA_COMP_BATCH_PAGE_FAULT) {
		printk("Unrecoverable PF on batch\n");
	} else
		printk("Desc failed with invalid status %d\n", compl->status);

	dsa_free_desc(dring, desc);

	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &batch->comp[i];

		if (comp->status == DSA_COMP_SUCCESS) {
			if (memcmp(src + (i << PAGE_SHIFT), dest1 +
				(i << PAGE_SHIFT), PAGE_SIZE) ||
				memcmp(src + (i << PAGE_SHIFT), dest2 +
				(i << PAGE_SHIFT), PAGE_SIZE)) {
				dev_err(dev, "Self-test Batch dcast page %d"
					" failed compare, disabling\n", i);
				err = -ENODEV;
				goto out;
			}
		} else {
			printk("desc %d operation %d failure %d\n",
				i, batch->descs[i].opcode, comp->status);
		}
	}
out:
	free_pages((unsigned long)src, order);
	free_pages((unsigned long)dest2, order);
	free_pages((unsigned long)dest1, order);
	dsa_free_batch_resources(batch);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	return err;
}

static int dsa_dma_dualcast_self_test_swq (struct dsadma_device *dsa)
{
	int i, len = DSA_TEST_SIZE;
	u8 *src, *src_base;
	u8 *dest1, *dest1_base;
	u8 *dest2, *dest2_base;
	struct device *dev = &dsa->pdev->dev;
	struct dsa_work_queue *wq;
	struct dsa_ring_ent *desc;
	struct dsa_completion_ring *dring;
	struct dsa_completion_record *compl;
	int err = 0, tmo, num_descs;
	unsigned long flags;

	/* find a SWQ */
	if ((wq = dsa_wq_alloc(dsa, 0)) == NULL)
		return 0;

	dring = dsa_alloc_svm_resources(wq);
	if (!dring) {
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	src_base = src = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!src) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	dest1_base = dest1 = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!dest1) {
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		kfree(src);
		return -ENOMEM;
	}

	dest2_base = dest2 = kzalloc(sizeof(u8) * len, GFP_KERNEL);
	if (!dest2) {
		kfree(src);
		kfree(dest1);
		dsa_free_descriptors(dring);
		dsa_wq_free(wq);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < len; i++)
		src[i] = (u8)i;

	memset(dest1, 0, len);
	memset(dest2, 0, len);

	printk("test dualcast: wq %d dedicated %d\n", wq->idx, wq->dedicated);

	flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		flags |= DSA_OP_FLAG_BOF;

	num_descs = len / (PAGE_SIZE *2) + !!(len % (PAGE_SIZE *2));

	for (i = 0; i < num_descs; i++) {
		int copy;
		copy = (len <= (PAGE_SIZE *2))? len: (PAGE_SIZE *2);
retry:
		desc = __dsa_prep_dualcast(dring, (u64)dest1, (u64)dest2,
				(u64)src, copy, flags);
		if (desc == NULL) {
			dev_err(dev, "Self-test prep failed, disabling\n");
			err = -ENODEV;
			goto out;
		}
		src += copy;
		dest1 += copy;
		dest2 += copy;
		len = len - copy;

		tmo = dsa_wait_on_desc_timeout(desc, msecs_to_jiffies(ms_to));

		if (tmo < 0) {
			dev_err(dev, "Self-test dcast timed out %d\n", tmo);
			err = -ENODEV;
			goto out;
		}

		compl = desc->completion;

		if (compl->status == DSA_COMP_SUCCESS) {
			printk("operation %d success\n", desc->hw.opcode);
		} else if (compl->status == DSA_COMP_PAGE_FAULT) {
			int *addr = (int *)compl->fault_addr;
			int temp;
			printk("PF addr %llx dir %d bc %d\n", compl->fault_addr,
				compl->result, compl->bytes_completed);

			copy -= compl->bytes_completed;
			if (compl->result == 0) {
				src += compl->bytes_completed;
				dest1 += compl->bytes_completed;
				dest2 += compl->bytes_completed;
			}
			/* resolve the page fault by touching the page */
			temp = *addr;
			dsa_free_desc(dring, desc);
			goto retry;
		} else
			printk("Desc failed with status %d\n", compl->status);
		dsa_free_desc(dring, desc);

	}

	if (memcmp(src_base, dest1_base, DSA_TEST_SIZE)) {
		dev_err(dev, "Self-test dcast failed, disabling\n");
		err = -ENODEV;
		goto out;
	}
	if (memcmp(src_base, dest2_base, DSA_TEST_SIZE)) {
		dev_err(dev, "Self-test dcast failed 2, disabling\n");
		err = -ENODEV;
		goto out;
	}
out:
	kfree(src_base);
	kfree(dest1_base);
	kfree(dest2_base);
	dsa_free_descriptors(dring);
	dsa_wq_free(wq);
	return err;
}


int dsa_dma_self_test (struct dsadma_device *dsa)
{
	int err;

	err = dsa_dma_memcpy_self_test(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_memcpy_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_memcpy_self_test(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_memcpy_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_memset_self_test(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_memset_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_memset_self_test(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_memset_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_compare_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_compare_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_dualcast_self_test_swq(dsa);
	if (err)
		goto err_self_test;

	err = dsa_dma_batch_dualcast_self_test_swq(dsa);
	if (err)
		goto err_self_test;

err_self_test:
	return err;
}


