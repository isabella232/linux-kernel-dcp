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

static void dsa_dma_test_callback(void *dma_async_param)
{
	struct completion *cmp = dma_async_param;

	complete(cmp);
}

/*
 * Perform a DSA transaction to verify the HW works.
 */
#define DSA_TEST_SIZE 2000

static struct completion cmp;

static int dsa_dma_batch_memcpy_self_test_swq (struct dsadma_device *dsa)
{
	int i, num_descs;
	u8 *src;
	u8 *dest;
	struct dsa_dma_descriptor *batch;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *comp_rec;
	struct device *dev = &dsa->pdev->dev;
	struct dma_async_tx_descriptor *tx;
	int err = 0;
	unsigned long tmo = 0;
	unsigned long flags = 0;
	int order, comp_order, buf_size, batch_size, cr_size;

	/* find a SWQ */
	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &dsa->wqs[i];
		if (wq->dedicated == 0)
			break;
	}
	if (i == dsa->num_wqs)
		return 0;

	num_descs = dsa->max_batch_size;

	batch_size = sizeof(struct dsa_dma_descriptor) * num_descs;
	batch = kzalloc(batch_size, GFP_KERNEL);
	if (!batch)
		return -ENOMEM;

	cr_size = sizeof(struct dsa_completion_record) * num_descs;
	comp_order = get_order(cr_size);
	comp_rec = (struct dsa_completion_record *)__get_free_pages(GFP_KERNEL,
					comp_order);
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
		free_pages((unsigned long)comp_rec, comp_order);
		return -ENOMEM;
	}

	dest = (u8 *)__get_free_pages(GFP_KERNEL, order);
	if (!dest) {
		kfree(batch);
		free_pages((unsigned long)comp_rec, comp_order);
		free_pages((unsigned long)src, order);
		return -ENOMEM;
	}

	/* Fill in src buffer */
	for (i = 0; i < buf_size; i++)
		src[i] = (u8)i;

	memset(dest, 0, buf_size);
	memset(comp_rec, 0, cr_size);

	printk("testing memcpy using wq dedicated %d idx %d \n", wq->dedicated, wq->idx);

	flags = DMA_PREP_INTERRUPT;
	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record  *compl_addr = comp_rec + i;
		u8  *src_page = src + (i << PAGE_SHIFT);
		u8  *dst_page = dest + (i << PAGE_SHIFT);

		__dsa_prep_batch_memcpy(wq, (u64)dst_page, (u64)src_page,
				&batch[i], (u64)compl_addr, PAGE_SIZE, flags);
	}
	tx = __dsa_prep_batch(wq, (u64)batch, num_descs, flags);
	if (!tx) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}
	init_completion(&cmp);
	tx->callback = dsa_dma_test_callback;
	tx->callback_param = &cmp;

	__dsa_issue_pending(wq);

	tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(10000));

	if (tmo == 0) {
		dev_err(dev, "Self-test copy timed out, disabling\n");
		err = -ENODEV;
		goto out;
	}
	for (i = 0; i < num_descs; i++) {
		struct dsa_completion_record *comp = &comp_rec[i];

		if (comp->status == DSA_COMP_SUCCESS) {
			if (memcmp(src + (i << PAGE_SHIFT), dest +
				(i << PAGE_SHIFT), PAGE_SIZE)) {
				dev_err(dev, "Self-test Batch copy page %d failed compare, disabling\n", i);
				err = -ENODEV;
				goto out;
			}
		} else if (comp->status) {
			printk("desc %d operation %d failure %d\n",
				i, batch[i].opcode, comp->status);
		} else {
			printk("desc %d operation %d abandoned\n",
						i, batch[i].opcode);
		}
	}
out:
	free_pages((unsigned long)src, order);
	free_pages((unsigned long)dest, order);
	kfree(batch);
	free_pages((unsigned long)comp_rec, comp_order);
	return err;
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

		tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(10000));

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
 * dsa_dma_self_test_svm - Perform a DSA transaction to verify the HW works.
 * @dsa_dma: dma device to be tested
 */
static int dsa_dma_memcpy_self_test_swq (struct dsadma_device *dsa)
{
	int i;
	u8 *src;
	u8 *dest;
	struct device *dev = &dsa->pdev->dev;
	struct dma_async_tx_descriptor *tx;
	struct dsa_work_queue *wq;
	int err = 0;
	struct completion cmp;
	unsigned long tmo = 0;
	unsigned long flags;

	/* find a SWQ */
	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &dsa->wqs[i];
		if (wq->dedicated == 0)
			break;
	}
	if (i == dsa->num_wqs)
		return 0;

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

	memset(dest, 0, DSA_TEST_SIZE);

	printk("testing memcpy using wq dedicated %d idx %d \n", wq->dedicated, wq->idx);

	flags = DMA_PREP_INTERRUPT;
	tx = __dsa_prep_memcpy(wq, (u64)dest, (u64)src, DSA_TEST_SIZE,
								flags);
	if (!tx) {
		dev_err(dev, "Self-test prep failed, disabling\n");
		err = -ENODEV;
		goto out;
	}

	init_completion(&cmp);
	tx->callback = dsa_dma_test_callback;
	tx->callback_param = &cmp;

	__dsa_issue_pending(wq);

	tmo = wait_for_completion_timeout(&cmp, msecs_to_jiffies(100));

	if (tmo == 0) {
		dev_err(dev, "Self-test copy timed out, disabling\n");
		err = -ENODEV;
		goto out;
	}
	if (memcmp(src, dest, DSA_TEST_SIZE)) {
		dev_err(dev, "Self-test copy failed, disabling\n");
		err = -ENODEV;
		goto out;
	}
out:
	kfree(src);
	kfree(dest);
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

err_self_test:
	return err;
}


