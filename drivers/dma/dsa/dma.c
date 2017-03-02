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

/*
 * This driver supports an Intel I/OAT DMA engine, which does asynchronous
 * copy operations.
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
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

/**
 * dsa_dma_do_interrupt_msix - handler used for vector-per-channel interrupt mode
 * @irq: interrupt id
 * @data: interrupt data
 */
irqreturn_t dsa_wq_completion_interrupt(int irq, void *data)
{
	struct dsa_irq_entry *irq_entry = data;

	printk("received wq completion interrupt\n");

	tasklet_schedule(&irq_entry->cleanup_task);

	return IRQ_HANDLED;
}

irqreturn_t dsa_misc_interrupt(int irq, void *data)
{
	struct dsa_irq_entry *irq_entry = data;
	struct dsadma_device *dsa = irq_entry->dsa;
	u32 int_cause;

	printk("received misc completion interrupt\n");

	int_cause = readl(dsa->reg_base + DSA_INTCAUSE_OFFSET);

	/* Write to clear the int cause register */
	writel(int_cause, dsa->reg_base + DSA_INTCAUSE_OFFSET);

	printk("INTCAUSE %x\n", int_cause);

	if (int_cause & DSA_INTCAUSE_HWERR) {
		u16 hwerr;
		hwerr = readw(dsa->reg_base + DSA_HWERR_OFFSET);
		printk("HWERR %x\n", hwerr);
		writew(0x3, dsa->reg_base + DSA_HWERR_OFFSET);
	}
	if (int_cause & DSA_INTCAUSE_SWERR) {
		struct dsa_swerr_reg swerr;
		swerr.qw1.val = readq(dsa->reg_base + DSA_SWERR_OFFSET);
		printk("SWERR %llx\n", swerr.qw1.val);
		if (swerr.qw1.qw1_fields.desc_valid &&
					swerr.qw1.qw1_fields.batch) {
			swerr.qw2.val =
				readq(dsa->reg_base + DSA_SWERR_OFFSET + 0x8);
			printk("batchidx %x\n", swerr.qw2.qw2_fields.batch_idx);
		}
		if (swerr.qw1.qw1_fields.err_code == 0x45) {
			swerr.qw3_address =
				readq(dsa->reg_base + DSA_SWERR_OFFSET + 0x10);
			printk("address %llx\n", swerr.qw3_address);
		}
		writeq(0x3, dsa->reg_base + DSA_SWERR_OFFSET);
	}

	tasklet_schedule(&irq_entry->cleanup_task);

	return IRQ_HANDLED;
}

void dsa_stop(struct dsa_work_queue *dsa_wq)
{
#if 0
	struct dsadma_device *dsa_dma = dsa_chan->dsa_dma;
	struct pci_dev *pdev = dsa_dma->pdev;
	int chan_id = chan_num(dsa_chan);
	struct msix_entry *msix;

	/* 1/ stop irq from firing tasklets
	 * 2/ stop the tasklet from re-arming irqs
	 */
	clear_bit(DSA_RUN, &dsa_chan->state);

	/* flush inflight interrupts */
	switch (dsa_dma->irq_mode) {
	case DSA_MSIX:
		msix = &dsa_dma->msix_entries[chan_id];
		synchronize_irq(msix->vector);
		break;
	case DSA_MSI:
	case DSA_INTX:
		synchronize_irq(pdev->irq);
		break;
	default:
		break;
	}

	/* flush inflight timers */
	del_timer_sync(&dsa_chan->timer);

	/* flush inflight tasklet runs */
	tasklet_kill(&dsa_chan->cleanup_task);

	/* final cleanup now that everything is quiesced and can't re-arm */
	dsa_cleanup_event((unsigned long)&dsa_chan->dma_chan);
#endif
}

void __iomem *dsa_get_wq_reg(struct dsadma_device *dsa, int wq_idx,
				int msix_idx, bool priv)
{
	u32 wq_offset;

	if (!priv) {
		wq_offset = wq_idx;
	} else {
		wq_offset = msix_idx * dsa->max_wqs + wq_idx;
	}
	wq_offset = wq_offset << PAGE_SHIFT;

	printk("%d msix_idx %d wq %d wq_offset %x\n", dsa->num_wq_irqs, msix_idx, wq_idx, wq_offset);
	return (dsa->wq_reg_base + wq_offset);
}

int dsa_enqcmds (struct dsa_dma_descriptor *hw, void __iomem * wq_reg)
{
        int retry_count = 5;

	retry_count = 0;

	while (retry_count < 5) {
		if (!enqcmds(hw, wq_reg))
			break;
		else
			printk("received retry\n");
		retry_count++;
	}
	if (retry_count >= 5) {
		/* FIXME: handle this case */
		printk("retry returned %p %p\n", hw, wq_reg);
		return 1;
	}
        return 0;
}

void dsa_issue_pending(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	int i, pending;
	struct dsa_ring_ent *desc;

	spin_lock_bh(&wq->lock);

	pending = dsa_ring_pending(dring);
	if (!pending)
		return;

	dring->dmacount += pending;

	printk("Issuing %d descs using wq %d\n", pending, wq->idx);

	/* FIXME: If pending descs are more than a threshold, issue them into
	 * a batch desc, to avoid submitting too many descs using movdir64b */
	for (i = 0; i < pending; i++) {
		desc = dsa_get_ring_ent(dring, dring->issued + i);

		/* use MOVDIR64B for DWQ */
		movdir64b(&desc->hw, dring->wq_reg);
	}
	dring->issued = add_dring_idx(dring, dring->issued, pending);

	spin_unlock_bh(&wq->lock);
	dev_dbg(to_dev(wq),
		"%s: head: %#x tail: %#x issued: %#x count: %#x\n",
		__func__, dring->head, dring->tail,
		dring->issued, dring->dmacount);
}

static void __dsa_restart_wq(struct dsa_work_queue *wq)
{
#if 0
	/* set the tail to be re-issued */
	dsa_chan->issued = dsa_chan->tail;
	dsa_chan->dmacount = 0;
	mod_timer(&dsa_chan->timer, jiffies + COMPLETION_TIMEOUT);

	dev_dbg(to_dev(dsa_chan),
		"%s: head: %#x tail: %#x issued: %#x count: %#x\n",
		__func__, dsa_chan->head, dsa_chan->tail,
		dsa_chan->issued, dsa_chan->dmacount);

	if (dsa_ring_pending(dsa_chan)) {
		struct dsa_ring_ent *desc;

		desc = dsa_get_ring_ent(dsa_chan, dsa_chan->tail);
		dsa_set_chainaddr(dsa_chan, desc->txd.phys);
		__dsa_issue_pending(dsa_chan);
	} else
		__dsa_start_null_desc(dsa_chan);
#endif
}

static int dsa_quiesce(struct dsa_work_queue *wq, unsigned long tmo)
{
	int err = 0;
#if 0
	unsigned long end = jiffies + tmo;
	u32 status;

	status = dsa_chansts(dsa_chan);
	if (is_dsa_active(status) || is_dsa_idle(status))
		dsa_suspend(dsa_chan);
	while (is_dsa_active(status) || is_dsa_idle(status)) {
		if (tmo && time_after(jiffies, end)) {
			err = -ETIMEDOUT;
			break;
		}
		status = dsa_chansts(dsa_chan);
		cpu_relax();
	}
#endif
	return err;
}

static dma_cookie_t dsa_tx_submit_unlock(struct dma_async_tx_descriptor *tx)
{
	struct dma_chan *c = tx->chan;
	struct dsa_work_queue *wq = to_dsa_wq(c);
	dma_cookie_t cookie;

	cookie = dma_cookie_assign(tx);
	dev_dbg(to_dev(wq), "%s: cookie: %d\n", __func__, cookie);

#if 0
	if (!test_and_set_bit(DSA_CHAN_ACTIVE, &dsa_chan->state))
		mod_timer(&dsa_chan->timer, jiffies + COMPLETION_TIMEOUT);

	/* make descriptor updates visible before advancing dsa->head,
	 * this is purposefully not smp_wmb() since we are also
	 * publishing the descriptor updates to a dma device
	 */
	wmb();

	dsa_chan->head += dsa_chan->produce;

	dsa_update_pending(dsa_chan);
	spin_unlock_bh(&dsa_chan->prep_lock);
#endif
	return cookie;
}

static void dsa_init_ring_ent(struct dsa_ring_ent *entry,
		struct dsa_completion_ring *dring, int desc_idx)
{
	entry->completion = dring->completion_ring_buf +
			desc_idx * sizeof(struct dsa_completion_record);

	/* comp_base is setup for DMAEngine contexts. Rest use SVM contexts */
	if (dring->comp_base) {
		entry->hw.compl_addr = dring->comp_base + desc_idx *
					sizeof(struct dsa_completion_record);
		entry->txd = dring->callback_ring_buf + desc_idx *
					sizeof(struct dma_async_tx_descriptor);

		entry->txd->tx_submit = dsa_tx_submit_unlock;
		entry->txd->phys = __pa(&entry->hw);
	} else {
		entry->hw.compl_addr = (u64)entry->completion;
		entry->cb_desc = dring->callback_ring_buf + desc_idx *
					sizeof(struct dsa_callback_descriptor);
		init_waitqueue_head(&entry->waitq);

		/* Set the PASID and U/S for SWQ */
		if (dring->wq->dedicated == 0) {
			entry->hw.u_s = 1;
			entry->hw.pasid = dring->wq->dsa->system_pasid;
		}
	}
}

void dsa_free_ring_ent(struct dsa_ring_ent *desc, struct dma_chan *chan)
{
	struct dsadma_device *dsa_dma;

	dsa_dma = to_dsadma_device(chan->device);
#if 0
	pci_pool_free(dsa_dma->dma_pool, desc->hw, desc->txd.phys);
	kmem_cache_free(dsa_cache, desc);
#endif
}

void dsa_free_client_buffers (struct dsa_completion_ring *dring)
{

	free_pages((unsigned long)dring->completion_ring_buf,
					get_order(dring->comp_ring_size));
	kfree(dring->ring);
}

int dsa_alloc_client_buffers (struct dsa_completion_ring *dring, gfp_t flags)
{
	struct dsa_ring_ent *ring;
	int order;

	/* allocate the array to hold the software ring */
	ring = kcalloc(dring->num_entries, sizeof(*ring), flags);
	if (!ring)
		return -ENOMEM;
	memset(ring, 0, dring->num_entries * sizeof(*ring));

	order = get_order(dring->comp_ring_size);
	dring->completion_ring_buf = (void *)__get_free_pages(flags, order);

	if (!dring->completion_ring_buf) {
		kfree(ring);
		return -ENOMEM;
	}

	memset(dring->completion_ring_buf, 0, dring->comp_ring_size);

	dring->ring = ring;

	return 0;
}

void dsa_init_completion_ring (struct dsa_completion_ring *dring)
{
	int i;
	struct dsa_ring_ent *ring = dring->ring;

	for (i = 0; i < dring->num_entries; i++) {
		dsa_init_ring_ent(&ring[i], dring, i);
		set_desc_id(&ring[i], i);
	}
}

/**
 * dsa_check_space_lock - verify space and grab ring producer lock
 * @dsa: dsa,3 channel (ring) to operate on
 * @num_descs: allocation length
 */
int dsa_check_space_lock(struct dsa_work_queue *wq, int num_descs)
	__acquires(&wq->lock)
{
#if 0
	bool retry;

 retry:
	spin_lock_bh(&dsa_chan->prep_lock);
	/* never allow the last descriptor to be consumed, we need at
	 * least one free at all times to allow for on-the-fly ring
	 * resizing.
	 */
	if (likely(dsa_ring_space(dsa_chan) > num_descs)) {
		dev_dbg(to_dev(dsa_chan), "%s: num_descs: %d (%x:%x:%x)\n",
			__func__, num_descs, dsa_chan->head,
			dsa_chan->tail, dsa_chan->issued);
		dsa_chan->produce = num_descs;
		return 0;  /* with dsa->prep_lock held */
	}
	retry = test_and_set_bit(DSA_RESHAPE_PENDING, &dsa_chan->state);
	spin_unlock_bh(&dsa_chan->prep_lock);

	/* is another cpu already trying to expand the ring? */
	if (retry)
		goto retry;

	spin_lock_bh(&dsa_chan->cleanup_lock);
	spin_lock_bh(&dsa_chan->prep_lock);
	retry = reshape_ring(dsa_chan, dsa_chan->alloc_order + 1);
	clear_bit(DSA_RESHAPE_PENDING, &dsa_chan->state);
	spin_unlock_bh(&dsa_chan->prep_lock);
	spin_unlock_bh(&dsa_chan->cleanup_lock);

	/* if we were able to expand the ring retry the allocation */
	if (retry)
		goto retry;

	dev_dbg_ratelimited(to_dev(dsa_chan),
			    "%s: ring full! num_descs: %d (%x:%x:%x)\n",
			    __func__, num_descs, dsa_chan->head,
			    dsa_chan->tail, dsa_chan->issued);

	/* progress reclaim in the allocation failure case we may be
	 * called under bh_disabled so we need to trigger the timer
	 * event directly
	 */
	if (time_is_before_jiffies(dsa_chan->timer.expires)
	    && timer_pending(&dsa_chan->timer)) {
		mod_timer(&dsa_chan->timer, jiffies + COMPLETION_TIMEOUT);
		dsa_timer_event((unsigned long)dsa_chan);
	}
#endif
	return -ENOMEM;
}

static void dsa_cleanup(struct dsa_work_queue *wq)
{
#if 0
	u64 phys_complete;

	spin_lock_bh(&dsa_chan->cleanup_lock);

	if (dsa_cleanup_preamble(dsa_chan, &phys_complete))
		__cleanup(dsa_chan, phys_complete);

	if (is_dsa_halted(*dsa_chan->completion)) {
	}

	spin_unlock_bh(&dsa_chan->cleanup_lock);
#endif
}

void dsa_wq_cleanup(unsigned long data)
{
	struct dsa_irq_entry *irq_entry = (struct dsa_irq_entry *)data;
	struct dsa_irq_event *ev;

        /* wake head waiter for each completion ring using this IRQ */
	read_lock(&irq_entry->irq_wait_lock);
	list_for_each_entry(ev, &irq_entry->irq_wait_head, irq_wait_chain) {
		if (ev->isr_cb)
			ev->isr_cb(ev->dring);
		else if (ev->use_waitq)
			wake_up_interruptible(&ev->waitq);
	}
	read_unlock(&irq_entry->irq_wait_lock);
}

void dsa_svm_completion_cleanup(struct dsa_completion_ring *dring)
{
	struct dsa_work_queue *wq;
	struct dsa_completion_record *comp;
	struct dsa_ring_ent *desc;
	int idx;

	idx = dring->tail;
        do {
                desc = dsa_get_ring_ent(dring, idx);
                wq = dring->wq;

                comp = desc->completion;

/*
		if (comp->status == DSA_COMP_SUCCESS) {
			printk("operation %d success\n", desc->desc->opcode);
			cbd = desc->cb_desc;
			if (cbd->callback) {
				cbd->callback(cbd->callback_param);
				cbd->callback = NULL;
			}
			comp->status = 0;
		} else
*/
		if (comp->status) {
			dsa_unlock_desc(desc);
			//printk("operation %d status %d\n", desc->desc->opcode,
					//comp->status);
		} else {
			break;
		}
		idx = inc_dring_idx(dring, idx);
        } while (idx != dring->head);

	printk("svm cleaned completion h:t %d:%d\n", dring->head, dring->tail);
}

void dsa_dma_completion_cleanup(struct dsa_completion_ring *dring)
{
	struct dsa_work_queue *wq;
	struct dsa_completion_record *comp;
	struct dma_async_tx_descriptor *tx;
	struct dsa_ring_ent *desc;
	int idx;

	idx = dring->tail;
	wq = dring->wq;
        do {
                desc = dsa_get_ring_ent(dring, idx);

                comp = desc->completion;

		if (comp->status == DSA_COMP_SUCCESS) {
			tx = desc->txd;

			if (tx->cookie) {
				dma_cookie_complete(tx);
				dma_descriptor_unmap(tx);
			}
			if (tx->callback) {
				tx->callback(tx->callback_param);
				tx->callback = NULL;
			}
			comp->status = 0;
		} else if (comp->status) {
			printk("operation %d failure %d %llx\n",
			desc->hw.opcode, comp->status, comp->op_specific[0]);
		} else {
			break;
		}
		idx = inc_dring_idx(dring, idx);
		dring->tail = idx;
                //dump_desc_dbg(wq, desc);
        } while (idx != dring->head);

	printk("dma cleaned completion h:t %d:%d\n", dring->head, dring->tail);
}

void dsa_misc_cleanup(unsigned long data)
{
	printk("In miscellaneous cleanup\n");
}

static void dsa_restart_wq(struct dsa_work_queue *wq)
{
	dsa_quiesce(wq, 0);
	dsa_cleanup(wq);

	__dsa_restart_wq(wq);
}

void dsa_timer_event(unsigned long data)
{
#if 0
	struct dsa_work_queue *wq = (struct dsa_work_queue *)data;
	dma_addr_t phys_complete;
	u64 status;
	status = dsa_chansts(dsa_chan);

	/* when halted due to errors check for channel
	 * programming errors before advancing the completion state
	 */
	if (is_dsa_halted(status)) {
		u32 chanerr;

		chanerr = readl(dsa_chan->reg_base + DSA_CHANERR_OFFSET);
		dev_err(to_dev(dsa_chan), "%s: Channel halted (%x)\n",
			__func__, chanerr);
		if (test_bit(DSA_RUN, &dsa_chan->state))
			BUG_ON(is_dsa_bug(chanerr));
		else /* we never got off the ground */
			return;
	}

	spin_lock_bh(&dsa_chan->cleanup_lock);

	/* handle the no-actives case */
	if (!dsa_ring_active(dsa_chan)) {
		spin_lock_bh(&dsa_chan->prep_lock);
		check_active(dsa_chan);
		spin_unlock_bh(&dsa_chan->prep_lock);
		spin_unlock_bh(&dsa_chan->cleanup_lock);
		return;
	}

	/* if we haven't made progress and we have already
	 * acknowledged a pending completion once, then be more
	 * forceful with a restart
	 */
	if (dsa_cleanup_preamble(dsa_chan, &phys_complete))
		__cleanup(dsa_chan, phys_complete);
	else if (test_bit(DSA_COMPLETION_ACK, &dsa_chan->state)) {
		u32 chanerr;

		chanerr = readl(dsa_chan->reg_base + DSA_CHANERR_OFFSET);
		dev_warn(to_dev(dsa_chan), "Restarting channel...\n");
		dev_warn(to_dev(dsa_chan), "CHANSTS: %#Lx CHANERR: %#x\n",
			 status, chanerr);
		dev_warn(to_dev(dsa_chan), "Active descriptors: %d\n",
			 dsa_ring_active(dsa_chan));

		spin_lock_bh(&dsa_chan->prep_lock);
		dsa_restart_channel(dsa_chan);
		spin_unlock_bh(&dsa_chan->prep_lock);
		spin_unlock_bh(&dsa_chan->cleanup_lock);
		return;
	} else
		set_bit(DSA_COMPLETION_ACK, &dsa_chan->state);

	mod_timer(&dsa_chan->timer, jiffies + COMPLETION_TIMEOUT);
	spin_unlock_bh(&dsa_chan->cleanup_lock);
#endif
}

enum dma_status dsa_tx_status(struct dma_chan *c, dma_cookie_t cookie,
		struct dma_tx_state *txstate)
{
	//struct dsa_work_queue *wq = to_dsa_wq(c);
	enum dma_status ret;

	ret = dma_cookie_status(c, cookie, txstate);
	if (ret == DMA_COMPLETE)
		return ret;

	return dma_cookie_status(c, cookie, txstate);
}


void dsa_free_batch_resources (struct dsa_batch *batch)
{
	int order;

	order = get_order(sizeof(struct dsa_dma_descriptor) *
						batch->num_descs);
	free_pages((unsigned long)batch->descs, order);

	batch->descs = NULL;

	order = get_order(sizeof(struct dsa_completion_record) *
						batch->num_descs);
	free_pages((unsigned long)batch->comp, order);

	batch->comp = NULL;

	batch->num_descs = 0;
}

void dsa_dma_free_batch_resources (struct dsa_batch *batch)
{
	struct dsa_work_queue *wq = batch->dring->wq;
	struct pci_dev *dev = wq->dsa->pdev;
	int batch_size, comp_size;

	comp_size = batch->num_descs * sizeof (struct dsa_completion_record);
	pci_unmap_single(dev, batch->dma_compl, comp_size, PCI_DMA_FROMDEVICE);

	batch_size = batch->num_descs * sizeof (struct dsa_dma_descriptor);
	pci_unmap_single(dev, batch->dma_batch, batch_size, PCI_DMA_TODEVICE);

	dsa_free_batch_resources(batch);
}

struct dsa_batch *dsa_alloc_batch_resources (struct dsa_completion_ring *dring,
			int num_descs)
{
	struct dsa_batch *batch = &dring->batch;
	int batch_size, batch_order, cr_size, cr_order, i;

	batch->dring = dring;
	batch->num_descs = num_descs;

        batch_size = sizeof(struct dsa_dma_descriptor) * num_descs;
        batch_order = get_order(batch_size);
	/* batch descriptors need to be 64B aligned */
        batch->descs = (struct dsa_dma_descriptor *)
			__get_free_pages(GFP_KERNEL, batch_order);
        if (!batch->descs)
                return NULL;
	memset(batch->descs, 0, batch_size);

        cr_size = sizeof(struct dsa_completion_record) * num_descs;
        cr_order = get_order(cr_size);
	/* batch completion records need to be 64B aligned */
        batch->comp = (struct dsa_completion_record *)
			__get_free_pages(GFP_KERNEL, cr_order);
        if (!batch->comp) {
		free_pages((unsigned long)batch->descs, batch_order);
                return NULL;
        }
	memset(batch->comp, 0, cr_size);

        //printk("batch compl rec %lx desc %lx\n", batch->comp, batch->descs);
	for (i = 0; i < num_descs; i++)
		batch->descs[i].compl_addr = (u64)&batch->comp[i];

	return batch;
}

struct dsa_batch *dsa_dma_alloc_batch_resources (struct dma_chan *dma_chan,
			int num_descs)
{
	struct dsa_work_queue *wq = to_dsa_wq(dma_chan);
	struct pci_dev *dev = wq->dsa->pdev;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_batch *batch;
	int batch_size, comp_size, i;

	batch = dsa_alloc_batch_resources(dring, num_descs);

	comp_size = num_descs * sizeof (struct dsa_completion_record);

        batch->dma_compl = pci_map_single(dev, batch->comp, comp_size,
						PCI_DMA_FROMDEVICE);

        if (dma_mapping_error(&dev->dev, batch->dma_compl)) {
                dsa_free_batch_resources(batch);
		printk("pci map failed\n");
		return NULL;
        }

	batch_size = num_descs * sizeof (struct dsa_dma_descriptor);
        batch->dma_batch = pci_map_single(dev, batch->descs, batch_size,
						PCI_DMA_TODEVICE);
        if (dma_mapping_error(&dev->dev, batch->dma_batch)) {
		pci_unmap_single(dev, batch->dma_compl, comp_size,
						PCI_DMA_FROMDEVICE);
                dsa_free_batch_resources(batch);
		printk("pci map failed\n");
		return NULL;
        }

	for (i = 0; i < num_descs; i++)
		batch->descs[i].compl_addr = (u64)(batch->dma_compl + i *
				sizeof(struct dsa_completion_record));
	return batch;
}

static int dsa_irq_reinit(struct dsadma_device *dsa)
{
	struct pci_dev *pdev = dsa->pdev;
	int i;

	for (i = 0; i < dsa->num_wq_irqs + 1; i++) {
		struct msix_entry *msix = &dsa->msix_entries[i];
		struct dsa_irq_entry *irq_entry = &dsa->irq_entries[i];

		devm_free_irq(&pdev->dev, msix->vector, irq_entry);
	}

	pci_disable_msix(pdev);

	dsa->irq_mode = DSA_NOIRQ;

	return dsa_dma_setup_interrupts(dsa);
}

int dsa_reset_hw(struct dsa_work_queue *wq)
{
	int err = 0;
#if 0
	/* throw away whatever the channel was doing and get it
	 * initialized, with dsa3 specific workarounds
	 */
	struct dsadma_device *dsa = wq->dsa;
	struct pci_dev *pdev = dsa->pdev;
	u32 chanerr;
	u16 dev_id;

	dsa_quiesce(wq, msecs_to_jiffies(100));
	chanerr = readl(dsa_chan->reg_base + DSA_CHANERR_OFFSET);
	writel(chanerr, dsa_chan->reg_base + DSA_CHANERR_OFFSET);

	if (dsa_dma->version < DSA_VER_3_3) {
		/* clear any pending errors */
		err = pci_read_config_dword(pdev,
				DSA_PCI_CHANERR_INT_OFFSET, &chanerr);
		if (err) {
			dev_err(&pdev->dev,
				"channel error register unreachable\n");
			return err;
		}
		pci_write_config_dword(pdev,
				DSA_PCI_CHANERR_INT_OFFSET, chanerr);

		/* Clear DMAUNCERRSTS Cfg-Reg Parity Error status bit
		 * (workaround for spurious config parity error after restart)
		 */
		pci_read_config_word(pdev, DSA_PCI_DEVICE_ID_OFFSET, &dev_id);
		if (dev_id == PCI_DEVICE_ID_INTEL_DSA_TBG0) {
			pci_write_config_dword(pdev,
					       DSA_PCI_DMAUNCERRSTS_OFFSET,
					       0x10);
		}
	}

	err = dsa_reset_sync(dsa_chan, msecs_to_jiffies(200));
	if (!err)
		err = dsa_irq_reinit(dsa_dma);

	if (err)
		dev_err(&pdev->dev, "Failed to reset: %d\n", err);
#endif
	return err;
}
