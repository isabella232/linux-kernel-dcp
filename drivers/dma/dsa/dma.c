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
	struct dsa_completion_ring *dsa_ring = data;

	printk("received wq completion interrupt\n");

	tasklet_schedule(&dsa_ring->cleanup_task);

	return IRQ_HANDLED;
}

irqreturn_t dsa_misc_interrupt(int irq, void *data)
{
	struct dsa_completion_ring *dsa_ring = data;
	struct dsadma_device *dsa = dsa_ring->dsa;
	u32 int_cause;

	printk("received misc completion interrupt\n");

	int_cause = readl(dsa->reg_base + DSA_INTCAUSE_OFFSET);

	printk("INTCAUSE %x\n", int_cause);

	if (int_cause & DSA_INTCAUSE_HWERR) {
		u16 hwerr;
		hwerr = readw(dsa->reg_base + DSA_HWERR_OFFSET);
		printk("HWERR %x\n", hwerr);
		writew(hwerr, dsa->reg_base + DSA_HWERR_OFFSET);
	}
	if (int_cause & DSA_INTCAUSE_SWERR) {
		u64 swerr;
		swerr = readq(dsa->reg_base + DSA_SWERR_OFFSET);
		printk("SWERR %llx\n", swerr);
		writeq(swerr, dsa->reg_base + DSA_SWERR_OFFSET);
	}
	tasklet_schedule(&dsa_ring->cleanup_task);

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

static void __iomem *dsa_get_wq_reg(struct dsadma_device *dsa, int wq_idx,
				int msix_idx, bool priv)
{
	u32 wq_offset;

	if (!priv) {
		wq_offset = wq_idx;
	} else {
		wq_offset = msix_idx * dsa->max_wqs + wq_idx;
	}
	wq_offset = wq_offset << PAGE_SHIFT;

	return (dsa->wq_reg_base + wq_offset);
}

static void __dsa_issue_pending(struct dsa_work_queue *wq)
{
	struct dsa_completion_ring *dring;
	int i, pending, retry_count;
	struct dsa_ring_ent *desc;
	void __iomem * wq_reg;

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);

	pending = dsa_ring_pending(dring);
	dring->dmacount += pending;

	printk("Issuing %d descs using wq %d ring %d\n", pending, wq->idx, dring->idx);
	for (i = 0; i < pending; i++) {
		desc = dsa_get_ring_ent(dring, dring->tail);

		wq_reg = dsa_get_wq_reg(wq->dsa, wq->idx, dring->idx, 1);

		printk("desc op %x wq_reg %p ded %d compl %llx\n", desc->desc->opcode, wq_reg, wq->dedicated, desc->desc->compl_addr);

		if (wq->dedicated) {
			/* use MOVDIR64B for DWQ */
			movdir64b(desc->desc, wq_reg);
		} else {
			/* use ENQCMDS for SWQ */
			retry_count = 0;

			while (retry_count < 5) {
				if (!enqcmds(desc->desc, wq_reg))
					break;
				else
					printk("received retry\n");
				retry_count++;
			}
			if (retry_count >= 5) {
				/* FIXME: handle this case */
				printk("retry returned %p %p\n", desc->desc,
							dring->wq_reg);
			}
		}
		dring->issued++;
	}
	dev_dbg(to_dev(wq),
		"%s: head: %#x tail: %#x issued: %#x count: %#x\n",
		__func__, dring->head, dring->tail,
		dring->issued, dring->dmacount);
}

void dsa_issue_pending(struct dma_chan *c)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring;

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);

	if (dsa_ring_pending(dring)) {
		spin_lock_bh(&wq->lock);
		__dsa_issue_pending(wq);
		spin_unlock_bh(&wq->lock);
	}
}

/**
 * dsa_update_pending - log pending descriptors
 * @dsa: dsa+ channel
 *
 * Check if the number of unsubmitted descriptors has exceeded the
 * watermark.  Called with prep_lock held
 */
static void dsa_update_pending(struct dsa_work_queue *wq)
{
#if 0
	if (dsa_ring_pending(dsa_chan) > dsa_pending_level)
		__dsa_issue_pending(dsa_chan);
#endif
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

static int dsa_reset_sync(struct dsa_work_queue *wq, unsigned long tmo)
{
	int err = 0;
#if 0
	unsigned long end = jiffies + tmo;
	dsa_reset(dsa_chan);
	while (dsa_reset_pending(dsa_chan)) {
		if (end && time_after(jiffies, end)) {
			err = -ETIMEDOUT;
			break;
		}
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

struct dsa_completion_ring * dsa_get_completion_ring(struct dsadma_device *dsa,
			int wq_idx)
{
	/* FIXME: return the completion ring based on wq idx for now.
	 * dsa->comp_rings[0]
	 * is not used since it would correspond to MSIX entry 0 which is not
	 * used for WQ completion interrupts. */

	return &dsa->comp_rings[wq_idx + 1];
}

static void dsa_init_ring_ent(struct dsa_ring_ent *entry,
		struct dsa_completion_ring *ring, int desc_idx)
{
	entry->desc = ring->desc_ring_buf + desc_idx * sizeof(struct dsa_dma_descriptor);
	entry->completion = ring->completion_ring_buf + desc_idx * sizeof(struct dsa_completion_record);
	entry->desc->compl_addr = ring->ring_base + desc_idx * sizeof(struct dsa_completion_record);

	entry->txd.tx_submit = dsa_tx_submit_unlock;
	entry->txd.phys = __pa(entry->desc);
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

int dsa_alloc_completion_ring(struct dsa_completion_ring *dring, gfp_t flags)
{
	struct dsa_ring_ent *ring;
	int descs = dring->num_entries;
	int i, order;
	struct pci_dev *dev = dring->dsa->pdev;

	/* allocate the array to hold the software ring */
	ring = kcalloc(descs, sizeof(*ring), flags);
	if (!ring)
		return -ENOMEM;
	memset(ring, 0, descs * sizeof(*ring));

	dring->completion_ring_buf =
		pci_alloc_consistent(dev, dring->comp_ring_size, &dring->ring_base);

	printk("allocated completion ring %p %llx\n", dring->completion_ring_buf, dring->ring_base);

	if (!dring->completion_ring_buf) {
		kfree(ring);
		return -ENOMEM;
	}
	memset(dring->completion_ring_buf, 0, dring->comp_ring_size);

	order = get_order(dring->desc_ring_size);
	dring->desc_ring_buf = (void *)__get_free_pages(flags, order);

	if (!dring->desc_ring_buf) {
		kfree(ring);
		kfree(dring->completion_ring_buf);
		return -ENOMEM;
	}
	memset(dring->desc_ring_buf, 0, dring->desc_ring_size);

	dring->ring = ring;

	for (i = 0; i < descs; i++) {
		dsa_init_ring_ent(&ring[i], dring, i);
		set_desc_id(&ring[i], i);
	}
	return 0;
}

static bool reshape_ring(struct dsa_work_queue *wq, int order)
{
	/* reshape differs from normal ring allocation in that we want
	 * to allocate a new software ring while only
	 * extending/truncating the hardware ring
	 */
#if 0
	struct dma_chan *c = &wq->dma_chan;
	const u32 curr_size = dsa_ring_size(dsa_chan);
	const u16 active = dsa_ring_active(dsa_chan);
	const u32 new_size = 1 << order;
	struct dsa_ring_ent **ring;
	u32 i;

	if (order > dsa_get_max_alloc_order())
		return false;

	/* double check that we have at least 1 free descriptor */
	if (active == curr_size)
		return false;

	/* when shrinking, verify that we can hold the current active
	 * set in the new ring
	 */
	if (active >= new_size)
		return false;

	/* allocate the array to hold the software ring */
	ring = kcalloc(new_size, sizeof(*ring), GFP_NOWAIT);
	if (!ring)
		return false;

	/* allocate/trim descriptors as needed */
	if (new_size > curr_size) {
		/* copy current descriptors to the new ring */
		for (i = 0; i < curr_size; i++) {
			u16 curr_idx = (dsa_chan->tail+i) & (curr_size-1);
			u16 new_idx = (dsa_chan->tail+i) & (new_size-1);

			ring[new_idx] = dsa_chan->ring[curr_idx];
			set_desc_id(ring[new_idx], new_idx);
		}

		/* add new descriptors to the ring */
		for (i = curr_size; i < new_size; i++) {
			u16 new_idx = (dsa_chan->tail+i) & (new_size-1);

			ring[new_idx] = dsa_alloc_ring_ent(c, GFP_NOWAIT);
			if (!ring[new_idx]) {
				while (i--) {
					u16 new_idx = (dsa_chan->tail+i) &
						       (new_size-1);

					dsa_free_ring_ent(ring[new_idx], c);
				}
				kfree(ring);
				return false;
			}
			set_desc_id(ring[new_idx], new_idx);
		}

		/* hw link new descriptors */
		for (i = curr_size-1; i < new_size; i++) {
			u16 new_idx = (dsa_chan->tail+i) & (new_size-1);
			struct dsa_ring_ent *next =
				ring[(new_idx+1) & (new_size-1)];
			struct dsa_dma_descriptor *hw = ring[new_idx]->hw;

			hw->next = next->txd.phys;
		}
	} else {
		struct dsa_dma_descriptor *hw;
		struct dsa_ring_ent *next;

		/* copy current descriptors to the new ring, dropping the
		 * removed descriptors
		 */
		for (i = 0; i < new_size; i++) {
			u16 curr_idx = (dsa_chan->tail+i) & (curr_size-1);
			u16 new_idx = (dsa_chan->tail+i) & (new_size-1);

			ring[new_idx] = dsa_chan->ring[curr_idx];
			set_desc_id(ring[new_idx], new_idx);
		}

		/* free deleted descriptors */
		for (i = new_size; i < curr_size; i++) {
			struct dsa_ring_ent *ent;

			ent = dsa_get_ring_ent(dsa_chan, dsa_chan->tail+i);
			dsa_free_ring_ent(ent, c);
		}

		/* fix up hardware ring */
		hw = ring[(dsa_chan->tail+new_size-1) & (new_size-1)]->hw;
		next = ring[(dsa_chan->tail+new_size) & (new_size-1)];
		hw->next = next->txd.phys;
	}

	dev_dbg(to_dev(dsa_chan), "%s: allocated %d descriptors\n",
		__func__, new_size);

	kfree(dsa_chan->ring);
	dsa_chan->ring = ring;
	dsa_chan->alloc_order = order;
#endif
	return true;
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

static bool desc_has_ext(struct dsa_ring_ent *desc)
{
#if 0
	struct dsa_dma_descriptor *hw = desc->hw;
	if (hw->ctl_f.op == DSA_OP_XOR ||
	    hw->ctl_f.op == DSA_OP_XOR_VAL) {
		struct dsa_xor_descriptor *xor = desc->xor;

		if (src_cnt_to_sw(xor->ctl_f.src_cnt) > 5)
			return true;
	} else if (hw->ctl_f.op == DSA_OP_PQ ||
		   hw->ctl_f.op == DSA_OP_PQ_VAL) {
		struct dsa_pq_descriptor *pq = desc->pq;

		if (src_cnt_to_sw(pq->ctl_f.src_cnt) > 3)
			return true;
	}
#endif
	return false;
}

static void
desc_get_errstat(struct dsa_work_queue *wq, struct dsa_ring_ent *desc)
{
#if 0
	struct dsa_dma_descriptor *hw = desc->hw;
	switch (hw->ctl_f.op) {
	case DSA_OP_PQ_VAL:
	case DSA_OP_PQ_VAL_16S:
	{
		struct dsa_pq_descriptor *pq = desc->pq;

		/* check if there's error written */
		if (!pq->dwbes_f.wbes)
			return;

		/* need to set a chanerr var for checking to clear later */

		if (pq->dwbes_f.p_val_err)
			*desc->result |= SUM_CHECK_P_RESULT;

		if (pq->dwbes_f.q_val_err)
			*desc->result |= SUM_CHECK_Q_RESULT;

		return;
	}
	default:
		return;
	}
#endif
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
	struct dsa_completion_ring *dring = (struct dsa_completion_ring *)data;
	struct dsa_work_queue *wq;
	struct dsa_completion_record *comp;
	struct dma_async_tx_descriptor *tx;
	struct dsa_ring_ent *desc;
	int idx;
/*
	if (dsa_ring->wq) {
		if (!list_empty(&dsa_ring->wq->user_ctx_list)) {
			struct dsa_context *ctx;
			struct list_head *ptr, *n;
			list_for_each_safe(ptr, n, dsa_ring->wq->user_ctx_list) {
				ctx = list_entry(ptr, struct dsa_context, wq_list);
				wake_up_interruptible(&ctx->intr_queue);
				list_del(&ctx->wq_list);
			}
		} else {


		}
		return;
	}
*/
	printk("cleanup completion ring %d h:t %d:%d\n", dring->idx, dring->head, dring->tail);
	idx = dring->tail;
        do {
                desc = dsa_get_ring_ent(dring, idx);
                wq = desc->wq;

                comp = desc->completion;

		if (comp->status == DSA_COMP_SUCCESS) {
			printk("operation %d success\n", desc->desc->opcode);
			tx = &desc->txd;
			if (tx->cookie) {
				dma_cookie_complete(tx);
				dma_descriptor_unmap(tx);
				if (tx->callback) {
					tx->callback(tx->callback_param);
					tx->callback = NULL;
				}
			}
			comp->status = 0;
		} else if (comp->status) {
			printk("operation %d failure %d\n", desc->desc->opcode, comp->status);
		} else {
			break;
		}
		idx++;
                //dump_desc_dbg(wq, desc);
        } while (idx != dring->head);

	spin_lock_bh(&dring->cleanup_lock);
	dring->tail = idx;
	spin_unlock_bh(&dring->cleanup_lock);
	printk("cleaned up completion ring %d h:t %d:%d\n", dring->idx, dring->head, dring->tail);
}

void dsa_misc_cleanup(unsigned long data)
{
	struct dsa_completion_ring *dring = (struct dsa_completion_ring *)data;
	struct dsadma_device *dsa = dring->dsa;

	printk("In miscellaneous cleanup\n");
}

static void dsa_restart_wq(struct dsa_work_queue *wq)
{
	dsa_quiesce(wq, 0);
	dsa_cleanup(wq);

	__dsa_restart_wq(wq);
}

static void check_active(struct dsa_work_queue *wq)
{
#if 0
	if (dsa_ring_active(dsa_chan)) {
		mod_timer(&dsa_chan->timer, jiffies + COMPLETION_TIMEOUT);
		return;
	}

	if (test_and_clear_bit(DSA_CHAN_ACTIVE, &dsa_chan->state))
		mod_timer(&dsa_chan->timer, jiffies + IDLE_TIMEOUT);
	else if (dsa_chan->alloc_order > dsa_get_alloc_order()) {
		/* if the ring is idle, empty, and oversized try to step
		 * down the size
		 */
		reshape_ring(dsa_chan, dsa_chan->alloc_order - 1);

		/* keep shrinking until we get back to our minimum
		 * default size
		 */
		if (dsa_chan->alloc_order > dsa_get_alloc_order())
			mod_timer(&dsa_chan->timer, jiffies + IDLE_TIMEOUT);
	}
#endif
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
	struct dsa_work_queue *wq = to_dsa_wq(c);
	enum dma_status ret;

	ret = dma_cookie_status(c, cookie, txstate);
	if (ret == DMA_COMPLETE)
		return ret;

	return dma_cookie_status(c, cookie, txstate);
}

static int dsa_irq_reinit(struct dsadma_device *dsa)
{
	struct pci_dev *pdev = dsa->pdev;
	int irq = pdev->irq, i;

	for (i = 0; i < dsa->msixcnt; i++) {
		struct msix_entry *msix = &dsa->msix_entries[i];
		struct dsa_completion_ring *dring = &dsa->comp_rings[i];

		devm_free_irq(&pdev->dev, msix->vector, dring);
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
