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
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/gfp.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/prefetch.h>
#include "../dmaengine.h"
#include "registers.h"
#include "hw.h"
#include "dma.h"

void dsa_dma_prep_batch_memcpy(struct dma_chan *c, dma_addr_t dest,
			dma_addr_t src, struct dsa_dma_descriptor *hw,
			dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;

	printk("preparing descr for batch memcpy %p %llx %ld\n", hw, compl_addr, len);

	//hw->u_s = 1;
	hw->flags = 0;
	hw->flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		hw->flags |= DSA_OP_FLAG_BOF;

	hw->opcode = DSA_OPCODE_MEMMOVE;
	hw->src_addr = src;
	hw->dst_addr = dest;
	hw->xfer_size = len;
	hw->compl_addr = compl_addr;
}

/* Currently we dont use Completion Queue */
struct dma_async_tx_descriptor *
dsa_dma_prep_batch(struct dma_chan *c, dma_addr_t dma_batch,
			   int num_descs, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	int idx;

	if (num_descs > dsa->max_batch_size) {
		printk("batch size %d > max batch size %d\n", num_descs, dsa->max_batch_size);
		return NULL;
	}

	if (test_bit(DSA_WQ_DISABLED, &wq->state))
		return NULL;

	dring = dsa_get_completion_ring(dsa, wq->idx);

        if (likely(num_descs)) {
		spin_lock_bh(&dring->cleanup_lock);
		if (dsa_ring_space(dring)) {
                	idx = dring->head;
			dring->head++;
		} else {
			goto no_space_unlock;
		}
		spin_unlock_bh(&dring->cleanup_lock);
        } else
                return NULL;

	printk("preparing batch using %d descs ring %d h:t %d:%d\n", num_descs, dring->idx, idx, dring->tail);

	desc = dsa_get_ring_ent(dring, idx);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);

	desc->len = num_descs;
	desc->wq = wq;

	hw = desc->desc;

	hw->u_s = 1;
	hw->flags = 0;
	hw->flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;

	hw->opcode = DSA_OPCODE_BATCH;

	hw->src_addr = dma_batch;
	hw->xfer_size = num_descs;

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
			   dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	dma_addr_t dst = dma_dest;
	dma_addr_t src = dma_src;
	size_t total_len = len;
	int num_descs, idx, i;

	if (test_bit(DSA_WQ_DISABLED, &wq->state))
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

        if (likely(num_descs)) {
		spin_lock_bh(&dring->cleanup_lock);
		if (num_descs <= dsa_ring_space(dring)) {
                	idx = dring->head;
			dring->head += num_descs;
		} else {
			goto no_space_unlock;
		}
		spin_unlock_bh(&dring->cleanup_lock);
        } else
                return NULL;

	printk("preparing memcpy using %d descs ring %d h:t %d:%d\n", num_descs, dring->idx, idx, dring->tail);
	i = 0;
	do {
		size_t copy = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);
		desc->txd.flags = flags;
		dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		hw->u_s = 1;
		hw->flags = 0;
		hw->flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
		if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
			hw->flags |= DSA_OP_FLAG_BOF;

		hw->opcode = DSA_OPCODE_MEMMOVE;

		hw->src_addr = src;
		hw->dst_addr = dst;
		hw->xfer_size = copy;

		len -= copy;
		dst += copy;
		src += copy;
		//dump_desc_dbg(wq, desc);
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_memset(struct dma_chan *c, dma_addr_t dma_dest,
			   int value, size_t len, unsigned long flags)
{
	/* FIXME: */
	return NULL;
}


#if 0
static void
dump_desc_dbg(struct dsa_work_queue *wq, struct dsa_ring_ent *desc,
		 struct dsa_ring_ent *ext)
{
	struct device *dev = to_dev(dsa_chan);
	struct dsa_pq_descriptor *pq = desc->pq;
	struct dsa_pq_ext_descriptor *pq_ex = ext ? ext->pq_ex : NULL;
	struct dsa_raw_descriptor *descs[] = { (void *) pq, (void *) pq_ex };
	int src_cnt = src_cnt_to_sw(pq->ctl_f.src_cnt);
	int i;

	dev_dbg(dev, "desc[%d]: (%#llx->%#llx) flags: %#x"
		" sz: %#10.8x ctl: %#x (op: %#x int: %d compl: %d pq: '%s%s'"
		" src_cnt: %d)\n",
		desc_id(desc), (unsigned long long) desc->txd.phys,
		(unsigned long long) (pq_ex ? pq_ex->next : pq->next),
		desc->txd.flags, pq->size, pq->ctl, pq->ctl_f.op,
		pq->ctl_f.int_en, pq->ctl_f.compl_write,
		pq->ctl_f.p_disable ? "" : "p", pq->ctl_f.q_disable ? "" : "q",
		pq->ctl_f.src_cnt);
	for (i = 0; i < src_cnt; i++)
		dev_dbg(dev, "\tsrc[%d]: %#llx coef: %#x\n", i,
			(unsigned long long) pq_get_src(descs, i), pq->coef[i]);
	dev_dbg(dev, "\tP: %#llx\n", pq->p_addr);
	dev_dbg(dev, "\tQ: %#llx\n", pq->q_addr);
	dev_dbg(dev, "\tNEXT: %#llx\n", pq->next);
}
#endif

struct dma_async_tx_descriptor *
dsa_prep_interrupt_lock(struct dma_chan *c, unsigned long flags)
{
#if 0
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_ring_ent *desc;
	struct dsa_dma_descriptor *hw;

	if (test_bit(DSA_CHAN_DOWN, &dsa_chan->state))
		return NULL;

	if (dsa_check_space_lock(dsa_chan, 1) == 0)
		desc = dsa_get_ring_ent(dsa_chan, dsa_chan->head);
	else
		return NULL;

	hw = desc->hw;
	hw->ctl = 0;
	hw->ctl_f.null = 1;
	hw->ctl_f.int_en = 1;
	hw->ctl_f.fence = !!(flags & DMA_PREP_FENCE);
	hw->ctl_f.compl_write = 1;
	hw->size = NULL_DESC_BUFFER_SIZE;
	hw->src_addr = 0;
	hw->dst_addr = 0;

	desc->txd.flags = flags;
	desc->len = 1;

	dump_desc_dbg(dsa_chan, desc);

	/* we leave the channel locked to ensure in order submission */
	return &desc->txd;
#endif
	return NULL;
}

