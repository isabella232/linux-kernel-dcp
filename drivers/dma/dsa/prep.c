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

/*
1. alloc chan resources creates descriptor and completion buffers
2. Clients can call chan resource another time to allocate batch desc buffers
3. API for prepare descriptor with a flag to submit it right away
4. API for submitting multiple descriptors with a flag for using batch desc
5. Submission APIs also specify whether to use interrupts
6. the submission cal be sync or async. async submissions provide a callback
   function. sync submissions use a wait event method to block and wait
7. DMAEngine APIs will always use Batch descriptor when doing issue_pending()

*/
inline void __dsa_prep_desc_common(struct dsa_dma_descriptor *hw, char opcode,
			u64 dest, u64 src, size_t len, unsigned long flags)
{
	hw->flags = flags;

	hw->opcode = opcode;
	hw->src_addr = src;
	hw->dst_addr = dest;
	hw->xfer_size = len;
}

static inline int dsa_reserve_space (struct dsa_completion_ring *dring,
			size_t len, int *idx)
{
	int num_descs = dsa_xferlen_to_descs(dring->dsa, len);

	spin_lock_bh(&dring->space_lock);
	if (num_descs <= dsa_ring_space(dring)) {
		*idx = dring->head;
		dring->head = add_dring_idx(dring, dring->head, num_descs);
	} else {
		num_descs = 0;
	}
	spin_unlock_bh(&dring->space_lock);

	return num_descs;
}

void inline __dsa_prep_batch_memcpy(struct dsa_batch *batch, int desc_idx,
		u64 dst, u64 src, size_t len, unsigned long desc_flags)
{
	struct dsa_dma_descriptor *hw;

	if (desc_idx >= batch->num_descs)
		return;

	hw = &batch->descs[desc_idx];

	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_memcpy(struct dma_chan *c, int idx, dma_addr_t dma_dest,
			dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	u64 dst = dma_dest;
	u64 src = dma_src;
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_batch_memcpy(&dring->batch, idx, dst, src, len, desc_flags);
}

void __dsa_prep_batch_memset(struct dsa_batch *batch, int desc_idx, u64 dst,
			u64 val, size_t len, unsigned long desc_flags)
{
	struct dsa_dma_descriptor *hw;

	if (desc_idx >= batch->num_descs)
		return;

	hw = &batch->descs[desc_idx];

	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, val, len,
						desc_flags);
}

void dsa_dma_prep_batch_memset(struct dma_chan *c, int idx, dma_addr_t dma_dest,
			int value, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	u64 dst = dma_dest;
	u64 val = (u64)value << 32 | value;
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_batch_memset(&dring->batch, idx, dst, val, len, desc_flags);
}

void __dsa_prep_batch_compare(struct dsa_batch *batch, int desc_idx, u64 src1,
			u64 src2, size_t len, unsigned long desc_flags)
{
	struct dsa_dma_descriptor *hw;

	if (desc_idx >= batch->num_descs)
		return;

	hw = &batch->descs[desc_idx];

	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, len,
							desc_flags);
}

void dsa_dma_prep_batch_compare(struct dma_chan *c, int idx,
			dma_addr_t dma_src1, dma_addr_t dma_src2,
			size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	u64 src1 = dma_src1;
	u64 src2 = dma_src2;
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_batch_compare(&dring->batch, idx, src1, src2, len,
					desc_flags);
}

void __dsa_prep_batch_compval(struct dsa_batch *batch, int desc_idx,
			u64 val, u64 src,
			size_t len, unsigned long desc_flags)
{
	struct dsa_dma_descriptor *hw;

	if (desc_idx >= batch->num_descs)
		return;

	hw = &batch->descs[desc_idx];

	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_compval(struct dma_chan *c, int idx,
			unsigned long value, dma_addr_t dma_src,
			size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	u64 src = dma_src;
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_batch_compval(&dring->batch, idx, value, src, len,
						desc_flags);
}

void __dsa_prep_batch_dualcast(struct dsa_batch *batch, int desc_idx, u64 dst1,
			u64 dst2, u64 src, size_t len, unsigned long desc_flags)
{
	struct dsa_dma_descriptor *hw;

	if (desc_idx >= batch->num_descs)
		return;

	hw = &batch->descs[desc_idx];

	hw->dcast.dest2 = dst2;

	__dsa_prep_desc_common(hw, DSA_OPCODE_DUALCAST, dst1, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_dualcast(struct dma_chan *c, int idx, dma_addr_t dest1,
		dma_addr_t dest2, dma_addr_t dma_src,
		size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	u64 src = dma_src;
	u64 dst1 = dest1;
	u64 dst2 = dest2;
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_batch_dualcast(&dring->batch, idx, dst1, dst2, src, len,
							desc_flags);
}

struct dsa_ring_ent *__dsa_prep_batch(struct dsa_completion_ring *dring,
	u64 batch_addr, int num_descs, unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
		(num_descs > dsa->max_batch_size))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}
	printk("preparing batch using h:t %d:%d\n", dring->head, dring->tail);

	hw = &desc->hw;

	__dsa_prep_desc_common(hw, DSA_OPCODE_BATCH, 0, batch_addr, num_descs,
						desc_flags);

	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}
	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_batch(struct dma_chan *c, dma_addr_t dma_batch,
			   int num_descs, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	unsigned long desc_flags;
	int idx;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
		(num_descs > wq->dsa->max_batch_size) ||
		dsa_reserve_space(dring, num_descs, &idx) == 0)
		return NULL;

	desc = dsa_get_ring_ent(dring, idx);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	//if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		//desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_BATCH, 0, (u64)dma_batch,
					num_descs, desc_flags);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}

/* This function can be called out of order */
void dsa_free_desc(struct dsa_completion_ring *dring,
				struct dsa_ring_ent *desc)
{
	clear_bit(desc_in_use, &desc->flags);

	while(!test_bit(desc_in_use, &dsa_get_ring_ent(dring,
			dring->tail)->flags)) {
		dring->tail = inc_dring_idx(dring, dring->tail);
		if (dring->tail == dring->head)
			break;
	}
}

struct dsa_ring_ent *__dsa_prep_memcpy(struct dsa_completion_ring *dring,
	u64 dst, u64 src, size_t len, unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || (dsa->max_xfer_size < len))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}

	printk("preparing memcpy h:t %d:%d\n", dring->head, dring->tail);

	hw = &desc->hw;

	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, len,
							desc_flags);

	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}

	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
			   dma_addr_t dma_src, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	unsigned long desc_flags;
	int idx, i, num_descs;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
			(num_descs = dsa_reserve_space(dring, len, &idx)) == 0)
		return NULL;

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t copy = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_MEMMOVE,
				(u64)dma_dest, (u64)dma_src, copy, desc_flags);

		len -= copy;
		dma_dest += copy;
		dma_src += copy;
	} while (++i < num_descs);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}

struct dsa_ring_ent *__dsa_prep_memset(struct dsa_completion_ring *dring,
		u64 dst, u64 value, size_t len, unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || (dsa->max_xfer_size < len))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}

	printk("preparing memset using h:t %d:%d\n", dring->head, dring->tail);

	hw = &desc->hw;

	/* src_addr is the location of value for memfill descriptor */
	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, value, len,
						desc_flags);

	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}

	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_memset(struct dma_chan *c, dma_addr_t dma_dest,
			   int value, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	u64 val = (u64)value << 32 | value;
	unsigned long desc_flags;
	int num_descs, idx, i;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
			(num_descs = dsa_reserve_space(dring, len, &idx)) == 0)
		return NULL;

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t fill = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		/* src_addr is the location of value for memfill descriptor */
		__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_MEMFILL,
				(u64)dma_dest, val, fill, desc_flags);
		len -= fill;
		dma_dest += fill;
	} while (++i < num_descs);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}


struct dsa_ring_ent *__dsa_prep_compare(struct dsa_completion_ring *dring,
		u64 src1, u64 src2, size_t len, unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || (dsa->max_xfer_size < len))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}

	hw = &desc->hw;
	printk("preparing compare using h:t %d:%d\n", dring->head, dring->tail);

	/* src_addr is the location of value for memfill descriptor */
	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, len,
							desc_flags);
	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}

	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_compare(struct dma_chan *c, dma_addr_t source1,
			   dma_addr_t source2, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	unsigned long desc_flags;
	int num_descs, idx, i;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
			(num_descs = dsa_reserve_space(dring, len, &idx)) == 0)
		return NULL;

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t comp = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_COMPARE,
			(u64)source1, (u64)source2, comp, desc_flags);

		len -= comp;
		source1 += comp;
		source2 += comp;
	} while (++i < num_descs);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}


struct dsa_ring_ent *__dsa_prep_compval(struct dsa_completion_ring *dring,
	u64 val, u64 src, size_t len, unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || (dsa->max_xfer_size < len))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}
	printk("preparing compval using h:t %d:%d\n", dring->head, dring->tail);

	hw = &desc->hw;
	/* src_addr is the location of value for memfill descriptor */
	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, len,
							desc_flags);
	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}

	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_compval(struct dma_chan *c, unsigned long val,
			   dma_addr_t source, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	unsigned long desc_flags;
	int num_descs, idx, i;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
			(num_descs = dsa_reserve_space(dring, len, &idx)) == 0)
		return NULL;

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t comp = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		/* src_addr is the location of value for memfill descriptor */
		__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_COMPVAL, val,
					(u64)source, comp, desc_flags);

		len -= comp;
		source += comp;
	} while (++i < num_descs);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}

struct dsa_ring_ent *__dsa_prep_dualcast(struct dsa_completion_ring *dring,
			u64 dst1, u64 dst2, u64 src, size_t len,	
			unsigned long desc_flags)
{
	struct dsa_work_queue *wq = dring->wq;
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || (dsa->max_xfer_size < len))
		return NULL;

	desc = dsa_alloc_desc(dring);

	if (!desc)
		return NULL;

	if ((desc_flags & DSA_OP_FLAG_RCI) && !dsa_trylock_desc(desc)) {
		printk("unable to lock\n");
		dsa_free_desc(dring, desc);
		return NULL;
	}
	printk("preparing dcast using h:t %d:%d\n", dring->head, dring->tail);

	hw = &desc->hw;

	__dsa_prep_desc_common(hw, DSA_OPCODE_DUALCAST, dst1, src, len,
							desc_flags);
	hw->dcast.dest2 = dst2;

	if (wq->dedicated) {
		/* use MOVDIR64B for DWQ */
		movdir64b(hw, dring->wq_reg);
	} else {
		/* use ENQCMDS for SWQ */
		dsa_enqcmds(hw, dring->wq_reg);
	}

	return desc;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_dualcast(struct dma_chan *c, dma_addr_t dest1, dma_addr_t dest2,
			   dma_addr_t source, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring = wq->dring;
	struct dsa_ring_ent *desc;
	unsigned long desc_flags;
	int num_descs, idx, i;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) ||
			(num_descs = dsa_reserve_space(dring, len, &idx)) == 0)
		return NULL;

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (flags & DMA_PREP_INTERRUPT)
		desc_flags |= DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t copy = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		__dsa_prep_desc_common(&desc->hw, DSA_OPCODE_DUALCAST,
				(u64)dest1, (u64)source, copy, desc_flags);
		desc->hw.dcast.dest2 = (u64)dest2;

		len -= copy;
		dest1 += copy;
		dest2 += copy;
		source += copy;
	} while (++i < num_descs);

	desc->txd->flags = flags;
	dma_async_tx_descriptor_init(desc->txd, &wq->dma_chan);

	return desc->txd;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_drain (struct dsa_work_queue *wq, unsigned long flags)
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

