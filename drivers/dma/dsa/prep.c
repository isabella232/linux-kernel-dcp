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

inline void __dsa_prep_desc_common(struct dsa_dma_descriptor *hw, char opcode,
			u64 dest, u64 src, size_t len, unsigned long flags)
{
	hw->flags = flags;

	hw->opcode = opcode;
	hw->src_addr = src;
	hw->dst_addr = dest;
	hw->xfer_size = len;
}

void __dsa_prep_batch_memcpy(struct dsa_work_queue *wq, u64 dst, u64 src,
			struct dsa_dma_descriptor *hw, u64 compl_addr,
			size_t len, unsigned long flags)
{
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	hw->compl_addr = compl_addr;

	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
			dma_addr_t dma_src, struct dsa_dma_descriptor *hw,
			dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 dst = dma_dest;
	u64 src = dma_src;
	u64 comp_addr = compl_addr;

	__dsa_prep_batch_memcpy(wq, dst, src, hw, comp_addr, len, flags);
}

void __dsa_prep_batch_memset(struct dsa_work_queue *wq, u64 dst,
			unsigned long val, struct dsa_dma_descriptor *hw,
			u64 compl_addr, size_t len, unsigned long flags)
{
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	hw->compl_addr = compl_addr;

	__dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, val, len,desc_flags);
}

void dsa_dma_prep_batch_memset(struct dma_chan *c, dma_addr_t dma_dest,
			int value, struct dsa_dma_descriptor *hw,
			dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 dst = dma_dest;
	u64 val = value;
	u64 comp_addr = compl_addr;

	__dsa_prep_batch_memset(wq, dst, val, hw, comp_addr, len, flags);
}

void __dsa_prep_batch_compare(struct dsa_work_queue *wq, u64 src1, u64 src2,
			struct dsa_dma_descriptor *hw, u64 compl_addr,
			size_t len, unsigned long flags)
{
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	hw->compl_addr = compl_addr;

	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, len,
							desc_flags);
}

void dsa_dma_prep_batch_compare(struct dma_chan *c, dma_addr_t dma_src1,
			dma_addr_t dma_src2, struct dsa_dma_descriptor *hw,
			dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src1 = dma_src1;
	u64 src2 = dma_src2;
	u64 comp_addr = compl_addr;

	__dsa_prep_batch_memcpy(wq, src1, src2, hw, comp_addr, len, flags);
}

void __dsa_prep_batch_compval(struct dsa_work_queue *wq, u64 val, u64 src,
			struct dsa_dma_descriptor *hw, u64 compl_addr,
			size_t len, unsigned long flags)
{
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	hw->compl_addr = compl_addr;

	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_compval(struct dma_chan *c, unsigned long value,
			dma_addr_t dma_src, struct dsa_dma_descriptor *hw,
			dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src = dma_src;
	u64 comp_addr = compl_addr;

	__dsa_prep_batch_compval(wq, value, src, hw, comp_addr, len, flags);
}

void __dsa_prep_batch_dualcast(struct dsa_work_queue *wq, u64 dst1, u64 dst2,
			u64 src, struct dsa_dma_descriptor *hw, u64 compl_addr,
			size_t len, unsigned long flags)
{
	unsigned long desc_flags = 0;

	desc_flags |= DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR;
	if (wq->dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	hw->compl_addr = compl_addr;
	hw->op.dcast.dest2 = dst2;

	__dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, dst1, src, len,
							desc_flags);
}

void dsa_dma_prep_batch_dualcast(struct dma_chan *c, dma_addr_t dest1,
		dma_addr_t dest2, dma_addr_t dma_src, struct dsa_dma_descriptor
		*hw, dma_addr_t compl_addr, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src = dma_src;
	u64 dst1 = dest1;
	u64 dst2 = dest2;
	u64 comp_addr = compl_addr;

	__dsa_prep_batch_dualcast(wq, dst1, dst2, src, hw, comp_addr, len,
							flags);
}

struct dma_async_tx_descriptor *
__dsa_prep_batch(struct dsa_work_queue *wq, u64 batch_addr,
			   int num_descs, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	int idx;
	unsigned long desc_flags;

	if (num_descs == 0 || num_descs > dsa->max_batch_size) {
		printk("invalid batch size %d\n", num_descs);
		return NULL;
	}

	if (test_bit(DSA_WQ_DISABLED, &wq->state))
		return NULL;

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (dsa_ring_space(dring)) {
		idx = dring->head;
		dring->head++;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	//printk("preparing batch using %d descs ring %d h:t %d:%d\n", num_descs, dring->idx, idx, dring->tail);

	desc = dsa_get_ring_ent(dring, idx);

	desc->len = num_descs;
	desc->wq = wq;

	hw = desc->desc;

	/* Set the PASID and completion addr kva for SWQ */
	if (wq->dedicated == 0) {
		hw->u_s = 1;
		hw->pasid = wq->dsa->system_pasid;
	}
	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	__dsa_prep_desc_common(hw, DSA_OPCODE_BATCH, 0, batch_addr, num_descs,
						desc_flags);

	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
	//printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_batch(struct dma_chan *c, dma_addr_t dma_batch,
			   int num_descs, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 batch_addr = dma_batch;

	return __dsa_prep_batch(wq, batch_addr, num_descs, flags);
}


struct dma_async_tx_descriptor *
__dsa_prep_memcpy(struct dsa_work_queue *wq, u64 dst,
			   u64 src, size_t len, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	size_t total_len = len;
	int num_descs, idx, i;
	unsigned long desc_flags;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || len == 0)
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (num_descs <= dsa_ring_space(dring)) {
               	idx = dring->head;
		dring->head += num_descs;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	printk("preparing memcpy using %d descs ring %d h:t %d:%d\n",
				num_descs, dring->idx, idx, dring->tail);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t copy = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		/* Set the PASID and U/S for SWQ */
		if (wq->dedicated == 0) {
			hw->u_s = 1;
			hw->pasid = wq->dsa->system_pasid;
		}

		__dsa_prep_desc_common(hw, DSA_OPCODE_MEMMOVE, dst, src, copy,
							desc_flags);
		len -= copy;
		dst += copy;
		src += copy;
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
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
	u64 dst = dma_dest;
	u64 src = dma_src;

	return __dsa_prep_memcpy(wq, dst, src, len, flags);
}

struct dma_async_tx_descriptor *
__dsa_prep_memset(struct dsa_work_queue *wq, u64 dst,
			   u64 value, size_t len, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	size_t total_len = len;
	int num_descs, idx, i;
	unsigned long desc_flags;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || len == 0)
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (num_descs <= dsa_ring_space(dring)) {
		idx = dring->head;
		dring->head += num_descs;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	printk("preparing memset using %d descs ring %d h:t %d:%d\n",
			num_descs, dring->idx, idx, dring->tail);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t fill = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		/* Set the PASID and U/S for SWQ */
		if (wq->dedicated == 0) {
			hw->u_s = 1;
			hw->pasid = wq->dsa->system_pasid;
		}

		/* src_addr is the location of value for memfill descriptor */
		__dsa_prep_desc_common(hw, DSA_OPCODE_MEMFILL, dst, value, fill,
							desc_flags);

		len -= fill;
		dst += fill;
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_memset(struct dma_chan *c, dma_addr_t dma_dest,
			   int value, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 dst = dma_dest;
	u64 val = value;

	return __dsa_prep_memset(wq, dst, val, len, flags);
}


struct dma_async_tx_descriptor *
__dsa_prep_compare(struct dsa_work_queue *wq, u64 src1,
			   u64 src2, size_t len, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	size_t total_len = len;
	int num_descs, idx, i;
	unsigned long desc_flags;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || len == 0)
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (num_descs <= dsa_ring_space(dring)) {
		idx = dring->head;
		dring->head += num_descs;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	printk("preparing compare using %d descs ring %d h:t %d:%d\n",
			num_descs, dring->idx, idx, dring->tail);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t comp = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		/* Set the PASID and U/S for SWQ */
		if (wq->dedicated == 0) {
			hw->u_s = 1;
			hw->pasid = wq->dsa->system_pasid;
		}

		/* src_addr is the location of value for memfill descriptor */
		__dsa_prep_desc_common(hw, DSA_OPCODE_COMPARE, src1, src2, comp,
							desc_flags);
		len -= comp;
		src1 += comp;
		src2 += comp;
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_compare(struct dma_chan *c, dma_addr_t source1,
			   dma_addr_t source2, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src1 = source1;
	u64 src2 = source2;

	return __dsa_prep_compare(wq, src1, src2, len, flags);
}


struct dma_async_tx_descriptor *
__dsa_prep_compval(struct dsa_work_queue *wq, u64 val,
			   u64 src, size_t len, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	size_t total_len = len;
	int num_descs, idx, i;
	unsigned long desc_flags;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || len == 0)
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (num_descs <= dsa_ring_space(dring)) {
		idx = dring->head;
		dring->head += num_descs;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	printk("preparing compare using %d descs ring %d h:t %d:%d\n",
			num_descs, dring->idx, idx, dring->tail);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t comp = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		/* Set the PASID and U/S for SWQ */
		if (wq->dedicated == 0) {
			hw->u_s = 1;
			hw->pasid = wq->dsa->system_pasid;
		}

		/* src_addr is the location of value for memfill descriptor */
		__dsa_prep_desc_common(hw, DSA_OPCODE_COMPVAL, val, src, comp,
							desc_flags);
		len -= comp;
		src += comp;
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_compval(struct dma_chan *c, unsigned long val,
			   dma_addr_t source, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src = source;

	return __dsa_prep_compval(wq, val, src, len, flags);
}

struct dma_async_tx_descriptor *
__dsa_prep_dualcast(struct dsa_work_queue *wq, u64 dst1, u64 dst2,
			   u64 src, size_t len, unsigned long flags)
{
	struct dsadma_device *dsa = wq->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_dma_descriptor *hw;
	struct dsa_ring_ent *desc;
	size_t total_len = len;
	int num_descs, idx, i;
	unsigned long desc_flags;

	if (test_bit(DSA_WQ_DISABLED, &wq->state) || len == 0)
		return NULL;

	num_descs = dsa_xferlen_to_descs(wq, len);

	dring = dsa_get_completion_ring(dsa, wq->idx);

	spin_lock_bh(&dring->cleanup_lock);
	if (num_descs <= dsa_ring_space(dring)) {
		idx = dring->head;
		dring->head += num_descs;
	} else {
		goto no_space_unlock;
	}
	spin_unlock_bh(&dring->cleanup_lock);

	printk("preparing compare using %d descs ring %d h:t %d:%d\n",
			num_descs, dring->idx, idx, dring->tail);

	desc_flags = DSA_OP_FLAG_CRAV | DSA_OP_FLAG_RCR | DSA_OP_FLAG_RCI;
	if (dsa->gencap & DSA_CAP_BLOCK_ON_FAULT)
		desc_flags |= DSA_OP_FLAG_BOF;

	i = 0;
	do {
		size_t copy = min_t(size_t, len, 1 << dsa->max_xfer_bits);

		desc = dsa_get_ring_ent(dring, idx + i);

		desc->len = total_len;
		desc->wq = wq;

		hw = desc->desc;

		/* Set the PASID and U/S for SWQ */
		if (wq->dedicated == 0) {
			hw->u_s = 1;
			hw->pasid = wq->dsa->system_pasid;
		}

		__dsa_prep_desc_common(hw, DSA_OPCODE_DUALCAST, dst1, src, copy,
							desc_flags);
		hw->op.dcast.dest2 = dst2;
		len -= copy;
		dst1 += copy;
		dst2 += copy;
		src += copy;
	} while (++i < num_descs);

	printk("prepared descs h:t %d:%d\n", dring->head, dring->tail);
	desc->txd.flags = flags;
	dma_async_tx_descriptor_init(&desc->txd, &wq->dma_chan);
	return &desc->txd;

no_space_unlock:
	spin_unlock_bh(&dring->cleanup_lock);
	return NULL;
}

struct dma_async_tx_descriptor *
dsa_dma_prep_dualcast(struct dma_chan *c, dma_addr_t dest1, dma_addr_t dest2,
			   dma_addr_t source, size_t len, unsigned long flags)
{
	struct dsa_work_queue *wq = to_dsa_wq(c);
	u64 src = source;
	u64 dst1 = dest1;
	u64 dst2 = dest2;

	return __dsa_prep_dualcast(wq, dst1, dst2, src, len, flags);
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

