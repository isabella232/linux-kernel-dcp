/*
 * Copyright(c) 2004 - 2009 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called COPYING.
 */
#ifndef DSADMA_H
#define DSADMA_H

#include <linux/dmaengine.h>
#include <linux/init.h>
#include <linux/dmapool.h>
#include <linux/cache.h>
#include <linux/pci_ids.h>
#include <linux/circ_buf.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include "svm.h"
#include "registers.h"
#include "hw.h"

#define DSA_DMA_VERSION  "4.00"

#define DSA_DMA_DCA_ANY_CPU		~0


#define DSA_WQ_UNALLOCATED  (-1)
#define IA32_PASID_MSR   0x00000d93

#define to_dsadma_device(dev) container_of(dev, struct dsadma_device, dma_dev)
#define to_dev(dsa_wq) (&(dsa_wq)->dsa->pdev->dev)
#define to_pdev(dsa_wq) ((dsa_wq)->dsa->pdev)

#define chan_num(ch) ((int)((ch)->reg_base - (ch)->dsa_dma->reg_base) / 0x80)

/* dsa hardware assumes at least two sources for raid operations */
#define src_cnt_to_sw(x) ((x) + 2)
#define src_cnt_to_hw(x) ((x) - 2)
#define ndest_to_sw(x) ((x) + 1)
#define ndest_to_hw(x) ((x) - 1)
#define src16_cnt_to_sw(x) ((x) + 9)
#define src16_cnt_to_hw(x) ((x) - 9)

/*
 * workaround for DSA ver.3.0 null descriptor issue
 * (channel returns error when size is 0)
 */
#define NULL_DESC_BUFFER_SIZE 1

struct dsa_completion_ring;

enum dsa_irq_mode {
	DSA_NOIRQ = 0,
	DSA_MSIX
};

enum desc_flags {
	desc_locked,
	desc_in_use,
};

struct dsa_grpcfg_reg {
	u64 wq_bits[4];
	u64 eng_bits;
	u32 vc;
	u32 rsvd0;
	u64 rsvd1[2];
};

struct dsa_work_queue {
	struct dma_chan dma_chan;
	struct timer_list timer;
	struct dsadma_device *dsa;
	bool wq_enabled;
	bool dedicated;
	bool bof_enabled;
	u8   priority;
	u8   idx;
	u32  pasid;
	bool privileged;
	u16  threshold;
	u16  wq_size;
	u64 issued;
	int grp_id;
	spinlock_t lock;
	struct kobject kobj;
	unsigned long state;
#define DSA_KOBJ_INIT_FAIL 3
#define DSA_WQ_DISABLED    0
#define DSA_WQ_ENABLED     1
#define DSA_WQ_RUN         5
	struct list_head user_ctx_list;
	int available;
	int allocated;

	/* for dedicated wq */
	struct dsa_completion_ring *dring;
};

struct dsa_work_queue_reg {
	union {
		struct {
			u32 wq_size:16;
			u32 rsvd5:16;
		}a_fields;
		u32     val;
	}a;

	union {
		struct {
			u32 threshold:16;
			u32 rsvd4:16;
		}b_fields;
		u32     val;
	}b;
	
	union {
		struct {
			u32 mode:1;
			u32 bof_en:1;
			u32 rsvd2:2;
			u32 priority:4;
			u32 pasid:20;
			u32 rsvd3:2;
			u32 paside:1;
			u32 u_s:1;
		}c_fields;
		u32     val;
	}c;

	union {
		struct {
			u32 wq_enable:1;
			u32 wq_enabled:1;
			u32 rsvd0:6;
			u32 wq_err:8;
			u32 rsvd1:16;
		}d_fields;
		u32     val;
	}d;
};

struct dsa_batch {
	struct dsa_completion_ring *dring;
	int num_descs;
	struct dsa_dma_descriptor *descs;
	struct dsa_completion_record *comp;
	dma_addr_t   dma_batch;
	dma_addr_t   dma_compl;
};

typedef void (*dsa_desc_callback)(void *param);

struct dsa_callback_descriptor {
	void *callback_param;
	dsa_desc_callback callback;
	struct completion cmpl;
};

struct dsa_irq_event {
	wait_queue_head_t waitq;
	struct dsa_irq_entry *irq_entry;
	int use_waitq;
	struct dsa_completion_ring *dring;
	u32 irq_vector;
	struct list_head irq_wait_chain;
	void (*isr_cb)(struct dsa_completion_ring *dring);
};

struct dsa_completion_ring {
	struct dsadma_device *dsa;
	struct dsa_work_queue *wq;
	struct dsa_ring_ent *ring;
	struct dsa_batch    batch;
	spinlock_t 	space_lock;
	u16 num_entries;
	u16 head;
	u16 tail;
	u16 dmacount;
	u16 issued;
	u64 completed; 		/* cumulative number */
	u32 comp_ring_size;
	void    *completion_ring_buf;
	void    *callback_ring_buf;
	dma_addr_t  comp_base;
	void __iomem *wq_reg;
	struct dsa_irq_event ev;
};

struct dsa_context {
	int user_handle;
	int pasid; /* 20 bits */
#ifdef CONFIG_INTEL_IOMMU_SVM
	struct device *svm_dev;
#endif
	struct dsadma_device *dsa;
	/* FIXME: Currently only 1 WQ per user context */
	int wq_idx;
	int flags;
	struct list_head mm_list;
	struct list_head wq_list;
	struct task_struct *tsk;
	struct dsa_irq_event ev;
	void __iomem *wq_reg;
	int err;
};

struct dsa_irq_entry {
	void *arg;
	cpumask_var_t mask;
	struct tasklet_struct cleanup_task;
	spinlock_t 	cleanup_lock;
	struct list_head irq_wait_head;
	rwlock_t irq_wait_lock;
	struct dsadma_device *dsa;
	int int_src;
};

/**
 * struct dsadma_device - internal representation of a DSA device
 * @pdev: PCI-Express device
 * @reg_base: MMIO register space base address
 * @dma_pool: for allocating DMA descriptors
 * @completion_pool: DMA buffers for completion ops
 * @dma_dev: embedded struct dma_device
 * @version: version of dsadma device
 * @msix_entries: irq handlers
 * @irq_mode: interrupt mode (INTX, MSI, MSIX)
 */
struct dsadma_device {
	struct pci_dev *pdev;
	void __iomem *reg_base;
	void __iomem *wq_reg_base;
	void __iomem *gwq_reg_base;
	struct pci_pool *dma_pool;
	struct pci_pool *completion_pool;
	struct dma_device dma_dev;
	int system_wq_idx;

	struct list_head  list;	/* List of DSA devices in the platform */
	struct miscdevice misc_dev;
	char user_name[16];
	unsigned int index;
	int virt_dwqs;
	int virt_swqs;
	int vdev_id;

	struct dsa_context priv_ctx;
	bool pasid_enabled;
	int system_pasid;
	spinlock_t cmd_lock;
	u32 version;
	struct msix_entry *msix_entries;
	struct msix_entry *ims_entries;
	enum dsa_irq_mode irq_mode;
	struct dsa_work_queue *wqs;
	struct dsa_grpcfg_reg *grpcfg;
	struct dsa_irq_entry *irq_entries;

	/* General Capabilities */
	u64 gencap;
	u32 max_xfer_bits;
	u32 max_xfer_size; /* in bytes */
	u32 max_batch_size;   /* no. of descriptors in a batch */
	u32 ims_size;         /* no. of entries in interrupt message storage */
	/* Work Queue Capabilities */
	u64 wqcap;
	u16 tot_wq_size;
	u16 max_wqs;
	u16 max_engs;
	u16 num_wqs;
	u16 num_dwqs;
	u16 num_virt_swqs;
	u16 num_grps;

	u16 num_kern_dwqs;

	u16 num_wq_irqs;
	atomic_t irq_wq_next;
	atomic_t irq_ims_next;

	/* Operational Caps - 256 bits but only first 64 bits are valid */
	u64 opcap;
};

struct dsa_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct dma_chan *, char *);
};

/**
 * struct dsa_ring_ent - wrapper around hardware descriptor
 * @hw: hardware DMA descriptor (for memcpy)
 * @raw: hardware raw (un-typed) descriptor
 * @txd: the generic software descriptor for all engines
 * @len: total transaction length for unmap
 * @result: asynchronous result of validate operations
 * @id: identifier for debug
 */

struct dsa_ring_ent {
	/* FIXME: Not sure if we need to keep track of submitted descriptor */
	struct dsa_dma_descriptor hw;
	union {
		struct dsa_completion_record *completion;
		struct dsa_raw_completion_record *comp_raw;
	};
	struct dma_async_tx_descriptor *txd;
	struct dsa_callback_descriptor *cb_desc;
	wait_queue_head_t waitq;
	unsigned long flags;
	#ifdef DEBUG
	int id;
	#endif
};

extern const struct sysfs_ops dsa_sysfs_ops;
extern struct dsa_sysfs_entry dsa_version_attr;
extern struct dsa_sysfs_entry dsa_cap_attr;
extern int dsa_pending_level;
extern int dsa_ring_alloc_order;
extern struct kobj_type dsa_ktype;
extern struct kmem_cache *dsa_cache;
extern int dsa_ring_max_alloc_order;
extern struct kmem_cache *dsa_sed_cache;

static inline struct dsa_work_queue *to_dsa_wq(struct dma_chan *c)
{
	return container_of(c, struct dsa_work_queue, dma_chan);
}

/* wrapper around hardware descriptor format + additional software fields */
#ifdef DEBUG
#define set_desc_id(desc, i) ((desc)->id = (i))
#define desc_id(desc) ((desc)->id)
#else
#define set_desc_id(desc, i)
#define desc_id(desc) (0)
#endif

static inline void
__dump_desc_dbg(struct dsa_work_queue *wq, struct dsa_dma_descriptor *hw,
		struct dma_async_tx_descriptor *tx, int id)
{
	//struct device *dev = to_dev(wq);

	//dev_dbg(dev, "desc[%d]: (%#llx->%#llx) cookie: %d flags: %#x"
		//" ctl: %#10.8x (op: %#x int_en: %d compl: %d)\n", id,
		//(unsigned long long) tx->phys,
		//(unsigned long long) hw->next, tx->cookie, tx->flags,
		//hw->ctl, hw->ctl_f.op, hw->ctl_f.int_en, hw->ctl_f.compl_write);
}

#define dump_desc_dbg(c, d) \
	({ if (d) __dump_desc_dbg(c, d->hw, &d->txd, desc_id(d)); 0; })

static inline int add_dring_idx (struct dsa_completion_ring *dring, int idx, int val)
{
	idx += val;

	if (idx >= dring->num_entries)
		idx = idx - dring->num_entries;

	return idx;
}

static inline int inc_dring_idx (struct dsa_completion_ring *dring, int idx)
{
	idx++;

	if (idx >= dring->num_entries)
		idx = 0;

	return idx;
}

static inline struct dsa_work_queue *
dsa_wq_by_index(struct dsadma_device *dsa_dma, int index)
{
	return &dsa_dma->wqs[index];
}

static inline u64 dsa_swerr(struct dsadma_device *dsa)
{
	return readq(dsa->reg_base + DSA_SWERR_OFFSET);
}

static inline void dsa_wq_disable(struct dsa_work_queue *wq)
{
	int i;
	u32 wq_enable, wq_offset;
	wq_offset = DSA_WQCFG_OFFSET + wq->idx * 0x10 + 0xC;

	writel(0, wq->dsa->reg_base + wq_offset);

	for (i = 0; i < 200000; i++) {
		wq_enable = readl(wq->dsa->reg_base + wq_offset);
		if (!(wq_enable & DSA_ENABLED_BIT))
			break;
	}

	if (i == 200000)
		printk("Error disabling the wq %d %d %x\n", wq->idx, i,
					wq_enable);
}

static inline u32 dsa_ring_size(struct dsa_completion_ring *dring)
{
        return dring->num_entries;
}

/* count of descriptors in flight with the engine */
static inline u16 dsa_ring_active(struct dsa_completion_ring *dring)
{
	if (dring->issued >= dring->tail)
		return dring->issued - dring->tail;
	else
		return dsa_ring_size(dring) - (dring->tail - dring->issued);
}

/* count of descriptors pending submission to hardware */
static inline u16 dsa_ring_pending(struct dsa_completion_ring *dring)
{
	if (dring->head >= dring->issued)
		return dring->head - dring->issued;
	else
		return dsa_ring_size(dring) - (dring->issued - dring->head);
}

static inline u32 dsa_ring_space(struct dsa_completion_ring *dring)
{
        return dsa_ring_size(dring) - dsa_ring_active(dring);
}

static inline int dsa_get_ims_index (struct dsadma_device *dsa)
{
	/* for now just do round-robin assignment */
	/* FIXME: This increment may become negative on overflow */
	return ((atomic_inc_return(&dsa->irq_ims_next) % dsa->ims_size));

}

static inline int dsa_get_msix_index (struct dsadma_device *dsa)
{
	/* for now just do round-robin assignment */
	return ((atomic_inc_return(&dsa->irq_wq_next) % dsa->num_wq_irqs) + 1);

}

static inline int dsa_trylock_desc(struct dsa_ring_ent *desc)
{
        return (likely(!test_and_set_bit_lock(desc_locked, &desc->flags)));
}

static inline void dsa_unlock_desc(struct dsa_ring_ent *desc)
{
	clear_bit_unlock(desc_locked, &desc->flags);
	smp_mb__after_atomic();
	__wake_up_bit(&desc->waitq, &desc->flags, desc_locked);
}

static inline int dsa_wait_on_desc_timeout(struct dsa_ring_ent *desc,
			unsigned long timeout)
{
	DEFINE_WAIT_BIT(wait, &desc->flags, desc_locked);

	wait.key.timeout = jiffies + timeout;
	if (!test_bit(desc_locked, &desc->flags))
		return 0;
	return __wait_on_bit(&desc->waitq, &wait,
				bit_wait_io_timeout, TASK_INTERRUPTIBLE);
}

static inline void dsa_reset(struct dsadma_device *dsa)
{
	/* FIXME: */
}

static inline unsigned char enqcmds(struct dsa_dma_descriptor *desc,
				void __iomem *reg)
{
	unsigned char retry;

	asm volatile(".byte 0xf3, 0x0f, 0x38, 0xf8, 0x02\t\n"
		     "setz %0\t\n"
		: "=r"(retry): "a" (reg), "d" (desc));


	return retry;
}


static inline void movdir64b(struct dsa_dma_descriptor *desc,
				void __iomem *reg)
{
	asm volatile(".byte 0x66, 0x0f, 0x38, 0xf8, 0x02\t\n"
		: : "a" (reg), "d" (desc));
}

static inline u16
dsa_xferlen_to_descs(struct dsadma_device *dsa, size_t len)
{
        u16 num_descs = len >> dsa->max_xfer_bits;

        num_descs += !!(len & ((1 << dsa->max_xfer_bits) - 1));
        return num_descs;
}

static inline struct dsa_ring_ent *
dsa_get_ring_ent(struct dsa_completion_ring *dring, u16 idx)
{
        return &dring->ring[idx];
}

static inline struct dsa_ring_ent *
dsa_alloc_desc(struct dsa_completion_ring *dring)
{
	struct dsa_ring_ent *desc;

        desc = dsa_get_ring_ent(dring, dring->head);

        if (test_bit(desc_in_use, &desc->flags)) {
                printk("No free descriptors\n");
                return NULL;
        }
	dring->head = inc_dring_idx(dring, dring->head);

        set_bit(desc_in_use, &desc->flags);
	return desc;
}


/* DSA Prep functions */
void dsa_dma_prep_batch_memcpy(struct dma_chan *c, int idx, dma_addr_t dma_dest,
			dma_addr_t dma_src, size_t len, unsigned long flags);

void __dsa_prep_batch_memcpy(struct dsa_batch *batch, int desc_idx, u64 dest,
			u64 src, size_t len, unsigned long flags);

void dsa_dma_prep_batch_memset(struct dma_chan *c, int idx, dma_addr_t dma_dest,
		int val, size_t len, unsigned long flags);
void __dsa_prep_batch_memset(struct dsa_batch *batch, int desc_idx, u64 dst,
		u64 val, size_t len, unsigned long flags);

void __dsa_prep_batch_compare(struct dsa_batch *batch, int idx, u64 src1,
		u64 src2, size_t len, unsigned long flags);
void dsa_dma_prep_batch_compare(struct dma_chan *c, int idx,
		dma_addr_t dma_src1, dma_addr_t dma_src2,
		size_t len, unsigned long flags);

void __dsa_prep_batch_compval(struct dsa_batch *batch, int idx, u64 val,
		u64 src, size_t len, unsigned long flags);
void dsa_dma_prep_batch_compval(struct dma_chan *c, int idx,
		unsigned long value, dma_addr_t dma_src,
		size_t len, unsigned long flags);

void __dsa_prep_batch_dualcast(struct dsa_batch *batch, int idx, u64 dst1,
		u64 dst2, u64 src, size_t len, unsigned long flags);
void dsa_dma_prep_batch_dualcast(struct dma_chan *c, int idx, dma_addr_t dest1,
		dma_addr_t dest2, dma_addr_t dma_src,
		size_t len, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_batch(struct dsa_completion_ring *dring,
	u64 batch_addr, int num_descs, unsigned long flags);

struct dma_async_tx_descriptor *
dsa_dma_prep_batch(struct dma_chan *c, dma_addr_t dma_batch,
				int num_descs, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_memcpy(struct dsa_completion_ring *dring,
		u64 dst, u64 src, size_t len, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_dma_prep_memcpy(struct dma_chan *c, dma_addr_t dma_dest,
			   dma_addr_t dma_src, size_t len, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_memset(struct dsa_completion_ring *dring,
	u64 dst, u64 value, size_t len, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_dma_prep_memset(struct dma_chan *c, dma_addr_t dma_dest,
			   int value, size_t len, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_compare(struct dsa_completion_ring *dring,
	u64 src1, u64 src2, size_t len, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_dma_prep_compare(struct dma_chan *c, dma_addr_t source1,
			dma_addr_t source2, size_t len, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_compval(struct dsa_completion_ring *dring,
	u64 val, u64 src, size_t len, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_dma_prep_compval(struct dma_chan *c, unsigned long val,
			dma_addr_t source, size_t len, unsigned long flags);

struct dsa_ring_ent *__dsa_prep_dualcast(struct dsa_completion_ring *dring,
			u64 dst1, u64 dst2, u64 src, size_t len,
			unsigned long flags);

struct dma_async_tx_descriptor *
dsa_dma_prep_dualcast(struct dma_chan *c, dma_addr_t dest1, dma_addr_t dest2,
			dma_addr_t source, size_t len, unsigned long flags);

struct dma_async_tx_descriptor *
dsa_dma_prep_drain (struct dsa_work_queue *wq, unsigned long flags);

void dsa_free_desc(struct dsa_completion_ring *dring,
				struct dsa_ring_ent *desc);

struct dma_async_tx_descriptor *
dsa_prep_interrupt_lock(struct dma_chan *c, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_prep_xor(struct dma_chan *chan, dma_addr_t dest, dma_addr_t *src,
	       unsigned int src_cnt, size_t len, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_prep_xor_val(struct dma_chan *chan, dma_addr_t *src,
		    unsigned int src_cnt, size_t len,
		    enum sum_check_flags *result, unsigned long flags);
struct dma_async_tx_descriptor *
dsa_prep_pq(struct dma_chan *chan, dma_addr_t *dst, dma_addr_t *src,
	      unsigned int src_cnt, const unsigned char *scf, size_t len,
	      unsigned long flags);
struct dma_async_tx_descriptor *
dsa_prep_pq_val(struct dma_chan *chan, dma_addr_t *pq, dma_addr_t *src,
		  unsigned int src_cnt, const unsigned char *scf, size_t len,
		  enum sum_check_flags *pqres, unsigned long flags);

int dsa_enqcmds (struct dsa_dma_descriptor *hw, void __iomem * wq_reg);

/* DSA Operation functions */
irqreturn_t dsa_wq_completion_interrupt(int irq, void *data);
irqreturn_t dsa_misc_interrupt(int irq, void *data);

struct dsa_ring_ent **
dsa_alloc_ring(struct dma_chan *c, int order, gfp_t flags);
void dsa_start_null_desc(struct dsa_work_queue *dsa_chan);
void dsa_free_ring_ent(struct dsa_ring_ent *desc, struct dma_chan *chan);
int dsa_reset_hw(struct dsa_work_queue *dsa_chan);
enum dma_status
dsa_tx_status(struct dma_chan *c, dma_cookie_t cookie,
		struct dma_tx_state *txstate);
void dsa_wq_cleanup(unsigned long data);
void dsa_misc_cleanup(unsigned long data);

void dsa_completion_cleanup(struct dsa_completion_ring *dring);

void dsa_timer_event(unsigned long data);
int dsa_check_space_lock(struct dsa_work_queue *dsa_chan, int num_descs);
void dsa_issue_pending(struct dma_chan *chan);
void dsa_timer_event(unsigned long data);
struct dsa_work_queue *dsa_wq_alloc (struct dsadma_device *dsa, int dedicated);
void dsa_wq_free (struct dsa_work_queue *wq);


/* DSA Init functions */
void dsa_kobject_add(struct dsadma_device *dsa_dma, struct kobj_type *type);
void dsa_kobject_del(struct dsadma_device *dsa_dma);
int dsa_dma_setup_interrupts(struct dsadma_device *dsa_dma);
void dsa_stop(struct dsa_work_queue *dsa_chan);

int dsa_alloc_client_buffers (struct dsa_completion_ring *dring, gfp_t flags);
void dsa_free_client_buffers (struct dsa_completion_ring *dring);
void dsa_init_completion_ring(struct dsa_completion_ring *dring);

struct dsadma_device * get_dsadma_device_by_minor(unsigned int minor);

int dsa_usr_add(struct dsadma_device *dsa);

int dsa_wq_set_pasid (struct dsadma_device *dsa, int wq_idx, int pasid,
				bool privilege);
int dsa_wq_disable_pasid (struct dsadma_device *dsa, int wq_idx);

void __iomem *dsa_get_wq_reg(struct dsadma_device *dsa, int wq_idx,
				int msix_idx, bool priv);
void dsa_setup_irq_event (struct dsa_irq_event *ev, struct dsa_irq_entry
			*irq_entry, struct dsa_completion_ring *dring,
			void (*isr_cb)(struct dsa_completion_ring *dring));

int dsa_ctx_drain_pasid (struct dsa_context *ctx, bool abort);

struct dsa_completion_ring *dsa_alloc_svm_resources(struct dsa_work_queue *wq);
void dsa_free_descriptors (struct dsa_completion_ring *dring);

struct dsa_batch *dsa_alloc_batch_resources (struct dsa_completion_ring *dring,
		int num_descs);
void dsa_free_batch_resources (struct dsa_batch *batch);
struct dsa_batch *dsa_dma_alloc_batch_resources(struct dma_chan
		*dma_chan, int num_descs);
void dsa_dma_free_batch_resources (struct dsa_batch *batch);

void dsa_svm_completion_cleanup(struct dsa_completion_ring *dring);
void dsa_dma_completion_cleanup(struct dsa_completion_ring *dring);

/* Self test routines */

int dsa_dma_self_test (struct dsadma_device *dsa);


int dsa_host_init(struct dsadma_device *dsa);
void dsa_host_exit(struct dsadma_device *dsa);

#endif /* DSADMA_H */
