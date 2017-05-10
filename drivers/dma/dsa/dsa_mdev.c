/*
 * KVMDSA - the implementation of Intel mediated pass-through framework for KVM
 *
 * Copyright(c) 2014-2017 Intel Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Authors:
 *    Xiao Zheng <xiao.zheng@intel.com>
 *    Kevin Tian <kevin.tian@intel.com>
 *    Sanjay Kumar <sanjay.k.kumar@intel.com>
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/mmu_context.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/eventfd.h>
#include <linux/uuid.h>
#include <linux/vmalloc.h>
#include <linux/kvm_host.h>
#include <linux/vfio.h>
#include <linux/pci.h>
#include <linux/mdev.h>
#include <linux/msi.h>
#include <linux/intel-iommu.h>

#include "dma.h"
#include "dsa_vdcm.h"

struct mutex mdev_list_lock;
struct list_head dsa_mdevs_list;

static u64 get_reg_val (void *buf, int size)
{
	u64 val = 0;

	switch(size) {
		case 8:
			val = *(uint64_t *)buf;
		break;
		case 4:
			val = *(uint32_t *)buf;
		break;
		case 2:
			val = *(uint16_t *)buf;
		break;
		case 1:
			val = *(uint8_t *)buf;
		break;
	}
	return val;
}

static uint64_t dsa_pci_config[] = {
	0x001000006f308086ULL,
	0x0080000008800000ULL,
	0x0000000000000004ULL,
	0x0000000000000004ULL,
	0x0000000000000004ULL,
	0x2010808600000000ULL,
	0x0000004000000000ULL,
	0x000000ff00000000ULL,
	0x0000600000005011ULL, /* MSI-X capability */
	0x0000700000000000ULL,
	0x0000000000910010ULL, /* PCIe capability */
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000001000000000ULL,
	0x0000000000000000ULL,
};

static uint64_t dsa_pci_ext_cap[] = {
	0x000000611101000fULL, /* ATS capability */
	0x0000000000000000ULL,
	0x0100000012010013ULL, /* Page Request capability */
	0x0000000000000001ULL,
	0x000014040001001bULL, /* PASID capability */
	0x0000000000000000ULL,
};

static uint64_t dsa_cap_ctrl_reg[] = {
	0x0000000000000100ULL,
	0x0000000000000000ULL,
	0x0000000500400001ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x0000000000000000ULL,
	0x000000000011f3ffULL,
};

static int vdsa_send_interrupt(struct vdcm_dsa *vdsa, int msix_idx);

void dsa_free_ims_index(struct dsadma_device *dsa, unsigned long ims_idx)
{
	clear_bit(ims_idx, dsa->allocated_ims);
	atomic_dec(&dsa->num_allocated_ims);
}

int dsa_alloc_ims_index (struct dsadma_device *dsa)
{
	unsigned long index = 0;
	int i;

	for(i = 0; i < dsa->ims_size; i++) {
		index = find_next_zero_bit(dsa->allocated_ims, dsa->ims_size,
				index);
		if (!test_and_set_bit(index, dsa->allocated_ims))
			break;
	}

	if (i == dsa->ims_size)
		return -ENOSPC;

	return index;
}

irqreturn_t dsa_guest_wq_completion_interrupt(int irq, void *data)
{
	struct ims_irq_entry *irq_entry = data;
        struct vdcm_dsa *vdsa = irq_entry->vdsa;
	int msix_idx = irq_entry->int_src;

	vdsa_send_interrupt(vdsa, msix_idx + 1);

        return IRQ_HANDLED;
}

static unsigned int dsa_ims_irq_mask (struct msi_desc *desc)
{
	int ims_offset;
	u32 mask_bits = desc->devims.masked;
	struct device *dev = desc->dev;
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	struct dsadma_device *dsa = vdsa->dsa;
	void __iomem *base;

	printk("dsa irq mask\n");

	mask_bits &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;
	mask_bits |= PCI_MSIX_ENTRY_CTRL_MASKBIT;

	ims_offset = DSA_IMS_OFFSET + vdsa->ims_index[desc->devims.ims_index]
						* 0x10;
	base = dsa->reg_base + ims_offset;

	writel(mask_bits, base + PCI_MSIX_ENTRY_VECTOR_CTRL);

	return mask_bits;
}

static unsigned int dsa_ims_irq_unmask (struct msi_desc *desc)
{
	int ims_offset;
	u32 mask_bits = desc->devims.masked;
	struct device *dev = desc->dev;
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	struct dsadma_device *dsa = vdsa->dsa;
	void __iomem *base;

	printk("dsa irq unmask\n");

	mask_bits &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;

	ims_offset = DSA_IMS_OFFSET + vdsa->ims_index[desc->devims.ims_index]
						* 0x10;
	base = dsa->reg_base + ims_offset;

	writel(mask_bits, base + PCI_MSIX_ENTRY_VECTOR_CTRL);

	return mask_bits;
}

static void dsa_ims_write_msg (struct msi_desc *desc, struct msi_msg *msg)
{
	int ims_offset;
	struct device *dev = desc->dev;
	struct mdev_device *mdev = mdev_from_dev(dev);
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	struct dsadma_device *dsa = vdsa->dsa;
	void __iomem *base;

	printk("ims_write: %d %x\n", desc->devims.ims_index, msg->address_lo);

	ims_offset = DSA_IMS_OFFSET + vdsa->ims_index[desc->devims.ims_index]
						* 0x10;

	base = dsa->reg_base + ims_offset;

	writel(msg->address_lo, base + PCI_MSIX_ENTRY_LOWER_ADDR);
	writel(msg->address_hi, base + PCI_MSIX_ENTRY_UPPER_ADDR);
	writel(msg->data, base + PCI_MSIX_ENTRY_DATA);
}

struct dev_ims_ops dsa_ims_ops  = {
	.irq_mask		= dsa_ims_irq_mask,
	.irq_unmask		= dsa_ims_irq_unmask,
	.irq_write_msi_msg	= dsa_ims_write_msg,
};

static int vdsa_free_ims_entries (struct vdcm_dsa *vdsa)
{
	struct dsadma_device *dsa = vdsa->dsa;
	struct ims_irq_entry *irq_entry;
	struct mdev_device *mdev = vdsa->vdev.mdev;
	struct device *dev = mdev_dev(mdev);
	struct msi_desc *desc;
	int i;

	i = 0;
	for_each_msi_entry(desc, dev) {
		irq_entry = &vdsa->irq_entries[i];
		devm_free_irq(dev, desc->irq, irq_entry);
		i++;
	}

	dev_ims_free_irqs(dev);

	for (i = 0; i < vdsa->num_wqs; i++)
		dsa_free_ims_index(dsa, vdsa->ims_index[i]);

	return 0;
}

static int vdsa_setup_ims_entries (struct vdcm_dsa *vdsa)
{
	struct dsadma_device *dsa = vdsa->dsa;
	struct ims_irq_entry *irq_entry;
	struct mdev_device *mdev = vdsa->vdev.mdev;
	struct device *dev = mdev_dev(mdev);
	struct msi_desc *desc;
	int i, err;

	if (atomic_add_return(vdsa->num_wqs, &dsa->num_allocated_ims) >
						dsa->ims_size) {
		atomic_sub(vdsa->num_wqs, &dsa->num_allocated_ims);
		return -ENOSPC;
	}
	for (i = 0; i < vdsa->num_wqs; i++)
		vdsa->ims_index[i] = dsa_alloc_ims_index(dsa);

	err = dev_ims_alloc_irqs(dev, vdsa->num_wqs, &dsa_ims_ops);

	if (err < 0) {
		printk("Enabling IMS entry! %d\n", err);
		return err;
	}

	i = 0;
	for_each_msi_entry(desc, dev) {
		irq_entry = &vdsa->irq_entries[i];
		irq_entry->vdsa = vdsa;
		irq_entry->int_src = i;

		err = devm_request_irq(dev, desc->irq,
				dsa_guest_wq_completion_interrupt, 0,
				"dsa-ims", irq_entry);
		if (err) {
			break;
		}
		i++;
	}

	if (err) {
		/* free allocated MSI interrupts above */
		i = 0;
		for_each_msi_entry(desc, dev) {
			irq_entry = &vdsa->irq_entries[i];
			devm_free_irq(dev, desc->irq, irq_entry);
			i++;
		}
	}
	return 0;
}

static int vdsa_free_ims_entry (struct vdcm_dsa *vdsa, int msix_idx)
{

	return 0;
}

static void vdsa_mmio_init (struct vdcm_dsa *vdsa)
{
	int i;
	int total_wq_size = 0;
	u64 sm = 0, dm = 0;
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	u64 *wq_cap;
	struct dsadma_device *dsa = vdsa->dsa;

	for (i = 0; i < vdsa->num_wqs; i++) {
		struct dsa_work_queue *wq = vdsa->wqs[i];
		struct dsa_work_queue_reg *wqcfg;
		struct dsa_grpcfg_reg *grpcfg;

		total_wq_size += wq->wq_size;

		wqcfg = (struct dsa_work_queue_reg*)&bar0->wq_ctrl_regs[i * 16];
		grpcfg = (struct dsa_grpcfg_reg *)
				&bar0->grp_ctrl_regs[wq->grp_id * 64];

		/* setup wq cfg */
		wqcfg->a.a_fields.wq_size = wq->wq_size;
		wqcfg->b.b_fields.threshold = wq->threshold;
		wqcfg->c.c_fields.mode = wq->dedicated;
		wqcfg->c.c_fields.bof_en = wq->bof_enabled;
		wqcfg->c.c_fields.priority = wq->priority;

		/* setup grp cfg */
		grpcfg->wq_bits[i/BITS_PER_LONG] |= (1 << (i % BITS_PER_LONG));
		/* copy the physical eng_bits for now. is that ok? */
		grpcfg->eng_bits = dsa->grpcfg[wq->grp_id].eng_bits;

		if (wq->dedicated == 0) {
			wqcfg->d.val = 3;
			sm = 1;
		} else
			dm = 1;
	}

	/* setup wqcap */
	wq_cap = (u64 *)&bar0->cap_ctrl_regs[DSA_WQCAP_OFFSET];
	*wq_cap = (sm << 48) | (dm << 49) | (((u64)dsa->max_engs & 0xFF) << 24)
		|(((u64)vdsa->num_wqs & 0xFF) << 16) | (total_wq_size & 0xffff);
}


struct vdcm_dsa * vdcm_vdsa_create (struct dsadma_device *dsa,
			struct vdcm_dsa_type *type)
{
	struct vdcm_dsa *vdsa;

	vdsa = kzalloc(sizeof(struct vdcm_dsa), GFP_KERNEL);
	if (vdsa == NULL)
		return NULL;

	vdsa->dsa = dsa;

	vdsa->id = dsa->vdev_id++;

	memcpy(vdsa->cfg, dsa_pci_config, sizeof(dsa_pci_config));
	memcpy(vdsa->cfg + 0x100, dsa_pci_ext_cap, sizeof(dsa_pci_ext_cap));

	memcpy(vdsa->bar0.cap_ctrl_regs, dsa_cap_ctrl_reg,
						sizeof(dsa_cap_ctrl_reg));

	switch (type->type) {
		case DSA_MDEV_TYPE_1_DWQ_0_SWQ:
			vdsa->wqs[0] = dsa_wq_alloc(dsa, 1);

			if (vdsa->wqs[0] == NULL) {
				kfree(vdsa);
				return NULL;
			}

			vdsa->num_wqs = 1;

			/* Set the MSI-X table size */
			vdsa->cfg[VDSA_MSIX_TBL_SZ_OFFSET] = vdsa->num_wqs;

		break;
		case DSA_MDEV_TYPE_0_DWQ_1_SWQ:
			vdsa->wqs[0] = dsa_wq_alloc(dsa, 0);
			if (vdsa->wqs[0] == NULL) {
				kfree(vdsa);
				return NULL;
			}

			vdsa->num_wqs = 1;

			/* Set the MSI-X table size */
			vdsa->cfg[VDSA_MSIX_TBL_SZ_OFFSET] = vdsa->num_wqs;

		break;
	}

	vdsa->bar_size[0] = VDSA_BAR0_SIZE;
	vdsa->bar_size[1] = VDSA_BAR2_SIZE;
	vdsa->bar_size[2] = 0;

	vdsa_mmio_init(vdsa);

	return vdsa;
}

static int vdsa_send_interrupt(struct vdcm_dsa *vdsa, int msix_idx)
{
	int ret = -1;

	if (!vdsa->vdev.msix_trigger[msix_idx]) {
		pr_info("%s: Intr evtfd not found %d\n", __func__, msix_idx);
		return -EINVAL;
	}

	ret = eventfd_signal(vdsa->vdev.msix_trigger[msix_idx], 1);

	pr_info("interrupt triggered %d %d\n", vdsa->id, msix_idx);

	if (ret != 1)
		pr_err("%s: eventfd signal failed (%d)\n", __func__, ret);

	return ret;
}

static inline u8 vdsa_state (struct vdcm_dsa *vdsa)
{
	return vdsa->bar0.cap_ctrl_regs[DSA_ENABLE_OFFSET] & 0x3;
}

static int vdcm_vdsa_cfg_read(struct vdcm_dsa *vdsa, unsigned int pos,
		void *buf, unsigned int count)
{
	uint32_t offset = pos & 0xfff;

	memcpy(buf, &vdsa->cfg[offset], count);

	printk("dsa pci R %d %x %x: %llx\n", vdsa->id, count, offset, get_reg_val(buf, count));

	return 0;
}

static int vdcm_vdsa_cfg_write(struct vdcm_dsa *vdsa, unsigned int pos,
		void *buf, unsigned int size)
{
	u32 offset = pos & 0xfff;
	u64 val;
	u8 *cfg = vdsa->cfg;
	u8 *bar0 = vdsa->bar0.cap_ctrl_regs;

	printk("dsa pci W %d %x %x: %llx\n", vdsa->id, size, offset, get_reg_val(buf, size));

	switch (offset) {
		case 0x04: { /* device control */
			bool bme;
			memcpy(&cfg[offset], buf, size);
			bme = cfg[offset] & (1u << 2);
			if (!bme && ((*(u32 *)&bar0[DSA_ENABLE_OFFSET]) & 0x3) != 0) {
				*(u32 *)(&bar0[DSA_ENABLE_OFFSET]) = 8u << 8;
			}
			if (size < 4)
				break;
			offset += 2;
			buf = buf + 2;
			size -= 2;
			/* fall through */
        	}

        	case 0x6: { /* device status */
			u16 nval = get_reg_val(buf, size) << (offset & 1) * 8;
			nval &= 0xf900;
			*(u16 *)&cfg[offset] = *((u16 *)&cfg[offset]) & ~nval;
			break;
		}

		case 0x0c:
		case 0x3c:
			memcpy(&cfg[offset], buf, size);
			break;

		case 0x10: /* BAR0 */
		case 0x14: /* BAR1 */
		case 0x18: /* BAR2 */
		case 0x1c: /* BAR3 */
		case 0x20: /* BAR4 */
		case 0x24: /* BAR5 */ {
			unsigned int bar_id, bar_offset;
			u64 bar, bar_size;

			bar_id = (offset - 0x10) / 8;
			bar_size = vdsa->bar_size[bar_id];
			bar_offset = 0x10 + bar_id * 8;

			val = get_reg_val(buf, size);
			bar = *(u64 *)&cfg[bar_offset];
			memcpy((u8 *)&bar + (offset & 0x7), buf, size);
			bar &= ~(bar_size - 1);

			*(u64 *)&cfg[bar_offset] = bar | 4;

			if (val == -1U || val == -1ULL)
				break;
			if (bar == 0 || bar == -1ULL - -1U)
				break;
			if (bar == (-1U & ~(bar_size - 1)))
				break;
			if (bar == (-1ULL & ~(bar_size - 1)))
				break;
			if (bar == vdsa->bar_val[bar_id])
				break;

			vdsa->bar_val[bar_id] = bar;
			break;
		}

		case VDSA_ATS_OFFSET + 4:
			if (size < 4)
				break;
			offset += 2;
			buf = buf + 2;
			size -= 2;
			/* fall through */

		case VDSA_ATS_OFFSET + 6:
			memcpy(&cfg[offset], buf, size);
			break;
        	case VDSA_PRS_OFFSET + 4: {
			u8 old_val, new_val;

			val = get_reg_val(buf, 1);
			old_val = cfg[VDSA_PRS_OFFSET + 4];
			new_val = val & 1;

			cfg[offset] = new_val;
			if (old_val == 0 && new_val == 1) {
				/* clear Stopped, Response Failure,
				and Unexpected Response. */
				*(u16 *)&cfg[VDSA_PRS_OFFSET + 6] &=
							~(u16)(0x0103);
			}
			if (val == 2) {
				/* FIXME: Reset page requests */
			}
			if (size < 4)
				break;
			offset += 2;
			buf = (u8 *)buf + 2;
			size -= 2;
			/* fall through */
		}
		case VDSA_PRS_OFFSET + 6:
			cfg[offset] &= ~(get_reg_val(buf, 1) & 3);
			break;
		case VDSA_PRS_OFFSET + 12 ... VDSA_PRS_OFFSET + 15:
			memcpy(&cfg[offset], buf, size);
			break;

		case VDSA_PASID_OFFSET + 4:
			if (size < 4)
				break;
			offset += 2;
			buf = buf + 2;
			size -= 2;
			/* fall through */
		case VDSA_PASID_OFFSET + 6:
			cfg[offset] = get_reg_val(buf, 1) & 5;
			break;
	}

	return 0;
}

static int vdcm_vdsa_mmio_read(struct vdcm_dsa *vdsa, u64 pos, void *buf,
                                unsigned int size)
{
	u32 offset = pos & (vdsa->bar_size[0] - 1);
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	u8 *reg_addr;

	BUG_ON((size & (size - 1)) != 0);
	BUG_ON(size > 8);
	BUG_ON((offset & (size - 1)) != 0);

        switch (offset) {
		case 0 ... VDSA_CAP_CTRL_SZ - 1:
			reg_addr = &bar0->cap_ctrl_regs[offset];
			break;

		case DSA_GRPCFG_OFFSET ... DSA_GRPCFG_OFFSET + VDSA_GRP_CTRL_SZ - 1:
			reg_addr =
				&bar0->grp_ctrl_regs[offset-DSA_GRPCFG_OFFSET];
			break;

		case DSA_WQCFG_OFFSET ... DSA_WQCFG_OFFSET + VDSA_WQ_CTRL_SZ - 1:
			reg_addr = &bar0->wq_ctrl_regs[offset-DSA_WQCFG_OFFSET];
			break;

		/* TODO: WQ Occupancy Interrupt Control */
		case DSA_MSIX_TABLE_OFFSET ... DSA_MSIX_TABLE_OFFSET + VDSA_MSIX_TBL_SZ - 1:
			reg_addr =
				&bar0->msix_table[offset-DSA_MSIX_TABLE_OFFSET];
                break;

		case DSA_MSIX_PBA_OFFSET ... DSA_MSIX_PBA_OFFSET + 7:
			reg_addr = (u8 *)&bar0->msix_pba;
			break;
		default:
			reg_addr = 0;
			break;
        }

	if (reg_addr != 0)
		memcpy(buf, reg_addr, size);
	else
		memset(buf, 0, size);

	printk("dsa mmio R %d %x %x: %llx\n", vdsa->id, size, offset, get_reg_val(buf, size));
	return 0;
}

void vdsa_enable(struct vdcm_dsa *vdsa)
{
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	bool ats = (*(u16 *)&vdsa->cfg[VDSA_ATS_OFFSET+6]) & (1U << 15);
	bool prs = (*(u16 *)&vdsa->cfg[VDSA_PRS_OFFSET+4]) & 1U;
	bool pasid = (*(u16 *)&vdsa->cfg[VDSA_PASID_OFFSET+6]) & 1U;
	u32 *reg = (u32 *)&bar0->cap_ctrl_regs[DSA_ENABLE_OFFSET];

	printk("dsa device enable\n");

	/* Check PCI configuration */
	if ((vdsa->cfg[PCI_COMMAND] & (1U << 2)) == 0)
		cmpxchg(reg, 1U, 2U << 8);

	if (pasid != prs || (pasid && !ats))
		cmpxchg(reg, 1U, 3U << 8);

	cmpxchg(reg, 1U, 3U);
}

void vdsa_disable(struct vdcm_dsa *vdsa)
{
	int i;
	struct dsa_work_queue *wq;
	volatile struct dsa_work_queue_reg *wqcfg;
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	u32 *reg = (u32 *)&bar0->cap_ctrl_regs[DSA_ENABLE_OFFSET];

	printk("dsa device disable\n");

	/* FIXME: If it is a DWQ, need to disable the DWQ as well */
	for (i = 0; i < vdsa->num_wqs; i++) {
		int wq_state;

		wq = vdsa->wqs[i];
		wqcfg = (struct dsa_work_queue_reg*)&bar0->wq_ctrl_regs[i * 16];
		wq_state = wqcfg->d.val;

		switch (wq_state) {
			case 1:
				if (cmpxchg(&wqcfg->d.val, 1U, 1U << 8))
					break;
				/* fall through */
			case 3:
				cmpxchg(&wqcfg->d.val, 3U, 0);
				/* fall through */
			default:
				break;
		}
	}

	cmpxchg(reg, 2U, 0);
}

static void wq_enable (struct vdcm_dsa *vdsa, int wq_id)
{
	struct dsa_work_queue *wq;
	volatile struct dsa_work_queue_reg *wqcfg;
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	int dedicated;
	bool wq_pasid_enable;
	bool pasid_enabled = (*(u16 *)&vdsa->cfg[VDSA_PASID_OFFSET+6]) & 1U;
	u64 *wqcap;

	wq = vdsa->wqs[wq_id];

	printk("vdsa enable wq %u:%u\n", wq_id, wq->idx);

	wqcfg = (struct dsa_work_queue_reg*)&bar0->wq_ctrl_regs[wq_id * 16];
	wqcap = (u64 *)&bar0->cap_ctrl_regs[DSA_WQCAP_OFFSET];

	if (vdsa_state(vdsa) != 3) {
		cmpxchg(&wqcfg->d.val, 1U, 1U << 8);
		return;
	}

	if (wqcfg->a.a_fields.wq_size == 0) {
		cmpxchg(&wqcfg->d.val, 1U, 2U << 8);
		return;
	}

	if (wqcfg->b.b_fields.threshold > wqcfg->a.a_fields.wq_size) {
		cmpxchg(&wqcfg->d.val, 1U, 3U << 8);
		return;
	}

	dedicated = wqcfg->c.c_fields.mode;
	wq_pasid_enable = wqcfg->c.c_fields.paside;

	if (((dedicated == 0) && ((*wqcap & (1UL << 48)) == 0)) ||
			((dedicated == 1) && ((*wqcap & (1UL << 49)) == 0))) {
		cmpxchg(&wqcfg->d.val, 1U, 4U << 8);
		return;
	}

	/* No need to check for error code 5 because BoF is enabled in both
	 * GENCAP and WQCAP */

	if ((dedicated == 0 && wq_pasid_enable == 0)
		|| (wq_pasid_enable != 0 && pasid_enabled == 0)) {
		cmpxchg(&wqcfg->d.val, 1U, 6U << 8);
		return;
	}

	/* If dedicated WQ and PASID is not enabled, program the default PASID
	 * in the WQ PASID register
	 */
	if (dedicated == 1 && wq_pasid_enable == 0) {
		int wq_pasid;
		struct mdev_device *mdev = vdsa->vdev.mdev;
		struct device *dev = mdev_dev(mdev);

		wq_pasid = intel_iommu_get_domain_pasid(dev);

		if (wq_pasid >= 0) {
			printk("program pasid %d in wq %d\n", wq_pasid, wq->idx);
			dsa_wq_set_pasid(vdsa->dsa, wq->idx, wq_pasid, true);
		} else
			printk("pasid lookup failed for wq %d\n", wq->idx);
	}

	cmpxchg(&wqcfg->d.val, 1U, 3u);
}

static void wq_disable (struct vdcm_dsa *vdsa, int wq_id)
{
	struct dsa_work_queue *wq;
	volatile struct dsa_work_queue_reg *wqcfg;
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;
	int dedicated;

	wq = vdsa->wqs[wq_id];

	printk("vdsa disable wq %u:%u\n", wq_id, wq->idx);

	wqcfg = (struct dsa_work_queue_reg*)&bar0->wq_ctrl_regs[wq_id * 16];

	dedicated = wqcfg->c.c_fields.mode;

	if (dedicated && dsa_wq_disable_pasid(vdsa->dsa, wq->idx))
		printk("vdsa disable_wq %d failed\n", wq->idx);

	cmpxchg(&wqcfg->d.val, 2U, 0);
}

static int vdcm_vdsa_mmio_write(struct vdcm_dsa *vdsa, u64 pos, void *buf,
                                unsigned int size)
{
	u32 offset = pos & (vdsa->bar_size[0] - 1);
	struct vdcm_dsa_pci_bar0 *bar0 = &vdsa->bar0;

	BUG_ON((size & (size - 1)) != 0);
	BUG_ON(size > 8);
	BUG_ON((offset & (size - 1)) != 0);

	printk("dsa mmio W %d %x %x: %llx\n", vdsa->id, size, offset, get_reg_val(buf, size));

	switch (offset) {
		case DSA_GENCFG_OFFSET ... DSA_GENCFG_OFFSET + 7:
			/* write only when device is disabled */
			if (vdsa_state(vdsa) == 0)
				memcpy(&bar0->cap_ctrl_regs[offset], buf, size);
			break;

		case DSA_GENCTRL_OFFSET:
			memcpy(&bar0->cap_ctrl_regs[offset], buf, size);
			break;

		case DSA_ENABLE_OFFSET: {
			u32 val = get_reg_val(buf, size);
			volatile u32 *reg = (u32 *)&bar0->cap_ctrl_regs[offset];
			u32 old_val = *reg;
			int vdev_state = old_val & 3;
			bool enable = val & 1;
			bool reset = val & 4;

			if (reset) {
				printk("dsa reset control not implemented\n");
			} else if (vdev_state == 0 && enable == 1) {
				if (cmpxchg(reg, old_val, 1) == 0)
					vdsa_enable(vdsa);
			} else if (vdev_state == 3 && enable == 0) {
				if (cmpxchg(reg, old_val, 2) == 3)
					vdsa_disable(vdsa);
			}
			break;
		}

		case DSA_INTCAUSE_OFFSET:
			bar0->cap_ctrl_regs[offset] &=
					~(get_reg_val(buf, 1) & 0x0f);
			break;

		/* Abort/Drain TBD */
		case DSA_CMD_OFFSET:
			if (size == 4) {
				volatile union dsa_command_reg *reg = (union
					dsa_command_reg *)&bar0->cap_ctrl_regs[
						DSA_CMD_OFFSET];
				u32 val = get_reg_val(buf, size) |
							reg->fields.status;
				u32 old_val = reg->val;

				printk("dsa cmd write %08x (prev: %08x)\n",
					val, old_val);

				if ((old_val & 0x80000000) == 0 &&
					cmpxchg(&reg->val, old_val, val)) {
					bool abort = (val >> 28) & 1U;
					switch ((val >> 24) & 0x0f) {
						case 1:
							//drain_all(abort);
							break;
						case 2:
							dsa_drain_pasid(
							vdsa->dsa, val &
							0xfffff, abort);
							break;
						case 3:
							//drain_wq(val & 0xff,
								//abort);
							break;
					}
				}
				val &= ~0x80000000;
				printk("cmd completion %08x\n", val);
				if (val & DSA_CMD_INT_MASK) {
					bar0->cap_ctrl_regs[DSA_INTCAUSE_OFFSET]
							|= 4U;

					vdsa_send_interrupt(vdsa, 0);
				}
			}
			break;
		/* W1C */
		case DSA_SWERR_OFFSET:
		case DSA_HWERR_OFFSET:
			bar0->cap_ctrl_regs[offset] &=
						~(get_reg_val(buf, 1) & 3);
			break;

		case DSA_WQCFG_OFFSET ... DSA_WQCFG_OFFSET + VDSA_WQ_CTRL_SZ - 1: {
			struct dsa_work_queue_reg *wqcfg;
			int wq_id = (offset - DSA_WQCFG_OFFSET) / 0x10;
			int subreg = offset & 0x0c;
			u32 new_val;

			wqcfg = (struct dsa_work_queue_reg *)
					&bar0->wq_ctrl_regs[wq_id * 0x10];
			if (size >= 4) {
				new_val = get_reg_val(buf, 4);
			} else {
				u32 tmp1, tmp2, shift, mask;
				switch (subreg) {
					case 4:
						tmp1 = wqcfg->b.val; break;
					case 8:
						tmp1 = wqcfg->c.val; break;
					case 12:
						tmp1 = wqcfg->d.val; break;
				}
				tmp2 = get_reg_val(buf, size);
				shift = (offset & 0x03U) * 8;
				mask = ((1U << size * 8) - 1u) << shift;
				new_val = (tmp1 & ~mask) | (tmp2 << shift);
			}
			switch (subreg) {
				case 4: {
					u16 threshold = new_val & 0xffff;
					wqcfg->b.b_fields.threshold = threshold;
					if (threshold >
						wqcfg->a.a_fields.wq_size) {
						volatile u32 *r =
							&wqcfg->d.val;
						u32 wq_state = *r;
						switch (wq_state) {
						case 1:
							if (cmpxchg(r, 1U, 4U << 8))
							break;
							/* fall through */
						case 3:
							if (cmpxchg(r, 3U, 4U << 8))
								wq_disable(vdsa, wq_id);
							break;
						default:
							break;
						}
					}
					break;
				}

				case 8: {
					u32 wq_state = wqcfg->d.val & 3u;
					if (wq_state == 0) {
						wqcfg->c.val = new_val & 0xcffffff3;
					}
					if (size <= 4)
						break;
					new_val = get_reg_val(buf + 4, size+4);
					/* fall through */
				}

				case 12: {
					volatile u32 *reg = &wqcfg->d.val;
					u32 old_val = *reg;
					int wq_state = old_val & 3U;
					bool enable = new_val & 1U;

					if (wq_state == 0 && enable == 1) {
						if (cmpxchg(reg, old_val, 1U) == 0) {
							wq_enable(vdsa, wq_id);
						}
					}
					else if (wq_state == 3 && enable == 0) {
						if (cmpxchg(reg, old_val, 2U) == 3) {
							wq_disable(vdsa, wq_id);
						}
					}
					break;
				}
			}
			break;
		}
		case DSA_MSIX_TABLE_OFFSET ... DSA_MSIX_TABLE_OFFSET + VDSA_MSIX_TBL_SZ - 1: {
			int index = (offset - DSA_MSIX_TABLE_OFFSET) / 0x10;
			u8 *msix_entry = &bar0->msix_table[index];
			memcpy(msix_entry + (offset & 0x0f), buf, size);
			/* check mask and pba */
			if ((msix_entry[12] & 1) == 0 &&
					(bar0->msix_pba & (1ULL << index))) {
				bar0->msix_pba &= ~(1ull << index);
				vdsa_send_interrupt(vdsa, index);
			}
			break;
		}
	}

	return 0;
}

static void vdcm_vdsa_remove(struct vdcm_dsa *vdsa)
{
	int i;

	printk("vdcm_vdsa_remove %d\n", vdsa->id);

	for (i = 0; i < vdsa->num_wqs; i++)
		dsa_wq_free(vdsa->wqs[i]);

	vdsa_free_ims_entries(vdsa);

	mutex_lock(&mdev_list_lock);
	list_del(&vdsa->next);
	mutex_unlock(&mdev_list_lock);

	kfree(vdsa);
}

static void vdcm_vdsa_reset(struct vdcm_dsa *vdsa)
{
	printk("vdcm_vdsa_reset %d\n", vdsa->id);
}

static const struct vdsa_ops dsa_ops = {
	.emulate_cfg_read       = vdcm_vdsa_cfg_read,
	.emulate_cfg_write      = vdcm_vdsa_cfg_write,
	.emulate_mmio_read      = vdcm_vdsa_mmio_read,
	.emulate_mmio_write     = vdcm_vdsa_mmio_write,

        .vdsa_create            = vdcm_vdsa_create,
        .vdsa_destroy           = vdcm_vdsa_remove,
	.vdsa_reset             = vdcm_vdsa_reset,
};

/* helper macros copied from vfio-pci */
#define VFIO_PCI_OFFSET_SHIFT   40
#define VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index) ((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK    (((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

struct vfio_region {
	u32				type;
	u32				subtype;
	size_t				size;
	u32				flags;
};

struct kvmdsa_guest_info {
	struct kvm *kvm;
	struct vdcm_dsa *vdsa;
	/* other necessary guest dsa driver related info */
};

static inline bool handle_valid(unsigned long handle)
{
	return !!(handle & ~0xff);
}


static void vdcm_dsa_release_work(struct work_struct *work);
static int kvmdsa_guest_init(struct mdev_device *mdev);
static bool kvmdsa_guest_exit(unsigned long handle);

struct vdcm_dsa_type mdev_types[DSA_MDEV_TYPES];

static struct attribute_group *dsa_mdev_type_groups[] = {
		[0 ... DSA_MDEV_TYPES-1] = NULL,
};

static struct vdcm_dsa_type *vdcm_dsa_find_vdsa_type(struct dsadma_device *dsa,
		const char *name)
{
	int i;

	for (i = 0; i < DSA_MDEV_TYPES; i++) {
		if (!strncmp(name, mdev_types[i].name, DSA_MDEV_NAME_LEN))
			return &mdev_types[i];
	}

	return NULL;
}

static ssize_t
dsa_dev_show(struct device *dev, struct device_attribute *attr,
		char *buf)
{
	return sprintf(buf, "Data Streaming Accelerator (DSA)\n");
}

static DEVICE_ATTR_RO(dsa_dev);

static struct attribute *dsa_dev_attrs[] = {
        &dev_attr_dsa_dev.attr,
        NULL,
};

static const struct attribute_group dsa_dev_group = {
        .name  = "dsa_dev",
        .attrs = dsa_dev_attrs,
};

const struct attribute_group *dsa_dev_groups[] = {
        &dsa_dev_group,
        NULL,
};

static ssize_t
name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	int i;

	for (i = 0; i < DSA_MDEV_TYPES; i++) {
		if (!strcmp(kobj->name, mdev_types[i].name))
			return sprintf(buf, "%s\n", mdev_types[i].description);
	}

	return -EINVAL;
}

MDEV_TYPE_ATTR_RO(name);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	int i;
	int dwqs = 0, swqs = 0;
	struct vdcm_dsa *vdsa;
	struct dsadma_device *dsa = dev_get_drvdata(dev);

	for (i = 0; i < DSA_MDEV_TYPES; i++) {
		if (!strcmp(kobj->name, mdev_types[i].name))
			break;
	}

	if (i == DSA_MDEV_TYPES)
		return -EINVAL;

	list_for_each_entry(vdsa, &dsa_mdevs_list, next) {
		for (i = 0; i < vdsa->num_wqs; i++) {
			if (vdsa->wqs[i]->dedicated)
				dwqs += 1;
			else
				swqs += 1;
		}
	}

	switch (mdev_types[i].type) {
		case DSA_MDEV_TYPE_1_DWQ_0_SWQ:
			return sprintf(buf, "%d\n", (dsa->num_dwqs - dwqs));
		case DSA_MDEV_TYPE_0_DWQ_1_SWQ:
			return sprintf(buf, "%d\n", (dsa->virt_swqs - swqs));
	}
	return -EINVAL;
}

MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
		char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}

MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *dsa_mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static bool vdcm_dsa_init_type_groups(struct dsadma_device *dsa)
{
	int i, j;
	struct vdcm_dsa_type *type;
	struct attribute_group *group;
	struct device *dev = &dsa->pdev->dev;

	for (i = 0; i < DSA_MDEV_TYPES; i++) {
		type = &mdev_types[i];

		group = kzalloc(sizeof(struct attribute_group), GFP_KERNEL);
		if (WARN_ON(!group))
			goto unwind;

		switch (i) {
			case DSA_MDEV_TYPE_1_DWQ_0_SWQ:
				sprintf(type->name, "%s-%s",
					dev_driver_string(dev), "1dwq");
				strncpy(type->description,
					"DSA MDEV w/ 1 dedicated work queue",
					DSA_MDEV_DESCRIPTION_LEN);
				type->type = i;
				group->name = "1dwq";
			break;
			case DSA_MDEV_TYPE_0_DWQ_1_SWQ:
				sprintf(type->name, "%s-%s",
					dev_driver_string(dev), "1swq");
				strncpy(type->description,
					"DSA MDEV w/ 1 shared work queue",
					DSA_MDEV_DESCRIPTION_LEN);
				type->type = i;
				group->name = "1swq";
			break;
		}
		group->attrs = dsa_mdev_types_attrs;
		dsa_mdev_type_groups[i] = group;
	}

	return true;

unwind:
	for (j = 0; j < i; j++) {
		group = dsa_mdev_type_groups[j];
		kfree(group);
	}

	return false;
}

static void vdcm_dsa_cleanup_type_groups(struct dsadma_device *dsa)
{
	int i;
	struct attribute_group *group;

	for (i = 0; i < DSA_MDEV_TYPES; i++) {
		group = dsa_mdev_type_groups[i];
		kfree(group);
	}
}


static int vdcm_dsa_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct vdcm_dsa *vdsa;
	struct vdcm_dsa_type *type;
	struct device *pdev;
	struct dsadma_device *dsa;
	int ret;

	pdev = mdev_parent_dev(mdev);
	dsa = dev_get_drvdata(pdev);

	type = vdcm_dsa_find_vdsa_type(dsa, kobject_name(kobj));
	if (!type) {
		pr_err("failed to find type %s to create\n",
						kobject_name(kobj));
		ret = -EINVAL;
		goto out;
	}

	vdsa = dsa_ops.vdsa_create(dsa, type);
	if (IS_ERR_OR_NULL(vdsa)) {
		ret = vdsa == NULL ? -EFAULT : PTR_ERR(vdsa);
		pr_err("failed to create intel vdsa: %d\n", ret);
		goto out;
	}

	INIT_WORK(&vdsa->vdev.release_work, vdcm_dsa_release_work);

	vdsa->vdev.mdev = mdev;
	mdev_set_drvdata(mdev, vdsa);

	vdsa->type = type;

	/* allocate and setup IMS entries */
	vdsa_setup_ims_entries(vdsa);

	mutex_lock(&mdev_list_lock);
	list_add(&vdsa->next, &dsa_mdevs_list);
	mutex_unlock(&mdev_list_lock);

	pr_info("vdcm_dsa_create succeeded for mdev: %s\n",
		     dev_name(mdev_dev(mdev)));
	ret = 0;

out:
	return ret;
}

static int vdcm_dsa_remove(struct mdev_device *mdev)
{
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);

	if (handle_valid(vdsa->handle))
		return -EBUSY;

	dsa_ops.vdsa_destroy(vdsa);
	return 0;
}

static int vdcm_dsa_iommu_notifier(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct vdcm_dsa *vdsa = container_of(nb,
					struct vdcm_dsa,
					vdev.iommu_notifier);

	if (action == VFIO_IOMMU_NOTIFY_DMA_UNMAP) {
		struct vfio_iommu_type1_dma_unmap *unmap = data;
		unsigned long gfn, end_gfn;

		gfn = unmap->iova >> PAGE_SHIFT;
		end_gfn = gfn + unmap->size / PAGE_SIZE;
		/*
		while (gfn < end_gfn)
			vdsa_cache_remove(vdsa, gfn++);
		*/
	}

	return NOTIFY_OK;
}

static int vdcm_dsa_group_notifier(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct vdcm_dsa *vdsa = container_of(nb,
					struct vdcm_dsa,
					vdev.group_notifier);

	/* the only action we care about */
	if (action == VFIO_GROUP_NOTIFY_SET_KVM) {
		vdsa->vdev.kvm = data;

		if (!data)
			schedule_work(&vdsa->vdev.release_work);
	}

	return NOTIFY_OK;
}

static int vdcm_dsa_open(struct mdev_device *mdev)
{
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	unsigned long events;
	int ret;

	vdsa->vdev.iommu_notifier.notifier_call = vdcm_dsa_iommu_notifier;
	vdsa->vdev.group_notifier.notifier_call = vdcm_dsa_group_notifier;

	events = VFIO_IOMMU_NOTIFY_DMA_UNMAP;
	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY, &events,
				&vdsa->vdev.iommu_notifier);
	if (ret != 0) {
		pr_err("vfio_register_notifier for iommu failed: %d\n", ret);
		goto out;
	}

	events = VFIO_GROUP_NOTIFY_SET_KVM;
	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY, &events,
				&vdsa->vdev.group_notifier);
	if (ret != 0) {
		pr_err("vfio_register_notifier for group failed: %d\n", ret);
		goto undo_iommu;
	}

	ret = kvmdsa_guest_init(mdev);
	if (ret)
		goto undo_group;

	atomic_set(&vdsa->vdev.released, 0);
	return ret;

undo_group:
	vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
					&vdsa->vdev.group_notifier);

undo_iommu:
	vfio_unregister_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY,
					&vdsa->vdev.iommu_notifier);
out:
	return ret;
}

static void __vdcm_dsa_release(struct vdcm_dsa *vdsa)
{
	int ret;

	if (!handle_valid(vdsa->handle))
		return;

	if (atomic_cmpxchg(&vdsa->vdev.released, 0, 1))
		return;

	ret = vfio_unregister_notifier(mdev_dev(vdsa->vdev.mdev), VFIO_IOMMU_NOTIFY,
					&vdsa->vdev.iommu_notifier);
	WARN(ret, "vfio_unregister_notifier for iommu failed: %d\n", ret);

	ret = vfio_unregister_notifier(mdev_dev(vdsa->vdev.mdev), VFIO_GROUP_NOTIFY,
					&vdsa->vdev.group_notifier);
	WARN(ret, "vfio_unregister_notifier for group failed: %d\n", ret);

	kvmdsa_guest_exit(vdsa->handle);

	vdsa->vdev.kvm = NULL;
	vdsa->handle = 0;
}

static void vdcm_dsa_release(struct mdev_device *mdev)
{
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);

	__vdcm_dsa_release(vdsa);
}

static void vdcm_dsa_release_work(struct work_struct *work)
{
	struct vdcm_dsa *vdsa = container_of(work, struct vdcm_dsa,
					vdev.release_work);

	__vdcm_dsa_release(vdsa);
}

static uint64_t vdcm_dsa_get_bar0_addr(struct vdcm_dsa *vdsa)
{
	u32 start_lo, start_hi;
	u32 mem_type;
	int pos = PCI_BASE_ADDRESS_0;

	start_lo = (*(u32 *)(vdsa->cfg + pos)) &
			PCI_BASE_ADDRESS_MEM_MASK;
	mem_type = (*(u32 *)(vdsa->cfg + pos)) &
			PCI_BASE_ADDRESS_MEM_TYPE_MASK;

	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		start_hi = (*(u32 *)(vdsa->cfg + pos + 4));
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_32:
	case PCI_BASE_ADDRESS_MEM_TYPE_1M:
		/* 1M mem BAR treated as 32-bit BAR */
	default:
		/* mem unknown type treated as 32-bit BAR */
		start_hi = 0;
		break;
	}

	return ((u64)start_hi << 32) | start_lo;
}

static ssize_t vdcm_dsa_rw(struct mdev_device *mdev, char *buf,
			size_t count, loff_t *ppos, bool is_write)
{
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	uint64_t pos = *ppos & VFIO_PCI_OFFSET_MASK;
	int ret = -EINVAL;


	if (index >= VFIO_PCI_NUM_REGIONS) {
		pr_err("invalid index: %u\n", index);
		return -EINVAL;
	}

	switch (index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		if (is_write)
			ret = dsa_ops.emulate_cfg_write(vdsa, pos,
						buf, count);
		else
			ret = dsa_ops.emulate_cfg_read(vdsa, pos,
						buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (is_write) {
			//uint64_t bar0_start = vdcm_dsa_get_bar0_addr(vdsa);

			ret = dsa_ops.emulate_mmio_write(vdsa,
					vdsa->bar_val[0] + pos, buf, count);
		} else {
			//uint64_t bar0_start = vdcm_dsa_get_bar0_addr(vdsa);

			ret = dsa_ops.emulate_mmio_read(vdsa,
					vdsa->bar_val[0] + pos, buf, count);
		}
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
	default:
		pr_err("unsupported region: %u\n", index);
	}

	return ret == 0 ? count : ret;
}

static ssize_t vdcm_dsa_read(struct mdev_device *mdev, char __user *buf,
			size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;

	while (count) {
		size_t filled;

		if (count >= 8 && !(*ppos % 8)) {
			u64 val;

			ret = vdcm_dsa_rw(mdev, (char *)&val, sizeof(val),
					ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 8;
		} else if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			ret = vdcm_dsa_rw(mdev, (char *)&val, sizeof(val),
					ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			ret = vdcm_dsa_rw(mdev, (char *)&val, sizeof(val),
					ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			ret = vdcm_dsa_rw(mdev, &val, sizeof(val), ppos,
					false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;

read_err:
	return -EFAULT;
}

static ssize_t vdcm_dsa_write(struct mdev_device *mdev,
				const char __user *buf,
				size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;

	while (count) {
		size_t filled;

		if (count >= 8 && !(*ppos % 8)) {
			u64 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = vdcm_dsa_rw(mdev, (char *)&val, sizeof(val),
					ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 8;
		} else if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = vdcm_dsa_rw(mdev, (char *)&val, sizeof(val),
					ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = vdcm_dsa_rw(mdev, (char *)&val,
					sizeof(val), ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = vdcm_dsa_rw(mdev, &val, sizeof(val),
					ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
write_err:
	return -EFAULT;
}

static int vdcm_dsa_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	unsigned int index, offset;
	u64 virtaddr;
	unsigned long req_size, pgoff = 0;
	pgprot_t pg_prot;
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	struct dsadma_device *dsa = vdsa->dsa;
	struct dsa_work_queue *wq;
	phys_addr_t base;
	uint32_t priv_offset;

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
	offset = (vma->vm_pgoff << PAGE_SHIFT) & 
				((1ULL << VFIO_PCI_OFFSET_SHIFT) - 1);

	if (index != VFIO_PCI_BAR2_REGION_INDEX)
		return -EINVAL;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	virtaddr = vma->vm_start;
	req_size = vma->vm_end - vma->vm_start;

	if (req_size != PAGE_SIZE) {
		printk("mmap not page size %lx\n", req_size);
		return -EINVAL;
	}

	priv_offset = vdsa->num_wqs * PAGE_SIZE;
	if (offset < priv_offset) {
		/* mapping a non-privileged portal */
		int idx = (offset - VDSA_BAR2_WQ_NP_OFFSET) >> PAGE_SHIFT;
		wq = vdsa->wqs[idx];

		if (wq == NULL) {
			printk("wq null %x\n", offset);
			return -EINVAL;
		}
		base = pci_resource_start(dsa->pdev, DSA_WQ_BAR);
		pgoff = (base + (wq->idx << PAGE_SHIFT)) >> PAGE_SHIFT;
	} else {
		/* mapping a privileged portal to a guest WQ portal */
		int idx = (offset - priv_offset) >> PAGE_SHIFT;
		wq = vdsa->wqs[idx];

		if (wq == NULL) {
			printk("p wq null %x\n", offset);
			return -EINVAL;
		}

		offset = vdsa->ims_index[idx] * dsa->max_wqs + wq->idx;
		base = pci_resource_start(dsa->pdev, DSA_GUEST_WQ_BAR);
		pgoff = (base + (offset << PAGE_SHIFT)) >> PAGE_SHIFT;
	}
	printk("mmap %llx %lx %lx %lx\n", virtaddr, pgoff, req_size, pgprot_val(pg_prot));
	vma->vm_private_data = mdev;
	vma->vm_pgoff = pgoff;
	return remap_pfn_range(vma, virtaddr, pgoff, req_size, pg_prot);
}

static int vdcm_dsa_get_irq_count(struct vdcm_dsa *vdsa, int type)
{
	if (type == VFIO_PCI_MSI_IRQ_INDEX || type == VFIO_PCI_MSIX_IRQ_INDEX) {
		return vdsa->num_wqs + 1;
	}

	return 0;
}

static int vdsa_setup_ims_entry (struct vdcm_dsa *vdsa, int msix_idx)
{

	return 0;
}

static int vdcm_dsa_set_msix_trigger(struct vdcm_dsa *vdsa,
		unsigned int index, unsigned int start, unsigned int count,
		uint32_t flags, void *data)
{
	struct eventfd_ctx *trigger;
	int i, ret = 0;

	if (count == 0 && (flags & VFIO_IRQ_SET_DATA_NONE)) {
		/* Disable all MSIX entries */
		i = 0;
		for (i = 0; i < VDSA_MAX_MSIX_ENTRIES; i++) {
			if (vdsa->vdev.msix_trigger[i]) {
				pr_info("disable MSIX entry %d\n", i);
				eventfd_ctx_put(vdsa->vdev.msix_trigger[i]);
				vdsa->vdev.msix_trigger[i] = 0;

				if (i) {
					ret = vdsa_free_ims_entry(vdsa, i - 1);
					if (ret)
						return ret;
				}
			}
		}
		return 0;
	}

	for (i = 0; i < count; i++) {
		if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
			u32 fd = *(u32 *)(data + i * sizeof(u32));

			pr_info("enable MSIX entry %d\n", i);
			trigger = eventfd_ctx_fdget(fd);
			if (IS_ERR(trigger)) {
				pr_err("eventfd_ctx_fdget failed %d\n", i);
				return PTR_ERR(trigger);
			}
			vdsa->vdev.msix_trigger[i] = trigger;
			/* allocate a vector from the OS and set in the IMS
			 * entry
			 */
			if (i) {
				ret = vdsa_setup_ims_entry(vdsa, i - 1);
				if (ret)
					return ret;
			}
			fd++;
		} else if (flags & VFIO_IRQ_SET_DATA_NONE) {
			pr_info("disable MSIX entry %d\n", i);
			eventfd_ctx_put(vdsa->vdev.msix_trigger[i]);
			vdsa->vdev.msix_trigger[i] = 0;

			if (i) {
				ret = vdsa_free_ims_entry(vdsa, i - 1);
				if (ret)
					return ret;
			}
		}
	}
	return ret;
}

static int vdcm_dsa_set_irqs(struct vdcm_dsa *vdsa, uint32_t flags,
		unsigned int index, unsigned int start, unsigned int count,
		void *data)
{
	int (*func)(struct vdcm_dsa *vdsa, unsigned int index,
			unsigned int start, unsigned int count, uint32_t flags,
			void *data) = NULL;

	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		printk("intx interrupts not supported \n");
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		printk("msi interrupt \n");
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			/* XXX Need masking support exported */
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_dsa_set_msix_trigger;
			break;
		}
		break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			/* XXX Need masking support exported */
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_dsa_set_msix_trigger;
			break;
		}
		break;
	}

	if (!func)
		return -ENOTTY;

	return func(vdsa, index, start, count, flags, data);
}

static long vdcm_dsa_ioctl(struct mdev_device *mdev, unsigned int cmd,
			     unsigned long arg)
{
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);
	unsigned long minsz;

	pr_debug("vdsa %lx ioctl, cmd: %d\n", vdsa->handle, cmd);

	if (cmd == VFIO_DEVICE_GET_INFO) {
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PCI;
		info.flags |= VFIO_DEVICE_FLAGS_RESET;
		info.num_regions = VFIO_PCI_NUM_REGIONS;
		info.num_irqs = VFIO_PCI_NUM_IRQS;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;

	} else if (cmd == VFIO_DEVICE_GET_REGION_INFO) {
		struct vfio_region_info info;
		struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
		int i, ret;
		struct vfio_region_info_cap_sparse_mmap *sparse = NULL;
		size_t size;
		int nr_areas = 1;
		int cap_type_id;
		uint32_t priv_offset;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		switch (info.index) {
		case VFIO_PCI_CONFIG_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = VDSA_MAX_CFG_SPACE_SZ;
			info.flags = VFIO_REGION_INFO_FLAG_READ |
				     VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR0_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = vdsa->bar_size[info.index];
			if (!info.size) {
				info.flags = 0;
				break;
			}

			info.flags = VFIO_REGION_INFO_FLAG_READ |
				     VFIO_REGION_INFO_FLAG_WRITE;
			break;
		case VFIO_PCI_BAR1_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;
			info.flags = 0;
			break;
		case VFIO_PCI_BAR2_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.flags = VFIO_REGION_INFO_FLAG_CAPS |
					VFIO_REGION_INFO_FLAG_MMAP |
					VFIO_REGION_INFO_FLAG_READ |
					VFIO_REGION_INFO_FLAG_WRITE;
			info.size = vdsa->bar_size[1];

			/* Every WQ has two areas for non-privileged and
			 * privileged portals */
			nr_areas = vdsa->num_wqs * 2;

			size = sizeof(*sparse) +
					(nr_areas * sizeof(*sparse->areas));
			sparse = kzalloc(size, GFP_KERNEL);
			if (!sparse)
				return -ENOMEM;

			sparse->nr_areas = nr_areas;
			cap_type_id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;

			priv_offset = vdsa->num_wqs * PAGE_SIZE;
			for (i = 0; i < vdsa->num_wqs; i++) {
				sparse->areas[2 * i].offset = PAGE_SIZE * i;
				sparse->areas[2 * i].size = PAGE_SIZE;

				sparse->areas[2 * i + 1].offset =
					priv_offset + PAGE_SIZE * i;
				sparse->areas[2 * i + 1].size = PAGE_SIZE;
			}
			break;

		case VFIO_PCI_BAR3_REGION_INDEX ... VFIO_PCI_BAR5_REGION_INDEX:
			info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
			info.size = 0;

			info.flags = 0;
			pr_debug("get region info bar:%d\n", info.index);
			break;

		case VFIO_PCI_ROM_REGION_INDEX:
		case VFIO_PCI_VGA_REGION_INDEX:
			pr_debug("get region info index:%d\n", info.index);
			break;
		default:
			{
				struct vfio_region_info_cap_type cap_type;

				if (info.index >= VFIO_PCI_NUM_REGIONS +
						vdsa->vdev.num_regions)
					return -EINVAL;

				i = info.index - VFIO_PCI_NUM_REGIONS;

				info.offset =
					VFIO_PCI_INDEX_TO_OFFSET(info.index);
				info.size = vdsa->vdev.region[i].size;
				info.flags = vdsa->vdev.region[i].flags;

				cap_type.type = vdsa->vdev.region[i].type;
				cap_type.subtype = vdsa->vdev.region[i].subtype;

				ret = vfio_info_add_capability(&caps,
						VFIO_REGION_INFO_CAP_TYPE,
						&cap_type);
				if (ret)
					return ret;
			}
		}

		if ((info.flags & VFIO_REGION_INFO_FLAG_CAPS) && sparse) {
			switch (cap_type_id) {
			case VFIO_REGION_INFO_CAP_SPARSE_MMAP:
				ret = vfio_info_add_capability(&caps,
					VFIO_REGION_INFO_CAP_SPARSE_MMAP,
					sparse);
				kfree(sparse);
				if (ret)
					return ret;
				break;
			default:
				return -EINVAL;
			}
		}

		if (caps.size) {
			if (info.argsz < sizeof(info) + caps.size) {
				info.argsz = sizeof(info) + caps.size;
				info.cap_offset = 0;
			} else {
				vfio_info_cap_shift(&caps, sizeof(info));
				if (copy_to_user((void __user *)arg +
						  sizeof(info), caps.buf,
						  caps.size)) {
					kfree(caps.buf);
					return -EFAULT;
				}
				info.cap_offset = sizeof(info);
			}

			kfree(caps.buf);
		}

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;
	} else if (cmd == VFIO_DEVICE_GET_IRQ_INFO) {
		struct vfio_irq_info info;

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz || info.index >= VFIO_PCI_NUM_IRQS)
			return -EINVAL;

		switch (info.index) {
			case VFIO_PCI_MSI_IRQ_INDEX:
			case VFIO_PCI_MSIX_IRQ_INDEX:
				break;
			default:
				return -EINVAL;
		}

		info.flags = VFIO_IRQ_INFO_EVENTFD;

		info.count = vdcm_dsa_get_irq_count(vdsa, info.index);

		info.flags |= VFIO_IRQ_INFO_NORESIZE;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;
	} else if (cmd == VFIO_DEVICE_SET_IRQS) {
		struct vfio_irq_set hdr;
		u8 *data = NULL;
		int ret = 0;
		size_t data_size = 0;

		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		if (!(hdr.flags & VFIO_IRQ_SET_DATA_NONE)) {
			int max = vdcm_dsa_get_irq_count(vdsa, hdr.index);

			ret = vfio_set_irqs_validate_and_prepare(&hdr, max,
						VFIO_PCI_NUM_IRQS, &data_size);
			if (ret) {
				pr_err("intel:vfio_set_irqs_validate_and_prepare failed\n");
				return -EINVAL;
			}
			if (data_size) {
				data = memdup_user((void __user *)(arg + minsz),
						   data_size);
				if (IS_ERR(data))
					return PTR_ERR(data);
			}
		}

		//pr_info("set_irq_info %x %d %d %d\n", hdr.flags, hdr.index, hdr.start, hdr.count);
		ret = vdcm_dsa_set_irqs(vdsa, hdr.flags, hdr.index,
					hdr.start, hdr.count, data);
		kfree(data);

		return ret;
	} else if (cmd == VFIO_DEVICE_RESET) {
		dsa_ops.vdsa_reset(vdsa);
		return 0;
	}

	return 0;
}

static const struct mdev_parent_ops vdcm_dsa_ops = {
	.supported_type_groups	= dsa_mdev_type_groups,
	.create			= vdcm_dsa_create,
	.remove			= vdcm_dsa_remove,

	.open			= vdcm_dsa_open,
	.release		= vdcm_dsa_release,

	.read			= vdcm_dsa_read,
	.write			= vdcm_dsa_write,
	.mmap			= vdcm_dsa_mmap,
	.ioctl			= vdcm_dsa_ioctl,
};

static int kvmdsa_guest_init(struct mdev_device *mdev)
{
	struct kvmdsa_guest_info *info;
	struct vdcm_dsa *vdsa;
	struct kvm *kvm;

	vdsa = mdev_get_drvdata(mdev);
	if (handle_valid(vdsa->handle))
		return -EEXIST;

	kvm = vdsa->vdev.kvm;
	if (!kvm || kvm->mm != current->mm) {
		pr_err("KVM is required to use Intel vDSA\n");
		return -ESRCH;
	}

	info = vzalloc(sizeof(struct kvmdsa_guest_info));
	if (!info)
		return -ENOMEM;

	vdsa->handle = (unsigned long)info;
	info->vdsa = vdsa;
	info->kvm = kvm;

	/* FIXME: Setup Scalable IOV IOMMU for translation */

	return 0;
}

static bool kvmdsa_guest_exit(unsigned long handle)
{
	if (handle == 0) {
		pr_err("kvmdsa_guest_info invalid\n");
		return false;
	}

	vfree((void*)handle);

	return true;
}

int dsa_host_init(struct dsadma_device *dsa)
{
	struct device *dev = &dsa->pdev->dev;

	if (!vdcm_dsa_init_type_groups(dsa))
		return -EFAULT;

	mutex_init(&mdev_list_lock);
	INIT_LIST_HEAD(&dsa_mdevs_list);

	return mdev_register_device(dev, &vdcm_dsa_ops);
}

void dsa_host_exit(struct dsadma_device *dsa)
{
	struct device *dev = &dsa->pdev->dev;

	mdev_unregister_device(dev);

	vdcm_dsa_cleanup_type_groups(dsa);
}

