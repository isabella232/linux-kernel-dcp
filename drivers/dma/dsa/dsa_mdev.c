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
#include <linux/mdev.h>

#include "dma.h"
/************* BELOW CODE NEED MOVE TO HEADER FILE **********************/

/* VDCM model, should move to dsa_vdcm.h */
struct vdcm_dsa_type {
	char name[16];
	unsigned int avail_instance;
};

#define VDSA_MAX_CFG_SPACE_SZ 256
#define VDSA_MAX_BAR_NUM 4

struct vdcm_dsa_pci_bar {
	u64 size;
	bool tracked;
};

struct vdcm_dsa_cfg_space {
	unsigned char virtual_cfg_space[VDSA_MAX_CFG_SPACE_SZ];
	struct vdcm_dsa_pci_bar bar[VDSA_MAX_BAR_NUM];
};

/* VDCM model, should move to dsa_vdcm.h */
struct vdcm_dsa {
	unsigned long handle;
	u64 pasid[8];
	u64 bar0_offset;
	u64 bar0_size;
	u64 bar1_offset;
	u64 bar1_size;
	u64 bar2_offset;	/* guest bar2 mapping to host bar4 */
	u64 bar2_size;		/* guest bar2 mapping to host bar4 */
	struct vdcm_dsa_cfg_space cfg_space;
	/* ... */

	struct {
		struct mdev_device *mdev;
		struct vfio_region *region;
		int num_regions;
		struct eventfd_ctx *intx_trigger;
		struct eventfd_ctx *msi_trigger;
		struct rb_root cache;
		struct mutex cache_lock;
		struct notifier_block iommu_notifier;
		struct notifier_block group_notifier;
		struct kvm *kvm;
		struct work_struct release_work;
		atomic_t released;
	} vdev;
};

/* VDCM model, should move to dsa_vdcm.h */
struct vdsa_ops {
	int (*emulate_cfg_read)(struct vdcm_dsa *, unsigned int, void *,
				unsigned int);
	int (*emulate_cfg_write)(struct vdcm_dsa *, unsigned int, void *,
				unsigned int);
	int (*emulate_mmio_read)(struct vdcm_dsa *, u64, void *,
				unsigned int);
	int (*emulate_mmio_write)(struct vdcm_dsa *, u64, void *,
				unsigned int);
	struct vdcm_dsa *(*vdsa_create) (struct vdcm_dsa_type *);
	void (*vdsa_destroy)(struct vdcm_dsa *);
	void (*vdsa_reset)(struct vdcm_dsa *);
};

/* VDCM model, should move to dsa_vdcm.h */
static inline struct vdcm_dsa *kdev_to_dsa(struct device *kdev)
{
	/* container_of(dev, struct dsadma_device, vdsa); */
	return dev_get_drvdata(kdev);
}

/************* ABOVE CODE NEED MOVE TO HEADER FILE **********************/

static const struct vdsa_ops *dsa_ops;

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

#define NR_TYPES 2
static struct attribute_group *vdcm_dsa_type_groups[] = {
	[0 ... NR_TYPES -1] = NULL,
};


static void vdcm_dsa_release_work(struct work_struct *work);
static int kvmdsa_guest_init(struct mdev_device *mdev);
static bool kvmdsa_guest_exit(unsigned long handle);

static struct vdcm_dsa_type *vdcm_dsa_find_vdsa_type(struct dsadma_device *dsa,
		const char *name)
{
	int i;
	struct vdcm_dsa_type *t;
	const char *driver_name = dev_driver_string(
			&dsa->pdev->dev);

	for (i = 0; i < NR_TYPES; i++) {
		/* TODO: Get types from DSA */
		BUG();

		if (!strncmp(t->name, name + strlen(driver_name) + 1,
			sizeof(t->name)))
			return t;
	}

	return NULL;
}

static ssize_t available_instances_show(struct kobject *kobj,
					struct device *dev, char *buf)
{
	struct vdcm_dsa_type *type;
	unsigned int num = 0;
	void *dsa = kdev_to_dsa(dev);

	type = vdcm_dsa_find_vdsa_type(dsa, kobject_name(kobj));
	if (!type)
		num = 0;
	else
		num = type->avail_instance;

	return sprintf(buf, "%u\n", num);
}

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
		char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}

static ssize_t description_show(struct kobject *kobj, struct device *dev,
		char *buf)
{
	struct vdcm_dsa_type *type;
	void *dsa = kdev_to_dsa(dev);

	type = vdcm_dsa_find_vdsa_type(dsa, kobject_name(kobj));
	if (!type)
		return 0;

	return sprintf(buf, "%s\n", type->name);
}

static MDEV_TYPE_ATTR_RO(available_instances);
static MDEV_TYPE_ATTR_RO(device_api);
static MDEV_TYPE_ATTR_RO(description);

static struct attribute *type_attrs[] = {
	&mdev_type_attr_available_instances.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_description.attr,
	NULL,
};

static bool vdcm_dsa_init_type_groups(struct dsadma_device *dsa)
{
	int i, j;
	struct vdcm_dsa_type *type;
	struct attribute_group *group;

	for (i = 0; i < NR_TYPES; i++) {
		dsa = dsa;

		/*TODO: initial type from DSA */
		BUG();

		group = kzalloc(sizeof(struct attribute_group), GFP_KERNEL);
		if (WARN_ON(!group))
			goto unwind;

		group->name = type->name;
		group->attrs = type_attrs;
		vdcm_dsa_type_groups[i] = group;
	}

	return true;

unwind:
	for (j = 0; j < i; j++) {
		group = vdcm_dsa_type_groups[j];
		kfree(group);
	}

	return false;
}

static void vdcm_dsa_cleanup_type_groups(struct dsadma_device *dsa)
{
	int i;
	struct attribute_group *group;

	for (i = 0; i < NR_TYPES; i++) {
		group = vdcm_dsa_type_groups[i];
		kfree(group);
	}
}


static int vdcm_dsa_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct vdcm_dsa *vdsa;
	struct vdcm_dsa_type *type;
	struct device *pdev;
	void *dsa;
	int ret;

	pdev = mdev_parent_dev(mdev);
	dsa = kdev_to_dsa(pdev);

	type = vdcm_dsa_find_vdsa_type(dsa, kobject_name(kobj));
	if (!type) {
		pr_err("failed to find type %s to create\n",
						kobject_name(kobj));
		ret = -EINVAL;
		goto out;
	}

	vdsa = dsa_ops->vdsa_create(type);
	if (IS_ERR_OR_NULL(vdsa)) {
		ret = vdsa == NULL ? -EFAULT : PTR_ERR(vdsa);
		pr_err("failed to create intel vdsa: %d\n", ret);
		goto out;
	}

	INIT_WORK(&vdsa->vdev.release_work, vdcm_dsa_release_work);

	vdsa->vdev.mdev = mdev;
	mdev_set_drvdata(mdev, vdsa);

	pr_debug("vdcm_dsa_create succeeded for mdev: %s\n",
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

	dsa_ops->vdsa_destroy(vdsa);
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

	start_lo = (*(u32 *)(vdsa->cfg_space.virtual_cfg_space + pos)) &
			PCI_BASE_ADDRESS_MEM_MASK;
	mem_type = (*(u32 *)(vdsa->cfg_space.virtual_cfg_space + pos)) &
			PCI_BASE_ADDRESS_MEM_TYPE_MASK;

	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		start_hi = (*(u32 *)(vdsa->cfg_space.virtual_cfg_space
						+ pos + 4));
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
			ret = dsa_ops->emulate_cfg_write(vdsa, pos,
						buf, count);
		else
			ret = dsa_ops->emulate_cfg_read(vdsa, pos,
						buf, count);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR1_REGION_INDEX:
		if (is_write) {
			uint64_t bar0_start = vdcm_dsa_get_bar0_addr(vdsa);

			ret = dsa_ops->emulate_mmio_write(vdsa,
						bar0_start + pos, buf, count);
		} else {
			uint64_t bar0_start = vdcm_dsa_get_bar0_addr(vdsa);

			ret = dsa_ops->emulate_mmio_read(vdsa,
						bar0_start + pos, buf, count);
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

		if (count >= 4 && !(*ppos % 4)) {
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

		if (count >= 4 && !(*ppos % 4)) {
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
	unsigned int index;
	u64 virtaddr;
	unsigned long req_size, pgoff = 0;
	pgprot_t pg_prot;
	struct vdcm_dsa *vdsa = mdev_get_drvdata(mdev);

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);
	if (index >= VFIO_PCI_ROM_REGION_INDEX)
		return -EINVAL;

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	if (index != VFIO_PCI_BAR2_REGION_INDEX)
		return -EINVAL;

	pg_prot = vma->vm_page_prot;
	virtaddr = vma->vm_start;
	req_size = vma->vm_end - vma->vm_start;
	/* TODO: check with DSA driver Guest bar2 mapping to host bar4 offset */
	pgoff = vdsa->bar2_offset >> PAGE_SHIFT;

	return remap_pfn_range(vma, virtaddr, pgoff, req_size, pg_prot);
}

static int vdcm_dsa_get_irq_count(struct vdcm_dsa *vdsa, int type)
{
	if (type == VFIO_PCI_INTX_IRQ_INDEX || type == VFIO_PCI_MSI_IRQ_INDEX)
		return 1;

	return 0;
}

static int vdcm_dsa_set_intx_mask(struct vdcm_dsa *vdsa,
			unsigned int index, unsigned int start,
			unsigned int count, uint32_t flags,
			void *data)
{
	return 0;
}

static int vdcm_dsa_set_intx_unmask(struct vdcm_dsa *vdsa,
			unsigned int index, unsigned int start,
			unsigned int count, uint32_t flags, void *data)
{
	return 0;
}

static int vdcm_dsa_set_intx_trigger(struct vdcm_dsa *vdsa,
		unsigned int index, unsigned int start, unsigned int count,
		uint32_t flags, void *data)
{
	return 0;
}

static int vdcm_dsa_set_msi_trigger(struct vdcm_dsa *vdsa,
		unsigned int index, unsigned int start, unsigned int count,
		uint32_t flags, void *data)
{
	struct eventfd_ctx *trigger;

	if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
		int fd = *(int *)data;

		trigger = eventfd_ctx_fdget(fd);
		if (IS_ERR(trigger)) {
			pr_err("eventfd_ctx_fdget failed\n");
			return PTR_ERR(trigger);
		}
		vdsa->vdev.msi_trigger = trigger;
	}

	return 0;
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
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
			func = vdcm_dsa_set_intx_mask;
			break;
		case VFIO_IRQ_SET_ACTION_UNMASK:
			func = vdcm_dsa_set_intx_unmask;
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_dsa_set_intx_trigger;
			break;
		}
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			/* XXX Need masking support exported */
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			func = vdcm_dsa_set_msi_trigger;
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
			info.size = vdsa->cfg_space.bar[info.index].size;
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
			/*TODO: Get DSA real mapping info here */
			info.size = vdsa->bar2_size;

			size = sizeof(*sparse) +
					(nr_areas * sizeof(*sparse->areas));
			sparse = kzalloc(size, GFP_KERNEL);
			if (!sparse)
				return -ENOMEM;

			sparse->nr_areas = nr_areas;
			cap_type_id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;

			/*TODO: Get DSA real mapping info here */
			sparse->areas[0].offset =
					PAGE_ALIGN(vdsa->bar2_offset);
			sparse->areas[0].size = vdsa->bar2_size;
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
		case VFIO_PCI_INTX_IRQ_INDEX:
		case VFIO_PCI_MSI_IRQ_INDEX:
			break;
		default:
			return -EINVAL;
		}

		info.flags = VFIO_IRQ_INFO_EVENTFD;

		info.count = vdcm_dsa_get_irq_count(vdsa, info.index);

		if (info.index == VFIO_PCI_INTX_IRQ_INDEX)
			info.flags |= (VFIO_IRQ_INFO_MASKABLE |
				       VFIO_IRQ_INFO_AUTOMASKED);
		else
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

		ret = vdcm_dsa_set_irqs(vdsa, hdr.flags, hdr.index,
					hdr.start, hdr.count, data);
		kfree(data);

		return ret;
	} else if (cmd == VFIO_DEVICE_RESET) {
		dsa_ops->vdsa_reset(vdsa);
		return 0;
	}

	return 0;
}

static const struct mdev_parent_ops vdcm_dsa_ops = {
	.supported_type_groups	= vdcm_dsa_type_groups,
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
		pr_err("KVM is required to use Intel vGPU\n");
		return -ESRCH;
	}

	info = vzalloc(sizeof(struct kvmdsa_guest_info));
	if (!info)
		return -ENOMEM;

	vdsa->handle = (unsigned long)info;
	info->vdsa = vdsa;
	info->kvm = kvm;

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

int kvmdsa_host_init(struct device *dev, void *dsa, const void *ops)
{
	if (!vdcm_dsa_init_type_groups(dsa))
		return -EFAULT;

	dsa_ops = ops;

	return mdev_register_device(dev, &vdcm_dsa_ops);
}
EXPORT_SYMBOL_GPL(kvmdsa_host_init);

static void kvmdsa_host_exit(struct device *dev, void *vdsa)
{
	vdcm_dsa_cleanup_type_groups(vdsa);
	mdev_unregister_device(dev);
}
EXPORT_SYMBOL_GPL(kvmdsa_host_exit);

static int __init kvmdsa_init(void)
{
	pr_info("kvmdsa module initialized.\n");
	return 0;
}

static void __exit kvmdsa_exit(void)
{
}

module_init(kvmdsa_init);
module_exit(kvmdsa_exit);

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Intel Corporation");
