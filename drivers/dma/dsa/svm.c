#include <linux/init.h>
#include <linux/compat.h>
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
#include <linux/intel-svm.h>
#include "dma.h"
#include "registers.h"
#include "hw.h"
#include "svm.h"
#include "dsa_ioctl.h"

#define DSA_WQ_UNALLOCATED  (-1)

int dsa_fops_open(struct inode *inode, struct file *filep)
{
        struct dsa_context *ctx;

        ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
        if (!ctx)
                return -ENOMEM;

        INIT_LIST_HEAD(&ctx->mm_list);
        INIT_LIST_HEAD(&ctx->wq_list);

	ctx->dsa = get_dsadma_device();
	ctx->wq_idx = DSA_WQ_UNALLOCATED;
        filep->private_data = ctx;

	printk("opened a user context\n");
        return 0;
}

int dsa_fops_release(struct inode *inode, struct file *filep)
{
        struct dsa_context *ctx = filep->private_data;

        filep->private_data = NULL;

	if (ctx->wq_idx != DSA_WQ_UNALLOCATED) {
		struct dsa_work_queue *wq = &ctx->dsa->wqs[ctx->wq_idx];
		wq->available = 1;
		wq->allocated = 0;
	}

	if (ctx->svm_dev) {
		intel_svm_unbind_mm(ctx->svm_dev, ctx->pasid);
		put_task_struct(current);
	}
	printk("closed a user context\n");
        return 0;
}

static int dsa_ioctl_completion_wait(struct dsa_context *ctx, unsigned long arg)
{


	return 0;
}

static void dsa_svm_fault_cb(struct device *dev, int pasid, u64 addr,
                              u32 private, int rwxp, int response)
{

	printk("page fault: pasid %x addr %llx %x\n", pasid, addr, rwxp);
}

static struct svm_dev_ops dsa_svm_ops = {
	.fault_cb = dsa_svm_fault_cb,
};

static int dsa_ioctl_wq_alloc (struct dsa_context *ctx, unsigned long arg)
{
	struct dsa_wq_alloc_req req;
	void __user *argp = (void __user *)arg;
	struct dsadma_device *dsa = ctx->dsa;
	struct dsa_work_queue *wq;
	struct dsa_completion_ring *dring;
	int i, ret;

	if (dsa->num_wqs == 0)
		return -ENODEV;

	if ((ret = copy_from_user(&req, argp, sizeof(req))) != 0) {
		printk("ioctl WQ_ALLOC: copy_from_user failed: %d\n", ret);
		return -EFAULT;
	}

	printk("wq_alloc: searching wq ded %d\n", req.dedicated);
	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &ctx->dsa->wqs[i];
		if (req.dedicated == wq->dedicated && wq->available)
			break;
	}

	/* FIXME: lock to make sure DMA API doesn't use this DWQ anymore */
	if (i == dsa->num_wqs)
		return -ENODEV;

	printk("wq_alloc: wq %d dedicated %d\n", wq->idx, wq->dedicated);
	wq->available = 0;
	wq->allocated = 1;
	ctx->wq_idx = wq->idx;

	init_waitqueue_head(&ctx->intr_queue);

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);

	/* reserve the interrupt for this wq */
	dring->wq = wq;

	/* FIXME: Allocate a PASID and if dedicated queue, configure it into
	 * WQ PASID register */
	ctx->svm_dev = &dsa->pdev->dev;
	ctx->tsk = current;
	get_task_struct(current);

	printk("calling bind mm\n");
	ret = intel_svm_bind_mm(ctx->svm_dev, &ctx->pasid, 0, &dsa_svm_ops);
	if (ret) {
		printk("pasid alloc fail: %d\n", ret);
		ctx->svm_dev = NULL;
		ctx->tsk = NULL;
		put_task_struct(current);
		goto error_pasid;
	}

	printk("pasid %d\n", ctx->pasid);

	return 0;
error_pasid:
	return ret;
}

long dsa_fops_unl_ioctl(struct file *filep,
                                unsigned int cmd, unsigned long arg)
{
        struct dsa_context *ctx = filep->private_data;
        long ret = -EINVAL;

        if (!ctx)
                return ret;

	printk("dsa ioctl cmd %x %lx \n", cmd, DSA_IOCTL_WQ_ALLOC);
        switch (cmd) {
        case DSA_IOCTL_WQ_ALLOC:
                ret = dsa_ioctl_wq_alloc(ctx, arg);
                break;
        case DSA_IOCTL_COMPLETION_WAIT:
                ret = dsa_ioctl_completion_wait(ctx, arg);
                break;
        default:
		break;
        }

        return ret;
}

#ifdef CONFIG_COMPAT
long dsa_fops_compat_ioctl(struct file *filep,
                                   unsigned int cmd, unsigned long arg)
{
        arg = (unsigned long)compat_ptr(arg);
        return dsa_fops_unl_ioctl(filep, cmd, arg);
}
#endif  /* CONFIG_COMPAT */

static int dsa_wq_reg_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct dsa_context *ctx = vma->vm_private_data;
	struct dsadma_device *dsa = ctx->dsa;
	struct pci_dev *dev = dsa->pdev;
	unsigned long pfn;
	phys_addr_t base = pci_resource_start(dev, DSA_WQ_BAR);
	int ret;

	printk("dsa page fault\n");
	/* the vma should be at most a 4K page size */
	BUG_ON((vma->vm_end - vma->vm_start) > PAGE_SIZE);

	pfn = (base + (ctx->wq_idx << PAGE_SHIFT)) >> PAGE_SHIFT;

	ret = vm_insert_pfn(vma, vma->vm_start, pfn);

	if (ret == -ENOMEM)
		return VM_FAULT_SIGBUS;

	/* err == -EBUSY is fine, we've raced against another thread
	 * that faulted-in the same page
	 */
	if (ret != -EBUSY)
		BUG_ON(ret);

	return VM_FAULT_NOPAGE;
}

static const struct vm_operations_struct dsa_vm_ops = {
        .fault  = dsa_wq_reg_fault,
};

int dsa_fops_mmap(struct file *filep, struct vm_area_struct *vma)
{
        struct dsa_context *ctx = filep->private_data;

	vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_ops= &dsa_vm_ops;
	vma->vm_private_data = ctx;

	return 0;
}

unsigned int dsa_fops_poll(struct file *file, poll_table * wait)
{
	unsigned int mask = 0;
	struct dsa_context *ctx = (struct dsa_context *)file->private_data;

	poll_wait(file, &ctx->intr_queue, wait);

	if (ctx->err > 0)
		mask = POLLERR;

	return mask;
}

