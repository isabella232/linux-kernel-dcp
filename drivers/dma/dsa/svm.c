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

static const struct file_operations dsa_fops = {
	.owner          = THIS_MODULE,
	.open           = dsa_fops_open,
	.release        = dsa_fops_release,
	//.read           = dsa_fops_read,
	//.write          = dsa_fops_write,
	.unlocked_ioctl = dsa_fops_unl_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl   = dsa_fops_compat_ioctl,
#endif
	.mmap           = dsa_fops_mmap,
	//.poll           = dsa_fops_poll,
};

int dsa_usr_add(struct dsadma_device *dsa)
{
	int rc;
	struct miscdevice *mdev;

	mdev = &dsa->misc_dev;
	mdev->minor = MISC_DYNAMIC_MINOR;
	snprintf(dsa->user_name, sizeof(dsa->user_name), "%s%d",
			"dsa", dsa->index);
	mdev->name = dsa->user_name;
	mdev->nodename = dsa->user_name;
	mdev->fops = &dsa_fops;
	mdev->mode = S_IRUGO | S_IWUGO;

	rc = misc_register(mdev);
	if (rc)
		dev_err(&dsa->pdev->dev, "%s failed rc %d\n", __func__, rc);

        printk("registered DSA user interface\n");

	return rc;
}

static void dsa_set_pasid_msr(int pasid)
{
	uint32_t val = (1 << 31) | pasid;

	wrmsr(IA32_PASID_MSR, val, 0);
}

static void dsa_disable_pasid_msr(void)
{
	uint32_t val = 0;

	wrmsr(IA32_PASID_MSR, val, 0);
}

int dsa_fops_open(struct inode *inode, struct file *filep)
{
        struct dsa_context *ctx;

        ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
        if (!ctx)
                return -ENOMEM;

        INIT_LIST_HEAD(&ctx->mm_list);
        INIT_LIST_HEAD(&ctx->wq_list);

	ctx->dsa = get_dsadma_device_by_minor(iminor(inode));
	ctx->wq_idx = DSA_WQ_UNALLOCATED;
        filep->private_data = ctx;

	printk("opened a user context\n");
        return 0;
}

int dsa_ctx_drain_pasid (struct dsa_context *ctx, bool abort)
{
	union dsa_command_reg reg;
	struct dsadma_device *dsa = ctx->dsa;
	int i;

	memset(&reg, 0, sizeof(union dsa_command_reg));

	printk("draining pasid %d %d\n", ctx->pasid, abort);
	spin_lock(&dsa->cmd_lock);

	reg.fields.operand = ctx->pasid;
	reg.fields.cmd = DRAIN_PASID;
	reg.fields.abort = abort;
	writel(reg.val, dsa->reg_base + DSA_CMD_OFFSET);

	/* wait for completion */
	for (i = 0; i < DRAIN_CMD_TIMEOUT; i++) {
		mdelay(1);
		reg.val = readl(dsa->reg_base + DSA_CMD_OFFSET);
		if (reg.fields.status == 0)
			break;
	}
	spin_unlock(&dsa->cmd_lock);

	if (i == DRAIN_CMD_TIMEOUT) {
		printk("drain pasid time out %d\n", ctx->pasid);
		/* FIXME: the device likely needs reset to recover from this */
		return 1;
	}

	return 0;
}

int dsa_fops_release(struct inode *inode, struct file *filep)
{
        struct dsa_context *ctx = filep->private_data;

        filep->private_data = NULL;

	if (ctx->svm_dev) {
		dsa_ctx_drain_pasid(ctx, 1);

		intel_svm_unbind_mm(ctx->svm_dev, ctx->pasid);
		put_task_struct(ctx->tsk);
	}
	if (ctx->wq_idx != DSA_WQ_UNALLOCATED) {
		struct dsa_work_queue *wq = &ctx->dsa->wqs[ctx->wq_idx];
		if (wq->dedicated) {
			if (dsa_wq_disable_pasid(ctx->dsa, ctx->wq_idx))
				printk("disable_pasid failed\n");
		} else {
			dsa_disable_pasid_msr();
		}
		wq->available = 1;
		wq->allocated = 0;
	}


	printk("closed the user context\n");
        return 0;
}

static int dsa_ioctl_completion_wait(struct dsa_context *ctx, unsigned long arg)
{


	return 0;
}

static void dsa_svm_fault_cb(struct device *dev, int pasid, u64 addr,
                              u32 private, int rwxp, int response)
{

	printk("page fault: pasid %x addr %llx priv %x rwxp %x resp %d\n",
			pasid, addr, private, rwxp, response);
}

static struct svm_dev_ops dsa_svm_ops = {
	.fault_cb = dsa_svm_fault_cb,
};

static int dsa_ioctl_submit_desc (struct dsa_context *ctx, unsigned long arg)
{
	struct dsa_submit_desc_req req;
	void __user *argp = (void __user *)arg;
	struct dsadma_device *dsa = ctx->dsa;
	struct dsa_completion_ring *dring;
	struct dsa_work_queue *wq;
	void __iomem * wq_reg;
	int ret = 0;

	if ((ret = copy_from_user(&req, argp, sizeof(req)))) {
		printk("ioctl SUBMIT_DESC: copy_from_user failed: %d\n", ret);
		return -EFAULT;
	}

	if (req.wq_idx >= dsa->num_wqs || ctx->wq_idx != req.wq_idx)
		return -EINVAL;

	req.desc.pasid = ctx->pasid;
	req.desc.u_s = 0;

	wq = &dsa->wqs[req.wq_idx];

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);

	wq_reg = dsa_get_wq_reg(wq->dsa, wq->idx, dring->idx, 1);
	printk("submit_desc: wq %d reg %p src %llx\n", wq->idx, wq_reg, req.desc.src_addr);

	if (dsa_enqcmds(&req.desc, wq_reg))
		return -ENOSPC;

	return ret;
}

static int dsa_ioctl_wq_alloc (struct dsa_context *ctx, unsigned long arg)
{
	struct dsa_wq_alloc_req req;
	void __user *argp = (void __user *)arg;
	struct dsadma_device *dsa = ctx->dsa;
	struct dsa_work_queue *wq;
	struct dsa_completion_ring *dring;
	int i, ret = 0;

	if (dsa->num_wqs == 0)
		return -ENODEV;

	if ((ret = copy_from_user(&req, argp, sizeof(req)))) {
		printk("ioctl WQ_ALLOC: copy_from_user failed: %d\n", ret);
		return -EFAULT;
	}

	printk("wq_alloc: searching wq ded %d\n", req.dedicated);

	/* FIXME: Use proper locks to provide mutual exclusion b/w processes */
	for (i = 0; i < dsa->num_wqs; i++) {
		wq = &ctx->dsa->wqs[i];
		if (req.dedicated == wq->dedicated && wq->available)
			break;
	}

	/* FIXME: lock to make sure DMA API doesn't use this DWQ anymore */
	if (i == dsa->num_wqs)
		return -ENODEV;

	printk("wq_alloc: wq %d dedicated %d\n", wq->idx, wq->dedicated);
	ctx->wq_idx = wq->idx;

	init_waitqueue_head(&ctx->intr_queue);

	dring = dsa_get_completion_ring(wq->dsa, wq->idx);

	/* reserve the interrupt for this wq */
	dring->wq = wq;

	/* Allocate and bind a PASID */
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

	/* If dedicated queue, configure PASID into WQ PASID register */
	if (wq->dedicated) {
		wq->available = 0;
		wq->allocated = 1;
		ret = dsa_wq_set_pasid(dsa, ctx->wq_idx, ctx->pasid, 0);
		if (ret)
			printk("set_pasid failed\n");
		req.size = wq->wq_size;
	} else {
		req.size = 0;
		dsa_set_pasid_msr(ctx->pasid);
	}
	/* FIXME: return appropriate capabilities to the user client */
	req.gencap = dsa->gencap & DSA_CAP_USER_MASK;
	req.opcap = dsa->opcap;
	req.wq_idx = wq->idx;

	if ((ret = copy_to_user(argp, &req, sizeof(req)))) {
		printk("ioctl WQ_ALLOC: copy_to_user failed: %d\n", ret);
		return -EFAULT;
	}

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

	printk("dsa ioctl cmd %x\n", cmd);
        switch (cmd) {
        case DSA_IOCTL_WQ_ALLOC:
                ret = dsa_ioctl_wq_alloc(ctx, arg);
                break;
        case DSA_IOCTL_COMPLETION_WAIT:
                ret = dsa_ioctl_completion_wait(ctx, arg);
                break;
        case DSA_IOCTL_SUBMIT_DESC:
                ret = dsa_ioctl_submit_desc(ctx, arg);
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

	/* the vma should be at most a 4K page size */
	BUG_ON((vma->vm_end - vma->vm_start) > PAGE_SIZE);

	pfn = (base + (ctx->wq_idx << PAGE_SHIFT)) >> PAGE_SHIFT;

	printk("dsa page fault pfn vaadr %lx %lx\n", vma->vm_start, pfn);
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
	struct dsadma_device *dsa = ctx->dsa;
	struct pci_dev *dev = dsa->pdev;
	unsigned long pfn;
	phys_addr_t base = pci_resource_start(dev, DSA_WQ_BAR);
	int ret;

	/* the vma should be at most a 4K page size */
	BUG_ON((vma->vm_end - vma->vm_start) > PAGE_SIZE);

	vma->vm_flags |= VM_DONTCOPY;

	pfn = (base + (ctx->wq_idx << PAGE_SHIFT)) >> PAGE_SHIFT;

	printk("dsa_fops_mmap %lx %lx %lx prot %lx\n", vma->vm_start, vma->vm_end, pfn, vma->vm_page_prot.pgprot);
	ret = io_remap_pfn_range(vma, vma->vm_start, pfn, PAGE_SIZE, vma->vm_page_prot);

	return ret;
}

/*
unsigned int dsa_fops_poll(struct file *file, poll_table * wait)
{
	unsigned int mask = 0;
	struct dsa_context *ctx = (struct dsa_context *)file->private_data;

	poll_wait(file, &ctx->intr_queue, wait);

	if (ctx->err > 0)
		mask = POLLERR;

	return mask;
}
*/
