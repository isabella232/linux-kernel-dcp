#define DEBUG
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
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
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/iommu.h>

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
/* For testing page response by guest */
struct mm_struct *tmm;
struct iommu_domain *tdomain;


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
	else
	        printk("registered DSA user interface\n");

	return rc;
}

static void dsa_set_pasid_msr(int pasid)
{
	uint32_t val = (1 << 31) | pasid;

	wrmsr(MSR_IA32_PASID, val, 0);
}

static void dsa_disable_pasid_msr(void)
{
	uint32_t val = 0;

	wrmsr(MSR_IA32_PASID, val, 0);
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

	return dsa_drain_pasid(ctx->dsa, ctx->pasid, abort);
}

int dsa_drain_pasid (struct dsadma_device *dsa, int pasid, bool abort)
{
	union dsa_command_reg reg;
	u32 cmdsts;
	int i;

	memset(&reg, 0, sizeof(union dsa_command_reg));

	printk("draining pasid %d %d\n", pasid, abort);
	spin_lock(&dsa->cmd_lock);

	reg.fields.operand = pasid;
	if (abort)
		reg.fields.cmd = DSA_ABORT_PASID;
	else
		reg.fields.cmd = DSA_DRAIN_PASID;
	writel(reg.val, dsa->reg_base + DSA_CMD_OFFSET);

	/* wait for completion */
	for (i = 0; i < DRAIN_CMD_TIMEOUT; i++) {
		mdelay(1);
		cmdsts = readl(dsa->reg_base + DSA_CMDSTS_OFFSET);
		if (!(cmdsts & DSA_CMD_ACTIVE))
			break;
	}
	spin_unlock(&dsa->cmd_lock);
	printk("drained pasid %d %d\n", pasid, abort);

	if (i == DRAIN_CMD_TIMEOUT) {
		printk("drain pasid time out %d\n", pasid);
		/* FIXME: the device likely needs reset to recover from this */
		return 1;
	}

	return 0;
}
struct workqueue_struct *dsa_fwq; /* Reporting IOMMU fault to device */


int dsa_fops_release(struct inode *inode, struct file *filep)
{
        struct dsa_context *ctx = filep->private_data;

        filep->private_data = NULL;

	if (ctx->svm_dev) {
		dsa_ctx_drain_pasid(ctx, 1);
		iommu_domain_free(tdomain);
//		destroy_workqueue(dsa_fwq);
		dsa_fwq = NULL;
		printk("DSA fault workqueue destroyed\n");

		iommu_unregister_device_fault_handler(ctx->svm_dev);
		intel_svm_unbind_mm(ctx->svm_dev, ctx->pasid);
		put_task_struct(ctx->tsk);
		tmm = NULL;
	}
	if (ctx->wq_idx != DSA_WQ_UNALLOCATED) {
		struct dsa_work_queue *wq = &ctx->dsa->wqs[ctx->wq_idx];
		if (wq->dedicated) {
			if (dsa_wq_disable_pasid(ctx->dsa, ctx->wq_idx))
				printk("disable_pasid failed\n");
		} else {
			dsa_disable_pasid_msr();
		}
		dsa_wq_free(wq);
	}


	printk("closed the user context\n");
        return 0;
}

static int dsa_ioctl_completion_wait(struct dsa_context *ctx, unsigned long arg)
{


	return 0;
}

static int dsa_ioctl_submit_desc (struct dsa_context *ctx, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	struct dsa_dma_descriptor desc;
	int ret = 0;

	if ((ret = copy_from_user(&desc, argp, sizeof(desc)))) {
		printk("ioctl SUBMIT_DESC: copy_from_user failed: %d\n", ret);
		return -EFAULT;
	}

	desc.pasid = ctx->pasid;
	desc.u_s = 0;

	printk("submit_desc: reg %p src %llx\n", ctx->wq_reg, desc.src_addr);

	if (dsa_enqcmds(&desc, ctx->wq_reg))
		return -ENOSPC;

	return ret;
}

static void prq_response(struct work_struct *work)
{
	struct dsa_fault_ctx *ctx;

	ctx = container_of(work, struct dsa_fault_ctx, dwork.work);

	pr_debug("PRQ resp gid %d\n", ctx->msg.page_req_group_id);
	iommu_page_response(ctx->dev, &ctx->msg);
	pr_debug("PRQ resp gid done %d\n", ctx->msg.page_req_group_id);

	kfree(ctx);
}

static int dsa_queue_page_response(struct dsadma_device *dsa,
				struct page_response_msg *msg)
{
	int ret;
	struct dsa_fault_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), GFP_ATOMIC);
	if (!ctx)
		return -ENOMEM;
	ctx->msg = *msg;
	ctx->dev = &dsa->pdev->dev;
	dev_dbg(&dsa->pdev->dev, "Pages faulted in, send response\n");
	INIT_DELAYED_WORK(&ctx->dwork, prq_response);
	schedule_delayed_work(&ctx->dwork, 10);
	dev_dbg(&dsa->pdev->dev, "Page response queued\n");
	ret = IOMMU_PAGE_RESP_HANDLED;
	return ret;
}

static int dsa_iommu_fault_handler(struct iommu_fault_event *event, void *data)
{
       struct dsadma_device *dsa = data;
       int ret = 0;
       struct vm_area_struct *vma;
       struct page_response_msg msg;

       dev_dbg(&dsa->pdev->dev,
               "DSA PRQ reported: type %d, addr %llx, pasid %d, prot %x, last %d\n",
               event->type, event->addr, event->pasid, event->prot, event->last_req);

       /* prepare page response */
       if (!tmm) {
	       dev_err(&dsa->pdev->dev, "No mm to handle page response\n");
	       return -EINVAL;
       }

       if (!mmget_not_zero(tmm)) {
	       pr_err("prq test mm is defunct, no response\n");
	       return -ENOENT;
       }

       pr_debug("prepare to handle mm %p\n", tmm);

       down_read(&tmm->mmap_sem);
       vma = find_extend_vma(tmm, event->addr);
       if (!vma || event->addr < vma->vm_start) {
	       pr_debug("invalid vma %p\n", vma);
	       ret = -EINVAL;
	       if (vma)
		       pr_debug("vm_start: 0x%lx\n", vma->vm_start);
	       goto invalid;
       }
       /* fault in pages as if done by the guest */
       ret = handle_mm_fault(vma, event->addr,
		       (event->prot & IOMMU_FAULT_WRITE) ? FAULT_FLAG_WRITE : 0);
       if (ret & VM_FAULT_ERROR) {
	       dev_err(&dsa->pdev->dev, "Failed handle mm fault\n");
	       msg.resp_code = IOMMU_PAGE_RESP_INVALID;
       } else
	       msg.resp_code = IOMMU_PAGE_RESP_SUCCESS;
       if (event->last_req) {
	       /* compose response message */
	       msg.addr = event->addr;
	       msg.pasid = event->pasid;
	       msg.pasid_present = 1;
	       msg.page_req_group_id = event->page_req_group_id;
	       ret = dsa_queue_page_response(dsa, &msg);
#if 0
	       pr_debug("PRQ resp gid %d\n", msg.page_req_group_id);
	       return iommu_page_response(&dsa->pdev->dev, &msg);
	       pr_debug("PRQ resp gid %d done\n", msg.page_req_group_id);
#endif
	       /* Tell IOMMU driver no need to respond */
       }
invalid:
       up_read(&tmm->mmap_sem);
       mmput(tmm);

       return ret;
}

static int dsa_ioctl_wq_alloc (struct dsa_context *ctx, unsigned long arg)
{
	struct dsa_wq_alloc_req req;
	void __user *argp = (void __user *)arg;
	struct dsadma_device *dsa = ctx->dsa;
	struct dsa_work_queue *wq;
	struct dsa_irq_entry *irq_entry;
	int ret = 0;
	u16 msix_idx;

	if ((ret = copy_from_user(&req, argp, sizeof(req)))) {
		printk("ioctl WQ_ALLOC: copy_from_user failed: %d\n", ret);
		return -EFAULT;
	}

	wq = dsa_wq_alloc (dsa, req.dedicated);

	if (wq == NULL)
		return -ENODEV;

	printk("wq_alloc: wq %d dedicated %d\n", wq->idx, wq->dedicated);
	ctx->wq_idx = wq->idx;

	/* Allocate and bind a PASID */
	ctx->svm_dev = &dsa->pdev->dev;
	ctx->tsk = current;

	printk("create test domain\n");
	tdomain = iommu_domain_alloc(&pci_bus_type);
	if (!tdomain) {
		pr_err("alloc domain failed\n");
		return -ENODEV;
	}
	ret = iommu_attach_device(tdomain, ctx->svm_dev);
	if (ret) {
		dev_err(ctx->svm_dev, "attach device failed ret %d", ret);
		iommu_domain_free(tdomain);
		return ret;
	}

	printk("calling bind mm\n");
	ret = intel_svm_bind_mm(ctx->svm_dev, &ctx->pasid, 0);
	if (ret) {
		printk("pasid alloc fail: %d\n", ret);
		ctx->svm_dev = NULL;
		ctx->tsk = NULL;
		put_task_struct(current);
		goto error_pasid;
	}
	dsa_fwq = alloc_ordered_workqueue("dsa_fwq", 0);
	printk("DSA fault workqueue allocated\n");
	iommu_register_device_fault_handler(ctx->svm_dev,
					dsa_iommu_fault_handler, dsa);

	printk("pasid %d\n", ctx->pasid);
	tmm = get_task_mm(current);
	printk("record mm of svm_bind_mm %p\n", tmm);

	/* allocate an interrupt for this wq */
	/* FIXME: save this somewhere? */
	msix_idx = dsa_get_msix_index(dsa);

	irq_entry = &dsa->irq_entries[msix_idx];

	dsa_setup_irq_event(&ctx->ev, irq_entry, NULL, NULL);

	ctx->wq_reg = dsa->wq_reg_base +
		dsa_get_wq_portal_offset(wq->idx, false, false);

	/* If dedicated queue, configure the PASID into WQ PASID register, else
	 * configure the PASID in MSR_IA_PASID */
	if (wq->dedicated) {
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
	req.gencap |= (wq->max_xfer_bits << DSA_CAP_MAX_XFER_SHIFT) &
				DSA_CAP_MAX_XFER_MASK;
	req.gencap |= (wq->max_batch_bits << DSA_CAP_MAX_BATCH_SHIFT) &
			DSA_CAP_MAX_BATCH_MASK;

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

static int dsa_wq_reg_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct dsa_context *ctx = vma->vm_private_data;
	struct dsadma_device *dsa = ctx->dsa;
	struct pci_dev *dev = dsa->pdev;
	unsigned long pfn;
	phys_addr_t base = pci_resource_start(dev, DSA_WQ_BAR);
	int ret;

	/* the vma should be at most a 4K page size */
	BUG_ON((vma->vm_end - vma->vm_start) > PAGE_SIZE);

	pfn = (base + dsa_get_wq_portal_offset(ctx->wq_idx, false, true))
					>> PAGE_SHIFT;

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

	pfn = (base + dsa_get_wq_portal_offset(ctx->wq_idx, false, true))
					>> PAGE_SHIFT;

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
