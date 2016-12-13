#ifndef __DSA_SVM_H__
#define __DSA_SVM_H__

struct dsa_context {
        int user_handle;
        int pasid; /* 20 bits */
#ifdef CONFIG_INTEL_IOMMU_SVM
        struct device *svm_dev;
#endif
	struct dsadma_device *dsa;
	int wq_idx;
        int flags;
        struct list_head mm_list;
        struct list_head wq_list;
        struct task_struct *tsk;
	wait_queue_head_t intr_queue;
	int err;
};

int dsa_fops_open(struct inode *inode, struct file *filep);
int dsa_fops_release(struct inode *inode, struct file *filep);
long dsa_fops_unl_ioctl(struct file *filep,
			unsigned int cmd, unsigned long arg);
long dsa_fops_compat_ioctl(struct file *filep,
			unsigned int cmd, unsigned long arg);
int dsa_fops_mmap(struct file *filep, struct vm_area_struct *vma);
unsigned int dsa_fops_poll(struct file *file, poll_table * wait);

#endif
