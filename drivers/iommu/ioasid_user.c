// SPDX-License-Identifier: GPL-2.0-only
/*
 * Support IOASID allocation/free from user space.
 *
 * Copyright (C) 2021 Intel Corporation.
 *     Author: Liu Yi L <yi.l.liu@intel.com>
 *
 */

#include <linux/ioasid.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched/mm.h>
#include <linux/miscdevice.h>

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Liu Yi L <yi.l.liu@intel.com>"
#define DRIVER_DESC     "IOASID management for user space"

/* Current user ioasid uapi supports 31 bits */
#define IOASID_BITS	31

struct ioasid_user_token {
	unsigned long long val;
};

struct ioasid_user {
	struct kref		kref;
	struct ioasid_set	*ioasid_set;
	struct mutex		lock;
	struct list_head	next;
	struct ioasid_user_token	token;
};

static struct mutex		ioasid_user_lock;
static struct list_head		ioasid_user_list;

/* called with ioasid_user_lock held */
static void ioasid_user_release(struct kref *kref)
{
	struct ioasid_user *iuser = container_of(kref, struct ioasid_user, kref);

	ioasid_free_all_in_set(iuser->ioasid_set);
	list_del(&iuser->next);
	mutex_unlock(&ioasid_user_lock);
	ioasid_set_free(iuser->ioasid_set);
	kfree(iuser);
}

void ioasid_user_put(struct ioasid_user *iuser)
{
	kref_put_mutex(&iuser->kref, ioasid_user_release, &ioasid_user_lock);
}
EXPORT_SYMBOL_GPL(ioasid_user_put);

static void ioasid_user_get(struct ioasid_user *iuser)
{
	kref_get(&iuser->kref);
}

struct ioasid_user *ioasid_user_get_from_task(struct task_struct *task)
{
	struct mm_struct *mm = get_task_mm(task);
	unsigned long long val = (unsigned long long)mm;
	struct ioasid_user *iuser;
	bool found = false;

	if (!mm)
		return NULL;

	mutex_lock(&ioasid_user_lock);
	/* Search existing ioasid_user with current mm pointer */
	list_for_each_entry(iuser, &ioasid_user_list, next) {
		if (iuser->token.val == val) {
			ioasid_user_get(iuser);
			found = true;
			break;
		}
	}

	mmput(mm);

	mutex_unlock(&ioasid_user_lock);
	return found ? iuser : NULL;
}
EXPORT_SYMBOL_GPL(ioasid_user_get_from_task);

void ioasid_user_for_each_id(struct ioasid_user *iuser, void *data,
			    void (*fn)(ioasid_t id, void *data))
{
	mutex_lock(&iuser->lock);
	ioasid_set_for_each_ioasid(iuser->ioasid_set, fn, data);
	mutex_unlock(&iuser->lock);
}
EXPORT_SYMBOL_GPL(ioasid_user_for_each_id);

static int ioasid_fops_open(struct inode *inode, struct file *filep)
{
	struct mm_struct *mm = get_task_mm(current);
	unsigned long long val = (unsigned long long)mm;
	struct ioasid_set *iset;
	struct ioasid_user *iuser;
	int ret = 0;

	mutex_lock(&ioasid_user_lock);
	/* Only allow one single open per process */
	list_for_each_entry(iuser, &ioasid_user_list, next) {
		if (iuser->token.val == val) {
			ret = -EBUSY;
			goto out;
		}
	}

	iuser = kzalloc(sizeof(*iuser), GFP_KERNEL);
	if (!iuser) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * IOASID core provides a 'IOASID set' concept to track all
	 * IOASIDs associated with a token. Here we use mm_struct as
	 * the token and create a IOASID set per mm_struct. All the
	 * containers of the process share the same IOASID set.
	 */
	iset = ioasid_set_alloc(mm, 0, IOASID_SET_TYPE_MM);
	if (IS_ERR(iset)) {
		kfree(iuser);
		ret = PTR_ERR(iset);
		goto out;
	}

	iuser->ioasid_set = iset;
	kref_init(&iuser->kref);
	iuser->token.val = val;
	mutex_init(&iuser->lock);
	filep->private_data = iuser;

	list_add(&iuser->next, &ioasid_user_list);
out:
	mutex_unlock(&ioasid_user_lock);
	mmput(mm);
	return ret;
}

static int ioasid_fops_release(struct inode *inode, struct file *filep)
{
	struct ioasid_user *iuser = filep->private_data;

	filep->private_data = NULL;

	ioasid_user_put(iuser);

	return 0;
}

static int ioasid_get_info(struct ioasid_user *iuser, unsigned long arg)
{
	struct ioasid_info info;
	unsigned long minsz;

	minsz = offsetofend(struct ioasid_info, ioasid_bits);

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz || info.flags)
		return -EINVAL;

	info.ioasid_bits = IOASID_BITS;

	return copy_to_user((void __user *)arg, &info, minsz) ? -EFAULT : 0;
}

static int ioasid_alloc_request(struct ioasid_user *iuser, unsigned long arg)
{
	struct ioasid_alloc_request req;
	unsigned long minsz;
	ioasid_t ioasid;

	minsz = offsetofend(struct ioasid_alloc_request, range);

	if (copy_from_user(&req, (void __user *)arg, minsz))
		return -EFAULT;

	if (req.argsz < minsz || req.flags)
		return -EINVAL;

	if (req.range.min > req.range.max ||
	    req.range.min >= (1 << IOASID_BITS) ||
	    req.range.max >= (1 << IOASID_BITS))
		return -EINVAL;

	ioasid = ioasid_alloc(iuser->ioasid_set, req.range.min,
			    req.range.max, NULL);

	if (ioasid == INVALID_IOASID)
		return -EINVAL;

	return ioasid;

}

static int ioasid_free_request(struct ioasid_user *iuser, unsigned long arg)
{
	int ioasid;

	if (copy_from_user(&ioasid, (void __user *)arg, sizeof(ioasid)))
		return -EFAULT;

	if (ioasid < 0)
		return -EINVAL;

	ioasid_free(iuser->ioasid_set, ioasid);

	return 0;
}

static long ioasid_fops_unl_ioctl(struct file *filep,
				  unsigned int cmd, unsigned long arg)
{
	struct ioasid_user *iuser = filep->private_data;
	long ret = -EINVAL;

	if (!iuser)
		return ret;

	mutex_lock(&iuser->lock);

	switch (cmd) {
	case IOASID_GET_API_VERSION:
		ret = IOASID_API_VERSION;
		break;
	case IOASID_GET_INFO:
		ret = ioasid_get_info(iuser, arg);
		break;
	case IOASID_REQUEST_ALLOC:
		ret = ioasid_alloc_request(iuser, arg);
		break;
	case IOASID_REQUEST_FREE:
		ret = ioasid_free_request(iuser, arg);
		break;
	default:
		pr_err("Unsupported cmd %u\n", cmd);
		break;
	}

	mutex_unlock(&iuser->lock);
	return ret;
}

static const struct file_operations ioasid_user_fops = {
	.owner		= THIS_MODULE,
	.open		= ioasid_fops_open,
	.release	= ioasid_fops_release,
	.unlocked_ioctl	= ioasid_fops_unl_ioctl,
};

static struct miscdevice ioasid_user = {
	.minor = IOASID_MINOR,
	.name = "ioasid_user",
	.fops = &ioasid_user_fops,
	.nodename = "ioasid",
	.mode = S_IRUGO | S_IWUGO,
};


static int __init ioasid_user_init(void)
{
	int ret;

	ret = misc_register(&ioasid_user);
	if (ret) {
		pr_err("ioasid_user: misc device register failed\n");
		return ret;
	}

	mutex_init(&ioasid_user_lock);
	INIT_LIST_HEAD(&ioasid_user_list);
	return 0;
}

static void __exit ioasid_user_exit(void)
{
	WARN_ON(!list_empty(&ioasid_user_list));
	misc_deregister(&ioasid_user);
}

module_init(ioasid_user_init);
module_exit(ioasid_user_exit);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
