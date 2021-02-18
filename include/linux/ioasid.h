/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_IOASID_H
#define __LINUX_IOASID_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/xarray.h>
#include <linux/refcount.h>

#define INVALID_IOASID ((ioasid_t)-1)
typedef unsigned int ioasid_t;
typedef ioasid_t (*ioasid_alloc_fn_t)(ioasid_t min, ioasid_t max, void *data);
typedef void (*ioasid_free_fn_t)(ioasid_t ioasid, void *data);

/* IOASID set types */
enum ioasid_set_type {
	IOASID_SET_TYPE_NULL = 1, /* Set token is NULL */
	IOASID_SET_TYPE_MM,	  /* Set token is a mm_struct pointer
				   * i.e. associated with a process
				   */
	IOASID_SET_TYPE_NR,
};

/**
 * struct ioasid_set - Meta data about ioasid_set
 * @nh:		List of notifiers private to that set
 * @xa:		XArray to store ioasid_set private IDs, can be used for
 *		guest-host IOASID mapping, or just a private IOASID namespace.
 * @token:	Unique to identify an IOASID set
 * @type:	Token types
 * @quota:	Max number of IOASIDs can be allocated within the set
 * @nr_ioasids:	Number of IOASIDs currently allocated in the set
 * @id:		ID of the set
 */
struct ioasid_set {
	struct atomic_notifier_head nh;
	struct xarray xa;
	void *token;
	int type;
	int quota;
	atomic_t nr_ioasids;
	int id;
	struct rcu_head rcu;
};

/**
 * struct ioasid_allocator_ops - IOASID allocator helper functions and data
 *
 * @alloc:	helper function to allocate IOASID
 * @free:	helper function to free IOASID
 * @list:	for tracking ops that share helper functions but not data
 * @pdata:	data belong to the allocator, provided when calling alloc()
 */
struct ioasid_allocator_ops {
	ioasid_alloc_fn_t alloc;
	ioasid_free_fn_t free;
	struct list_head list;
	void *pdata;
};

/* Notification data when IOASID status changed */
enum ioasid_notify_val {
	IOASID_NOTIFY_ALLOC = 1,
	IOASID_NOTIFY_FREE,
	IOASID_NOTIFY_BIND,
	IOASID_NOTIFY_UNBIND,
};

#define IOASID_NOTIFY_FLAG_ALL BIT(0)
#define IOASID_NOTIFY_FLAG_SET BIT(1)
/**
 * enum ioasid_notifier_prios - IOASID event notification order
 *
 * When status of an IOASID changes, users might need to take actions to
 * reflect the new state. For example, when an IOASID is freed due to
 * exception, the hardware context in virtual CPU, DMA device, and IOMMU
 * shall be cleared and drained. Order is required to prevent life cycle
 * problems.
 */
enum ioasid_notifier_prios {
	IOASID_PRIO_LAST,
	IOASID_PRIO_DEVICE,
	IOASID_PRIO_IOMMU,
	IOASID_PRIO_CPU,
};

/**
 * struct ioasid_nb_args - Argument provided by IOASID core when notifier
 * is called.
 * @id:		The IOASID being notified
 * @spid:	The set private ID associated with the IOASID
 * @set:	The IOASID set of @id
 * @pdata:	The private data attached to the IOASID
 */
struct ioasid_nb_args {
	ioasid_t id;
	ioasid_t spid;
	struct ioasid_set *set;
	void *pdata;
};

#if IS_ENABLED(CONFIG_IOASID)
void ioasid_install_capacity(ioasid_t total);
int ioasid_reserve_capacity(ioasid_t nr_ioasid);
int ioasid_cancel_capacity(ioasid_t nr_ioasid);
struct ioasid_set *ioasid_set_alloc(void *token, ioasid_t quota, int type);
int ioasid_set_free(struct ioasid_set *set);
struct ioasid_set *ioasid_find_mm_set(struct mm_struct *token);

ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min, ioasid_t max,
		      void *private);
int ioasid_get(struct ioasid_set *set, ioasid_t ioasid);
int ioasid_get_locked(struct ioasid_set *set, ioasid_t ioasid);
int ioasid_get_if_owned(ioasid_t ioasid);
bool ioasid_put(struct ioasid_set *set, ioasid_t ioasid);
bool ioasid_put_locked(struct ioasid_set *set, ioasid_t ioasid);
void ioasid_free(struct ioasid_set *set, ioasid_t ioasid);
void ioasid_free_all_in_set(struct ioasid_set *set);
void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
		  bool (*getter)(void *));
struct ioasid_set *ioasid_find_set(ioasid_t ioasid);
int ioasid_register_allocator(struct ioasid_allocator_ops *allocator);
void ioasid_unregister_allocator(struct ioasid_allocator_ops *allocator);
int ioasid_attach_data(ioasid_t ioasid, void *data);
void ioasid_detach_data(ioasid_t ioasid);
int ioasid_attach_spid(ioasid_t ioasid, ioasid_t spid);
void ioasid_detach_spid(ioasid_t ioasid);
ioasid_t ioasid_find_by_spid(struct ioasid_set *set, ioasid_t spid, bool get);
int ioasid_register_notifier(struct ioasid_set *set,
			struct notifier_block *nb);
void ioasid_unregister_notifier(struct ioasid_set *set,
				struct notifier_block *nb);
void ioasid_set_for_each_ioasid(struct ioasid_set *sdata,
				void (*fn)(ioasid_t id, void *data),
				void *data);
int ioasid_register_notifier_mm(struct mm_struct *mm, struct notifier_block *nb);
void ioasid_unregister_notifier_mm(struct mm_struct *mm, struct notifier_block *nb);
bool ioasid_queue_work(struct work_struct *work);
#else /* !CONFIG_IOASID */
static inline void ioasid_install_capacity(ioasid_t total)
{
}

static inline int ioasid_reserve_capacity(ioasid_t nr_ioasid)
{
	return -ENOSPC;
}

static inline int ioasid_cancel_capacity(ioasid_t nr_ioasid)
{
	return -EINVAL;
}

static inline ioasid_t ioasid_alloc(struct ioasid_set *set, ioasid_t min,
				    ioasid_t max, void *private)
{
	return INVALID_IOASID;
}

static inline struct ioasid_set *ioasid_set_alloc(void *token, ioasid_t quota,
						  ioasid_set_type type)
{
	return ERR_PTR(-ENOTSUPP);
}

static inline void ioasid_free(struct ioasid_set *set, ioasid_t ioasid)
{
}

static inline struct ioasid_set *ioasid_find_mm_set(struct mm_struct *token)
{
	return NULL;
}

static inline int ioasid_get(struct ioasid_set *set, ioasid_t ioasid)
{
	return -ENOTSUPP;
}

static inline int ioasid_get_locked(struct ioasid_set *set, ioasid_t ioasid)
{
	return -ENOTSUPP;
}

static inline int ioasid_get_if_owned(ioasid_t ioasid)
{
	return -ENOTSUPP;
}

static inline bool ioasid_put(struct ioasid_set *set, ioasid_t ioasid)
{
	return false;
}

static inline bool ioasid_put_locked(struct ioasid_set *set, ioasid_t ioasid)
{
	return false;
}

static inline void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
				bool (*getter)(void *))
{
	return NULL;
}

static inline int ioasid_register_notifier(struct notifier_block *nb)
{
	return -ENOTSUPP;
}

static inline void ioasid_unregister_notifier(struct notifier_block *nb)
{
}

static inline int ioasid_register_allocator(struct ioasid_allocator_ops *allocator)
{
	return -ENOTSUPP;
}

static inline void ioasid_unregister_allocator(struct ioasid_allocator_ops *allocator)
{
}

static inline int ioasid_attach_data(ioasid_t ioasid, void *data)
{
	return -ENOTSUPP;
}

static inline void ioasid_detach_data(ioasid_t ioasid)
{
}

static inline void ioasid_free_all_in_set(struct ioasid_set *set)
{
}

static inline struct ioasid_set *ioasid_find_set(ioasid_t ioasid)
{
	return ERR_PTR(-ENOTSUPP);
}

static inline int ioasid_attach_spid(ioasid_t ioasid, ioasid_t spid)
{
	return -ENOTSUPP;
}

static inline void ioasid_detach_spid(ioasid_t ioasid)
{
}

static inline ioasid_t ioasid_find_by_spid(struct ioasid_set *set,
					   ioasid_t spid, bool get)
{
	return INVALID_IOASID;
}

static inline void ioasid_set_for_each_ioasid(struct ioasid_set *sdata,
					      void (*fn)(ioasid_t id, void *data),
					      void *data)
{
}

static inline int ioasid_register_notifier_mm(struct mm_struct *mm,
					      struct notifier_block *nb)
{
	return -ENOTSUPP;
}

static inline void ioasid_unregister_notifier_mm(struct mm_struct *mm,
						 struct notifier_block *nb)
{
}

static inline bool ioasid_queue_work(struct work_struct *work)
{
	return false;
}
#endif /* CONFIG_IOASID */
#endif /* __LINUX_IOASID_H */
