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
bool ioasid_put(struct ioasid_set *set, ioasid_t ioasid);
bool ioasid_put_locked(struct ioasid_set *set, ioasid_t ioasid);
void ioasid_free(struct ioasid_set *set, ioasid_t ioasid);
void *ioasid_find(struct ioasid_set *set, ioasid_t ioasid,
		  bool (*getter)(void *));
int ioasid_register_allocator(struct ioasid_allocator_ops *allocator);
void ioasid_unregister_allocator(struct ioasid_allocator_ops *allocator);
int ioasid_attach_data(ioasid_t ioasid, void *data);
void ioasid_detach_data(ioasid_t ioasid);
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
#endif /* CONFIG_IOASID */
#endif /* __LINUX_IOASID_H */
