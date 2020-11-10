// SPDX-License-Identifier: GPL-2.0-only
/*
 * IO Address Space ID limiting controller for cgroups.
 *
 */
#define pr_fmt(fmt)	"ioasids_cg: " fmt

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/ioasid.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>

#define IOASIDS_MAX_STR "max"
static DEFINE_MUTEX(ioasids_cg_lock);

struct ioasids_cgroup {
	struct cgroup_subsys_state	css;
	atomic64_t			counter;
	atomic64_t			limit;
	struct cgroup_file		events_file;
	/* Number of times allocations failed because limit was hit. */
	atomic64_t			events_limit;
};

static struct ioasids_cgroup *css_ioasids(struct cgroup_subsys_state *css)
{
	return container_of(css, struct ioasids_cgroup, css);
}

static struct ioasids_cgroup *parent_ioasids(struct ioasids_cgroup *ioasids)
{
	return css_ioasids(ioasids->css.parent);
}

static struct cgroup_subsys_state *
ioasids_css_alloc(struct cgroup_subsys_state *parent)
{
	struct ioasids_cgroup *ioasids;

	ioasids = kzalloc(sizeof(struct ioasids_cgroup), GFP_KERNEL);
	if (!ioasids)
		return ERR_PTR(-ENOMEM);

	atomic64_set(&ioasids->counter, 0);
	atomic64_set(&ioasids->limit, 0);
	atomic64_set(&ioasids->events_limit, 0);
	return &ioasids->css;
}

static void ioasids_css_free(struct cgroup_subsys_state *css)
{
	kfree(css_ioasids(css));
}

/**
 * ioasids_cancel - uncharge the local IOASID count
 * @ioasids: the ioasid cgroup state
 * @num: the number of ioasids to cancel
 *
 */
static void ioasids_cancel(struct ioasids_cgroup *ioasids, int num)
{
	WARN_ON_ONCE(atomic64_add_negative(-num, &ioasids->counter));
}

/**
 * ioasids_uncharge - hierarchically uncharge the ioasid count
 * @ioasids: the ioasid cgroup state
 * @num: the number of ioasids to uncharge
 */
static void ioasids_uncharge(struct ioasids_cgroup *ioasids, int num)
{
	struct ioasids_cgroup *p;

	for (p = ioasids; parent_ioasids(p); p = parent_ioasids(p))
		ioasids_cancel(p, num);
}

/**
 * ioasids_charge - hierarchically charge the ioasid count
 * @ioasids: the ioasid cgroup state
 * @num: the number of ioasids to charge
 */
static void ioasids_charge(struct ioasids_cgroup *ioasids, int num)
{
	struct ioasids_cgroup *p;

	for (p = ioasids; parent_ioasids(p); p = parent_ioasids(p))
		atomic64_add(num, &p->counter);
}

/**
 * ioasids_try_charge - hierarchically try to charge the ioasid count
 * @ioasids: the ioasid cgroup state
 * @num: the number of ioasids to charge
 */
static int ioasids_try_charge(struct ioasids_cgroup *ioasids, int num)
{
	struct ioasids_cgroup *p, *q;

	for (p = ioasids; parent_ioasids(p); p = parent_ioasids(p)) {
		int64_t new = atomic64_add_return(num, &p->counter);
		int64_t limit = atomic64_read(&p->limit);

		if (new > limit)
			goto revert;
	}

	return 0;

revert:
	for (q = ioasids; q != p; q = parent_ioasids(q))
		ioasids_cancel(q, num);
	ioasids_cancel(p, num);
	cgroup_file_notify(&ioasids->events_file);

	return -EAGAIN;
}


/**
 * ioasid_cg_charge - Check and charge IOASIDs cgroup
 *
 * @set: IOASID set used for allocation
 *
 * The IOASID quota is managed per cgroup, all process based allocations
 * must be validated per cgroup hierarchy.
 * Return 0 if a single IOASID can be allocated or error if failed in various
 * checks.
 */
int ioasid_cg_charge(struct ioasid_set *set)
{
	struct mm_struct *mm = get_task_mm(current);
	struct cgroup_subsys_state *css;
	struct ioasids_cgroup *ioasids;
	int ret = 0;

	/* Must be called with a valid mm, not during process exit */
	if (set->type != IOASID_SET_TYPE_MM)
		return ret;
	if (!mm)
		return -EINVAL;
	/* We only charge user process allocated PASIDs */
	if (set->type != IOASID_SET_TYPE_MM) {
		ret = -EINVAL;
		goto exit_drop;
	}
	if (set->token != mm) {
		pr_err("No permisson to allocate IOASID\n");
		ret = -EPERM;
		goto exit_drop;
	}
	rcu_read_lock();
	css = task_css(current, ioasids_cgrp_id);
	ioasids = css_ioasids(css);
	rcu_read_unlock();
	ret = ioasids_try_charge(ioasids, 1);
	if (ret)
		pr_warn("%s: Unable to charge IOASID %d\n", __func__, ret);
exit_drop:
	mmput_async(mm);
	return ret;
}
EXPORT_SYMBOL_GPL(ioasid_cg_charge);

/* Uncharge IOASIDs cgroup after freeing an IOASID */
void ioasid_cg_uncharge(struct ioasid_set *set)
{
	struct cgroup_subsys_state *css;
	struct ioasids_cgroup *ioasids;
	struct mm_struct *mm;

	/* We only charge user process allocated PASIDs */
	if (set->type != IOASID_SET_TYPE_MM)
		return;
	mm = set->token;
	if (!mmget_not_zero(mm)) {
		pr_err("MM defunct! Cannot uncharge IOASID\n");
		return;
	}
	rcu_read_lock();
	css = task_css(current, ioasids_cgrp_id);
	ioasids = css_ioasids(css);
	rcu_read_unlock();
	ioasids_uncharge(ioasids, 1);
	mmput_async(mm);
}
EXPORT_SYMBOL_GPL(ioasid_cg_uncharge);

static int ioasids_can_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *dst_css;
	static struct ioasid_set *set;
	struct task_struct *leader;

	/*
	 * IOASIDs are managed at per process level, we only support domain mode
	 * in task management model. Loop through all processes by each thread
	 * leader, charge the leader's css.
	 */
	cgroup_taskset_for_each_leader(leader, dst_css, tset) {
		struct ioasids_cgroup *ioasids = css_ioasids(dst_css);
		struct cgroup_subsys_state *old_css;
		struct ioasids_cgroup *old_ioasids;
		struct mm_struct *mm = get_task_mm(leader);

		set = ioasid_find_mm_set(mm);
		mmput(mm);
		if (!set)
			continue;

		old_css = task_css(leader, ioasids_cgrp_id);
		old_ioasids = css_ioasids(old_css);

		ioasids_charge(ioasids, atomic_read(&set->nr_ioasids));
		ioasids_uncharge(old_ioasids, atomic_read(&set->nr_ioasids));
	}

	return 0;
}

static void ioasids_cancel_attach(struct cgroup_taskset *tset)
{
	struct cgroup_subsys_state *dst_css;
	struct task_struct *task;

	cgroup_taskset_for_each(task, dst_css, tset) {
		struct ioasids_cgroup *ioasids = css_ioasids(dst_css);
		struct cgroup_subsys_state *old_css;
		struct ioasids_cgroup *old_ioasids;

		old_css = task_css(task, ioasids_cgrp_id);
		old_ioasids = css_ioasids(old_css);

		ioasids_charge(old_ioasids, 1);
		ioasids_uncharge(ioasids, 1);
	}
}

static ssize_t ioasids_max_write(struct kernfs_open_file *of, char *buf,
			      size_t nbytes, loff_t off)
{
	struct cgroup_subsys_state *css = of_css(of);
	struct ioasids_cgroup *ioasids = css_ioasids(css);
	int64_t limit, limit_cur;
	int err;

	mutex_lock(&ioasids_cg_lock);
	/* Check whether we are growing or shrinking */
	limit_cur = atomic64_read(&ioasids->limit);
	buf = strstrip(buf);
	if (!strcmp(buf, IOASIDS_MAX_STR)) {
		/* Returns how many IOASIDs was in the pool */
		limit = ioasid_reserve_capacity(0);
		ioasid_reserve_capacity(limit - limit_cur);
		goto set_limit;
	}
	err = kstrtoll(buf, 0, &limit);
	if (err)
		goto done_unlock;

	err = nbytes;
	/* Check whether we are growing or shrinking */
	limit_cur = atomic64_read(&ioasids->limit);
	if (limit < 0 || limit == limit_cur) {
		err = -EINVAL;
		goto done_unlock;
	}
	if (limit < limit_cur)
		err = ioasid_cancel_capacity(limit_cur - limit);
	else
		err = ioasid_reserve_capacity(limit - limit_cur);
	if (err < 0)
		goto done_unlock;

set_limit:
	err = nbytes;
	atomic64_set(&ioasids->limit, limit);
done_unlock:
	mutex_unlock(&ioasids_cg_lock);
	return err;
}

static int ioasids_max_show(struct seq_file *sf, void *v)
{
	struct cgroup_subsys_state *css = seq_css(sf);
	struct ioasids_cgroup *ioasids = css_ioasids(css);
	int64_t limit = atomic64_read(&ioasids->limit);

	seq_printf(sf, "%lld\n", limit);

	return 0;
}

static s64 ioasids_current_read(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	struct ioasids_cgroup *ioasids = css_ioasids(css);

	return atomic64_read(&ioasids->counter);
}

static int ioasids_events_show(struct seq_file *sf, void *v)
{
	struct ioasids_cgroup *ioasids = css_ioasids(seq_css(sf));

	seq_printf(sf, "max %lld\n", (s64)atomic64_read(&ioasids->events_limit));
	return 0;
}

static struct cftype ioasids_files[] = {
	{
		.name = "max",
		.write = ioasids_max_write,
		.seq_show = ioasids_max_show,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "current",
		.read_s64 = ioasids_current_read,
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{
		.name = "events",
		.seq_show = ioasids_events_show,
		.file_offset = offsetof(struct ioasids_cgroup, events_file),
		.flags = CFTYPE_NOT_ON_ROOT,
	},
	{ }	/* terminate */
};

struct cgroup_subsys ioasids_cgrp_subsys = {
	.css_alloc	= ioasids_css_alloc,
	.css_free	= ioasids_css_free,
	.can_attach	= ioasids_can_attach,
	.cancel_attach	= ioasids_cancel_attach,
	.legacy_cftypes	= ioasids_files,
	.dfl_cftypes	= ioasids_files,
	.threaded	= false,
};

