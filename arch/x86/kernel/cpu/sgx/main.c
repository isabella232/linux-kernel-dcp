// SPDX-License-Identifier: GPL-2.0
/*  Copyright(c) 2016-20 Intel Corporation. */

#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/pagemap.h>
#include <linux/ratelimit.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <asm/sgx.h>
#include "driver.h"
#include "encl.h"
#include "encls.h"

struct sgx_epc_section sgx_epc_sections[SGX_MAX_EPC_SECTIONS];
static int sgx_nr_epc_sections;
static struct task_struct *ksgxd_tsk;
static DECLARE_WAIT_QUEUE_HEAD(ksgxd_waitq);
/*
 * The flags prevents new from using SGX for
 * things like EADD.
 */
static bool __rcu sgx_epc_locked;
/*
 * SRCU ensures that old users that might not
 * have noticed the flag have gone away before
 * proceeding with an SVN update.
 */
DEFINE_SRCU(sgx_lock_epc_srcu);
static DECLARE_WAIT_QUEUE_HEAD(sgx_zap_waitq);
/*
 * This is defined to abort the SGX CPUSVN
 * update process, and must be accessed
 * with sgx_zap_abort_lock.
 */
static bool sgx_zap_abort_wait;
static DEFINE_MUTEX(sgx_zap_abort_lock);
/*
 * Track the number of SECS and VA pages
 * associated with enclaves in releasing.
 * SGX CPUSVN update will wait for them
 * EREMOVEd by enclave exiting process.
 */
static atomic_t zap_waiting_count;

/*
 * These variables are part of the state of the reclaimer, and must be accessed
 * with sgx_reclaimer_lock acquired.
 */
static LIST_HEAD(sgx_active_page_list);
static DEFINE_SPINLOCK(sgx_reclaimer_lock);

/* The free page list lock protected variables prepend the lock. */
static unsigned long sgx_nr_free_pages;

/* Nodes with one or more EPC sections. */
static nodemask_t sgx_numa_mask;

/*
 * Array with one list_head for each possible NUMA node.  Each
 * list contains all the sgx_epc_section's which are on that
 * node.
 */
static struct sgx_numa_node *sgx_numa_nodes;

static LIST_HEAD(sgx_dirty_page_list);

/*
 * Reset post-kexec EPC pages to the uninitialized state. The pages are removed
 * from the input list, and made available for the page allocator. SECS pages
 * prepending their children in the input list are left intact.
 */
static void __sgx_sanitize_pages(struct list_head *dirty_page_list)
{
	struct sgx_epc_page *page;
	LIST_HEAD(dirty);
	int ret;

	/* dirty_page_list is thread-local, no need for a lock: */
	while (!list_empty(dirty_page_list)) {
		if (kthread_should_stop())
			return;

		page = list_first_entry(dirty_page_list, struct sgx_epc_page, list);

		ret = __eremove(sgx_get_epc_virt_addr(page));
		if (!ret) {
			/*
			 * page is now sanitized.  Make it available via the SGX
			 * page allocator:
			 */
			list_del(&page->list);
			sgx_free_epc_page(page);
		} else {
			/* The page is not yet clean - move to the dirty list. */
			list_move_tail(&page->list, &dirty);
		}

		cond_resched();
	}

	list_splice(&dirty, dirty_page_list);
}

static bool sgx_reclaimer_age(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	struct sgx_encl *encl = page->encl;
	struct sgx_encl_mm *encl_mm;
	bool ret = true;
	int idx;

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		mmap_read_lock(encl_mm->mm);
		ret = !sgx_encl_test_and_clear_young(encl_mm->mm, page);
		mmap_read_unlock(encl_mm->mm);

		mmput_async(encl_mm->mm);

		if (!ret)
			break;
	}

	srcu_read_unlock(&encl->srcu, idx);

	if (!ret)
		return false;

	return true;
}

static void sgx_reclaimer_block(struct sgx_epc_page *epc_page)
{
	struct sgx_encl_page *page = epc_page->owner;
	unsigned long addr = page->desc & PAGE_MASK;
	struct sgx_encl *encl = page->encl;
	unsigned long mm_list_version;
	struct sgx_encl_mm *encl_mm;
	struct vm_area_struct *vma;
	int idx, ret;

	do {
		mm_list_version = encl->mm_list_version;

		/* Pairs with smp_rmb() in sgx_encl_mm_add(). */
		smp_rmb();

		idx = srcu_read_lock(&encl->srcu);

		list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
			if (!mmget_not_zero(encl_mm->mm))
				continue;

			mmap_read_lock(encl_mm->mm);

			ret = sgx_encl_find(encl_mm->mm, addr, &vma);
			if (!ret && encl == vma->vm_private_data)
				zap_vma_ptes(vma, addr, PAGE_SIZE);

			mmap_read_unlock(encl_mm->mm);

			mmput_async(encl_mm->mm);
		}

		srcu_read_unlock(&encl->srcu, idx);
	} while (unlikely(encl->mm_list_version != mm_list_version));

	mutex_lock(&encl->lock);

	ret = __eblock(sgx_get_epc_virt_addr(epc_page));
	if (encls_failed(ret))
		ENCLS_WARN(ret, "EBLOCK");

	mutex_unlock(&encl->lock);
}

static int __sgx_encl_ewb(struct sgx_epc_page *epc_page, void *va_slot,
			  struct sgx_backing *backing)
{
	struct sgx_pageinfo pginfo;
	int ret;

	pginfo.addr = 0;
	pginfo.secs = 0;

	pginfo.contents = (unsigned long)kmap_atomic(backing->contents);
	pginfo.metadata = (unsigned long)kmap_atomic(backing->pcmd) +
			  backing->pcmd_offset;

	ret = __ewb(&pginfo, sgx_get_epc_virt_addr(epc_page), va_slot);

	kunmap_atomic((void *)(unsigned long)(pginfo.metadata -
					      backing->pcmd_offset));
	kunmap_atomic((void *)(unsigned long)pginfo.contents);

	return ret;
}

static void sgx_ipi_cb(void *info)
{
}

static const cpumask_t *sgx_encl_cpumask(struct sgx_encl *encl)
{
	cpumask_t *cpumask = &encl->cpumask;
	struct sgx_encl_mm *encl_mm;
	int idx;

	/*
	 * Can race with sgx_encl_mm_add(), but ETRACK has already been
	 * executed, which means that the CPUs running in the new mm will enter
	 * into the enclave with a fresh epoch.
	 */
	cpumask_clear(cpumask);

	idx = srcu_read_lock(&encl->srcu);

	list_for_each_entry_rcu(encl_mm, &encl->mm_list, list) {
		if (!mmget_not_zero(encl_mm->mm))
			continue;

		cpumask_or(cpumask, cpumask, mm_cpumask(encl_mm->mm));

		mmput_async(encl_mm->mm);
	}

	srcu_read_unlock(&encl->srcu, idx);

	return cpumask;
}

/*
 * Swap page to the regular memory transformed to the blocked state by using
 * EBLOCK, which means that it can no longer be referenced (no new TLB entries).
 *
 * The first trial just tries to write the page assuming that some other thread
 * has reset the count for threads inside the enclave by using ETRACK, and
 * previous thread count has been zeroed out. The second trial calls ETRACK
 * before EWB. If that fails we kick all the HW threads out, and then do EWB,
 * which should be guaranteed the succeed.
 */
static void sgx_encl_ewb(struct sgx_epc_page *epc_page,
			 struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_va_page *va_page;
	unsigned int va_offset;
	void *va_slot;
	int ret;

	encl_page->desc &= ~SGX_ENCL_PAGE_BEING_RECLAIMED;

	va_page = list_first_entry(&encl->va_pages, struct sgx_va_page,
				   list);
	va_offset = sgx_alloc_va_slot(va_page);
	va_slot = sgx_get_epc_virt_addr(va_page->epc_page) + va_offset;
	if (sgx_va_page_full(va_page))
		list_move_tail(&va_page->list, &encl->va_pages);

	ret = __sgx_encl_ewb(epc_page, va_slot, backing);
	if (ret == SGX_NOT_TRACKED) {
		ret = __etrack(sgx_get_epc_virt_addr(encl->secs.epc_page));
		if (ret) {
			if (encls_failed(ret))
				ENCLS_WARN(ret, "ETRACK");
		}

		ret = __sgx_encl_ewb(epc_page, va_slot, backing);
		if (ret == SGX_NOT_TRACKED) {
			/*
			 * Slow path, send IPIs to kick cpus out of the
			 * enclave.  Note, it's imperative that the cpu
			 * mask is generated *after* ETRACK, else we'll
			 * miss cpus that entered the enclave between
			 * generating the mask and incrementing epoch.
			 */
			on_each_cpu_mask(sgx_encl_cpumask(encl),
					 sgx_ipi_cb, NULL, 1);
			ret = __sgx_encl_ewb(epc_page, va_slot, backing);
		}
	}

	if (ret) {
		if (encls_failed(ret))
			ENCLS_WARN(ret, "EWB");

		sgx_free_va_slot(va_page, va_offset);
	} else {
		encl_page->desc |= va_offset;
		encl_page->va_page = va_page;
	}
}

static void sgx_reclaimer_write(struct sgx_epc_page *epc_page,
				struct sgx_backing *backing)
{
	struct sgx_encl_page *encl_page = epc_page->owner;
	struct sgx_encl *encl = encl_page->encl;
	struct sgx_backing secs_backing;
	int ret;

	mutex_lock(&encl->lock);

	sgx_encl_ewb(epc_page, backing);
	encl_page->epc_page = NULL;
	encl->secs_child_cnt--;

	if (!encl->secs_child_cnt && test_bit(SGX_ENCL_INITIALIZED, &encl->flags)) {
		ret = sgx_encl_get_backing(encl, PFN_DOWN(encl->size),
					   &secs_backing);
		if (ret)
			goto out;

		sgx_encl_ewb(encl->secs.epc_page, &secs_backing);

		sgx_encl_free_epc_page(encl->secs.epc_page);
		encl->secs.epc_page = NULL;

		sgx_encl_put_backing(&secs_backing, true);
	}

out:
	mutex_unlock(&encl->lock);
}

/*
 * Take a fixed number of pages from the head of the active page pool and
 * reclaim them to the enclave's private shmem files. Skip the pages, which have
 * been accessed since the last scan. Move those pages to the tail of active
 * page pool so that the pages get scanned in LRU like fashion.
 *
 * Batch process a chunk of pages (at the moment 16) in order to degrade amount
 * of IPI's and ETRACK's potentially required. sgx_encl_ewb() does degrade a bit
 * among the HW threads with three stage EWB pipeline (EWB, ETRACK + EWB and IPI
 * + EWB) but not sufficiently. Reclaiming one page at a time would also be
 * problematic as it would increase the lock contention too much, which would
 * halt forward progress.
 */
static void sgx_reclaim_pages(void)
{
	struct sgx_epc_page *chunk[SGX_NR_TO_SCAN];
	struct sgx_backing backing[SGX_NR_TO_SCAN];
	struct sgx_epc_section *section;
	struct sgx_encl_page *encl_page;
	struct sgx_epc_page *epc_page;
	struct sgx_numa_node *node;
	pgoff_t page_index;
	int cnt = 0;
	int ret;
	int i;

	spin_lock(&sgx_reclaimer_lock);
	for (i = 0; i < SGX_NR_TO_SCAN; i++) {
		if (list_empty(&sgx_active_page_list))
			break;

		epc_page = list_first_entry(&sgx_active_page_list,
					    struct sgx_epc_page, list);
		list_del_init(&epc_page->list);
		encl_page = epc_page->owner;

		if (kref_get_unless_zero(&encl_page->encl->refcount) != 0)
			chunk[cnt++] = epc_page;
		else
			/* The owner is freeing the page. No need to add the
			 * page back to the list of reclaimable pages.
			 */
			epc_page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;
	}
	spin_unlock(&sgx_reclaimer_lock);

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		encl_page = epc_page->owner;

		if (!sgx_reclaimer_age(epc_page))
			goto skip;

		page_index = PFN_DOWN(encl_page->desc - encl_page->encl->base);
		ret = sgx_encl_get_backing(encl_page->encl, page_index, &backing[i]);
		if (ret)
			goto skip;

		mutex_lock(&encl_page->encl->lock);
		encl_page->desc |= SGX_ENCL_PAGE_BEING_RECLAIMED;
		mutex_unlock(&encl_page->encl->lock);
		continue;

skip:
		spin_lock(&sgx_reclaimer_lock);
		list_add_tail(&epc_page->list, &sgx_active_page_list);
		spin_unlock(&sgx_reclaimer_lock);

		kref_put(&encl_page->encl->refcount, sgx_encl_release);

		chunk[i] = NULL;
	}

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		if (epc_page)
			sgx_reclaimer_block(epc_page);
	}

	for (i = 0; i < cnt; i++) {
		epc_page = chunk[i];
		if (!epc_page)
			continue;

		encl_page = epc_page->owner;
		sgx_reclaimer_write(epc_page, &backing[i]);
		sgx_encl_put_backing(&backing[i], true);

		kref_put(&encl_page->encl->refcount, sgx_encl_release);
		epc_page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;

		section = &sgx_epc_sections[epc_page->section];
		node = section->node;

		spin_lock(&node->lock);
		list_add_tail(&epc_page->list, &node->free_page_list);
		sgx_nr_free_pages++;
		spin_unlock(&node->lock);
	}
}

static bool sgx_should_reclaim(unsigned long watermark)
{
	return sgx_nr_free_pages < watermark && !list_empty(&sgx_active_page_list);
}

static int ksgxd(void *p)
{
	set_freezable();

	/*
	 * Sanitize pages in order to recover from kexec(). The 2nd pass is
	 * required for SECS pages, whose child pages blocked EREMOVE.
	 */
	__sgx_sanitize_pages(&sgx_dirty_page_list);
	__sgx_sanitize_pages(&sgx_dirty_page_list);

	/* sanity check: */
	WARN_ON(!list_empty(&sgx_dirty_page_list));

	while (!kthread_should_stop()) {
		if (try_to_freeze())
			continue;

		wait_event_freezable(ksgxd_waitq,
				     kthread_should_stop() ||
				     sgx_should_reclaim(SGX_NR_HIGH_PAGES));

		if (sgx_should_reclaim(SGX_NR_HIGH_PAGES))
			sgx_reclaim_pages();

		cond_resched();
	}

	return 0;
}

static bool __init sgx_page_reclaimer_init(void)
{
	struct task_struct *tsk;

	tsk = kthread_run(ksgxd, NULL, "ksgxd");
	if (IS_ERR(tsk))
		return false;

	ksgxd_tsk = tsk;

	return true;
}

static struct sgx_epc_page *__sgx_alloc_epc_page_from_node(int nid)
{
	struct sgx_numa_node *node = &sgx_numa_nodes[nid];
	struct sgx_epc_page *page = NULL;

	spin_lock(&node->lock);

	if (list_empty(&node->free_page_list)) {
		spin_unlock(&node->lock);
		return NULL;
	}

	page = list_first_entry(&node->free_page_list, struct sgx_epc_page, list);
	list_del_init(&page->list);
	sgx_nr_free_pages--;

	spin_unlock(&node->lock);

	return page;
}

/**
 * __sgx_alloc_epc_page() - Allocate an EPC page
 *
 * Iterate through NUMA nodes and reserve ia free EPC page to the caller. Start
 * from the NUMA node, where the caller is executing.
 *
 * Return:
 * - an EPC page:	A borrowed EPC pages were available.
 * - NULL:		Out of EPC pages.
 */
struct sgx_epc_page *__sgx_alloc_epc_page(void)
{
	struct sgx_epc_page *page;
	int nid_of_current = numa_node_id();
	int nid = nid_of_current;

	if (node_isset(nid_of_current, sgx_numa_mask)) {
		page = __sgx_alloc_epc_page_from_node(nid_of_current);
		if (page)
			return page;
	}

	/* Fall back to the non-local NUMA nodes: */
	while (true) {
		nid = next_node_in(nid, sgx_numa_mask);
		if (nid == nid_of_current)
			break;

		page = __sgx_alloc_epc_page_from_node(nid);
		if (page)
			return page;
	}

	return ERR_PTR(-ENOMEM);
}

/**
 * sgx_mark_page_reclaimable() - Mark a page as reclaimable
 * @page:	EPC page
 *
 * Mark a page as reclaimable and add it to the active page list. Pages
 * are automatically removed from the active list when freed.
 */
void sgx_mark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_reclaimer_lock);
	page->flags |= SGX_EPC_PAGE_RECLAIMER_TRACKED;
	list_add_tail(&page->list, &sgx_active_page_list);
	spin_unlock(&sgx_reclaimer_lock);
}

/**
 * sgx_unmark_page_reclaimable() - Remove a page from the reclaim list
 * @page:	EPC page
 *
 * Clear the reclaimable flag and remove the page from the active page list.
 *
 * Return:
 *   0 on success,
 *   -EBUSY if the page is in the process of being reclaimed
 */
int sgx_unmark_page_reclaimable(struct sgx_epc_page *page)
{
	spin_lock(&sgx_reclaimer_lock);
	if (page->flags & SGX_EPC_PAGE_RECLAIMER_TRACKED) {
		/* The page is being reclaimed. */
		if (list_empty(&page->list)) {
			spin_unlock(&sgx_reclaimer_lock);
			return -EBUSY;
		}

		list_del(&page->list);
		page->flags &= ~SGX_EPC_PAGE_RECLAIMER_TRACKED;
	}
	spin_unlock(&sgx_reclaimer_lock);

	return 0;
}

/**
 * sgx_alloc_epc_page() - Allocate an EPC page
 * @owner:	the owner of the EPC page
 * @reclaim:	reclaim pages if necessary
 *
 * Iterate through EPC sections and borrow a free EPC page to the caller. When a
 * page is no longer needed it must be released with sgx_free_epc_page(). If
 * @reclaim is set to true, directly reclaim pages when we are out of pages. No
 * mm's can be locked when @reclaim is set to true.
 *
 * Finally, wake up ksgxd when the number of pages goes below the watermark
 * before returning back to the caller.
 *
 * Return:
 *   an EPC page,
 *   -errno on error
 */
struct sgx_epc_page *sgx_alloc_epc_page(void *owner, bool reclaim)
{
	struct sgx_epc_page *page;

	for ( ; ; ) {
		page = __sgx_alloc_epc_page();
		if (!IS_ERR(page)) {
			page->owner = owner;
			break;
		}

		if (list_empty(&sgx_active_page_list))
			return ERR_PTR(-ENOMEM);

		if (!reclaim) {
			page = ERR_PTR(-EBUSY);
			break;
		}

		if (signal_pending(current)) {
			page = ERR_PTR(-ERESTARTSYS);
			break;
		}

		sgx_reclaim_pages();
		cond_resched();
	}

	if (sgx_should_reclaim(SGX_NR_LOW_PAGES))
		wake_up(&ksgxd_waitq);

	return page;
}

/**
 * sgx_free_epc_page() - Free an EPC page
 * @page:	an EPC page
 *
 * Put the EPC page back to the list of free pages. It's the caller's
 * responsibility to make sure that the page is in uninitialized state. In other
 * words, do EREMOVE, EWB or whatever operation is necessary before calling
 * this function.
 */
void sgx_free_epc_page(struct sgx_epc_page *page)
{
	struct sgx_epc_section *section = &sgx_epc_sections[page->section];
	struct sgx_numa_node *node = section->node;

	spin_lock(&node->lock);

	/*
	 * The page is EREMOVEd, stop tracking it
	 * as a deferred target for CPUSVN update
	 * process.
	 */
	if ((page->flags & SGX_EPC_PAGE_ZAP_TRACKED) &&
	    (!list_empty(&page->list)))
		list_del(&page->list);

	/*
	 * The page is EREMOVEd, decrease
	 * "zap_waiting_count" to stop counting it
	 * as a waiting target for CPUSVN update
	 * process.
	 */
	if (page->flags & SGX_EPC_PAGE_IN_RELEASE)
		atomic_dec_if_positive(&zap_waiting_count);

	page->flags = 0;
	page->owner = NULL;

	list_add_tail(&page->list, &node->free_page_list);
	sgx_nr_free_pages++;

	spin_unlock(&node->lock);
}

static bool __init sgx_setup_epc_section(u64 phys_addr, u64 size,
					 unsigned long index,
					 struct sgx_epc_section *section)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long i;

	section->virt_addr = memremap(phys_addr, size, MEMREMAP_WB);
	if (!section->virt_addr)
		return false;

	section->pages = vmalloc(nr_pages * sizeof(struct sgx_epc_page));
	if (!section->pages) {
		memunmap(section->virt_addr);
		return false;
	}

	section->phys_addr = phys_addr;
	section->size = size;

	for (i = 0; i < nr_pages; i++) {
		section->pages[i].section = index;
		section->pages[i].flags = 0;
		section->pages[i].owner = NULL;
		list_add_tail(&section->pages[i].list, &sgx_dirty_page_list);
	}

	return true;
}

/**
 * A section metric is concatenated in a way that @low bits 12-31 define the
 * bits 12-31 of the metric and @high bits 0-19 define the bits 32-51 of the
 * metric.
 */
static inline u64 __init sgx_calc_section_metric(u64 low, u64 high)
{
	return (low & GENMASK_ULL(31, 12)) +
	       ((high & GENMASK_ULL(19, 0)) << 32);
}

static bool __init sgx_page_cache_init(void)
{
	u32 eax, ebx, ecx, edx, type;
	u64 pa, size;
	int nid;
	int i;

	sgx_numa_nodes = kmalloc_array(num_possible_nodes(), sizeof(*sgx_numa_nodes), GFP_KERNEL);
	if (!sgx_numa_nodes)
		return false;

	for (i = 0; i < ARRAY_SIZE(sgx_epc_sections); i++) {
		cpuid_count(SGX_CPUID, i + SGX_CPUID_EPC, &eax, &ebx, &ecx, &edx);

		type = eax & SGX_CPUID_EPC_MASK;
		if (type == SGX_CPUID_EPC_INVALID)
			break;

		if (type != SGX_CPUID_EPC_SECTION) {
			pr_err_once("Unknown EPC section type: %u\n", type);
			break;
		}

		pa   = sgx_calc_section_metric(eax, ebx);
		size = sgx_calc_section_metric(ecx, edx);

		pr_info("EPC section 0x%llx-0x%llx\n", pa, pa + size - 1);

		if (!sgx_setup_epc_section(pa, size, i, &sgx_epc_sections[i])) {
			pr_err("No free memory for an EPC section\n");
			break;
		}

		nid = numa_map_to_online_node(phys_to_target_node(pa));
		if (nid == NUMA_NO_NODE) {
			/* The physical address is already printed above. */
			pr_warn(FW_BUG "Unable to map EPC section to online node. Fallback to the NUMA node 0.\n");
			nid = 0;
		}

		if (!node_isset(nid, sgx_numa_mask)) {
			spin_lock_init(&sgx_numa_nodes[nid].lock);
			INIT_LIST_HEAD(&sgx_numa_nodes[nid].free_page_list);
			node_set(nid, sgx_numa_mask);
		}

		sgx_epc_sections[i].node =  &sgx_numa_nodes[nid];

		sgx_nr_epc_sections++;
	}

	if (!sgx_nr_epc_sections) {
		pr_err("There are zero EPC sections.\n");
		return false;
	}

	return true;
}

/*
 * Update the SGX_LEPUBKEYHASH MSRs to the values specified by caller.
 * Bare-metal driver requires to update them to hash of enclave's signer
 * before EINIT. KVM needs to update them to guest's virtual MSR values
 * before doing EINIT from guest.
 */
void sgx_update_lepubkeyhash(u64 *lepubkeyhash)
{
	int i;

	WARN_ON_ONCE(preemptible());

	for (i = 0; i < 4; i++)
		wrmsrl(MSR_IA32_SGXLEPUBKEYHASH0 + i, lepubkeyhash[i]);
}

const struct file_operations sgx_provision_fops = {
	.owner			= THIS_MODULE,
};

static struct miscdevice sgx_dev_provision = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sgx_provision",
	.nodename = "sgx_provision",
	.fops = &sgx_provision_fops,
};

/**
 * sgx_set_attribute() - Update allowed attributes given file descriptor
 * @allowed_attributes:		Pointer to allowed enclave attributes
 * @attribute_fd:		File descriptor for specific attribute
 *
 * Append enclave attribute indicated by file descriptor to allowed
 * attributes. Currently only SGX_ATTR_PROVISIONKEY indicated by
 * /dev/sgx_provision is supported.
 *
 * Return:
 * -0:		SGX_ATTR_PROVISIONKEY is appended to allowed_attributes
 * -EINVAL:	Invalid, or not supported file descriptor
 */
int sgx_set_attribute(unsigned long *allowed_attributes,
		      unsigned int attribute_fd)
{
	struct file *file;

	file = fget(attribute_fd);
	if (!file)
		return -EINVAL;

	if (file->f_op != &sgx_provision_fops) {
		fput(file);
		return -EINVAL;
	}

	*allowed_attributes |= SGX_ATTR_PROVISIONKEY;

	fput(file);
	return 0;
}
EXPORT_SYMBOL_GPL(sgx_set_attribute);

static int __init sgx_init(void)
{
	int ret;
	int i;

	if (!cpu_feature_enabled(X86_FEATURE_SGX))
		return -ENODEV;

	if (!sgx_page_cache_init())
		return -ENOMEM;

	if (!sgx_page_reclaimer_init()) {
		ret = -ENOMEM;
		goto err_page_cache;
	}

	ret = misc_register(&sgx_dev_provision);
	if (ret)
		goto err_kthread;

	/*
	 * Always try to initialize the native *and* KVM drivers.
	 * The KVM driver is less picky than the native one and
	 * can function if the native one is not supported on the
	 * current system or fails to initialize.
	 *
	 * Error out only if both fail to initialize.
	 */
	ret = sgx_drv_init();

	if (sgx_vepc_init() && ret)
		goto err_provision;

	return 0;

err_provision:
	misc_deregister(&sgx_dev_provision);

err_kthread:
	kthread_stop(ksgxd_tsk);

err_page_cache:
	for (i = 0; i < sgx_nr_epc_sections; i++) {
		vfree(sgx_epc_sections[i].pages);
		memunmap(sgx_epc_sections[i].virt_addr);
	}

	return ret;
}

device_initcall(sgx_init);

void sgx_lock_epc(void)
{
	sgx_epc_locked = true;
	synchronize_srcu(&sgx_lock_epc_srcu);
}

void sgx_unlock_epc(void)
{
	sgx_epc_locked = false;
	synchronize_srcu(&sgx_lock_epc_srcu);
}

bool sgx_epc_is_locked(void)
{
	return sgx_epc_locked;
}

/**
 * sgx_zap_encl_page - unuse one EPC page
 *
 * Zap an EPC page if it's used by an enclave.
 *
 * Returns:
 * 0:			EPC page is unused or EREMOVE succeeds.
 * -EBUSY:		EREMOVE failed for other threads executing
 *			in enclave.
 * -EIO:		Other EREMOVE failures, like EPC leaks.
 */
static int sgx_zap_encl_page(struct sgx_epc_section *section,
			     struct sgx_epc_page *epc_page,
			     struct list_head *secs_pages_list)
{
	struct sgx_encl *encl;
	struct sgx_encl_page *encl_page;
	struct sgx_va_page *va_page;
	int retry_count = 10;
	int ret;

	/*
	 * Holding the per-section lock to ensure the
	 * "owner" field will not be cleared while
	 * checking.
	 */
	spin_lock(&section->node->lock);

	/*
	 * The "owner" field is NULL, it means the page
	 * is unused.
	 */
	if (!epc_page->owner) {
		spin_unlock(&section->node->lock);
		return 0;
	}

	if (epc_page->flags & SGX_EPC_PAGE_VA) {
		va_page = epc_page->owner;
		encl = va_page->encl;
	} else {
		encl_page = epc_page->owner;
		encl = encl_page->encl;
	}

	if (!encl) {
		spin_unlock(&section->node->lock);
		/*
		 * The page has owner, but without an Enclave
		 * associated with. This might be caused by
		 * EPC leaks happen in enclave's release path.
		 */
		ret = __eremove(sgx_get_epc_virt_addr(epc_page));
		if (!ret)
			sgx_free_epc_page(epc_page);
		else
			ret = -EIO;
		return ret;
	}

	/*
	 * Ensure that the 'encl' is not being freed and
	 * won't be freed while we operate on it.
	 */
	if (!kref_get_unless_zero(&encl->refcount)) {

		/*
		 * The enclave is exiting. The EUPDATESVN
		 * procedure needs to wait for the EREMOVE
		 * operation which happens as a part of
		 * the enclave exit operation. Use
		 * "zap_waiting_count" to indicate to the
		 * EUPDATESVN code when it needs to wait.
		 */
		if ((epc_page->flags & (SGX_EPC_PAGE_VA | SGX_EPC_PAGE_SECS)) &&
		    !(epc_page->flags & SGX_EPC_PAGE_IN_RELEASE)) {
			atomic_inc(&zap_waiting_count);
			epc_page->flags |= SGX_EPC_PAGE_IN_RELEASE;
		}

		spin_unlock(&section->node->lock);
		return 0;
	}

	spin_unlock(&section->node->lock);

	/*
	 * This EREMOVE has two main purposes:
	 * 1. Getting EPC pages into the "unused" state.
	 *    Every EPC page must be unused before an
	 *    EUPDATESVN can be succeed.
	 * 2. Forcing enclaves to exit more frequently.
	 *    EREMOVE will not succeed while any thread is
	 *    running in the enclave. Every successful
	 *    EREMOVE increases the chance that an enclave
	 *    will trip over this page, fault, and exit.
	 *    This, in turn, increases the likelihood of
	 *    success for every future EREMOVE attempt.
	 */
	ret = __eremove(sgx_get_epc_virt_addr(epc_page));

	if (!ret) {
		/*
		 * The SECS page is EREMOVEd successfully this time.
		 * Remove it from the list to stop tracking it.
		 */
		if ((epc_page->flags & SGX_EPC_PAGE_ZAP_TRACKED) &&
		    !list_empty(&epc_page->list)) {
			list_del_init(&epc_page->list);
			epc_page->flags &= ~SGX_EPC_PAGE_ZAP_TRACKED;
		}
		goto out;
	}

	if (ret == SGX_CHILD_PRESENT) {
		/*
		 * The SECS page is failed to be EREMOVEd due
		 * to associations. Add it to "secs_pages_list"
		 * for deferred handling.
		 */
		if (!(epc_page->flags & SGX_EPC_PAGE_ZAP_TRACKED) &&
		    secs_pages_list) {
			epc_page->flags |= SGX_EPC_PAGE_ZAP_TRACKED;
			list_add_tail(&epc_page->list, secs_pages_list);
		}
		ret = 0;
		goto out;
	}

	if (ret) {
		/*
		 * EREMOVE will fail on a page if the owning
		 * enclave is executing. An IPI will cause the
		 * enclave to exit, providing an opportunity to
		 * EREMOVE the page, but it does not guarantee
		 * the page will be EREMOVEd successfully. Retry
		 * for several times, if it keeps on failing,
		 * return -EBUSY to notify userspace for retry.
		 */
		do {
			on_each_cpu_mask(sgx_encl_cpumask(encl), sgx_ipi_cb, NULL, true);
			ret = __eremove(sgx_get_epc_virt_addr(epc_page));
			if (!ret)
				break;
			retry_count--;
		} while (retry_count);

		if (ret)
			ret = -EBUSY;
	}

out:
	kref_put(&encl->refcount, sgx_encl_release);
	return ret;
}

/**
 * sgx_zap_section_pages - unuse one EPC section's pages
 *
 * Iterate through pages in one EPC section, unuse the pages
 * initialized for enclaves on bare metal.
 *
 * TODO: EPC pages for KVM guest will be handled in future.
 *
 * Returns:
 * 0:			EPC page is unused.
 * -EBUSY:		EREMOVE failed for other threads executing
 *			in enclave.
 * -EIO:		Other EREMOVE failures, like EPC leaks.
 */
static int sgx_zap_section_pages(struct sgx_epc_section *section,
				 struct list_head *secs_pages_list)
{
	struct sgx_epc_page *epc_page;
	int i, ret;
	unsigned long nr_pages = section->size >> PAGE_SHIFT;

	for (i = 0; i < nr_pages; i++) {
		epc_page = &section->pages[i];

		/*
		 * EPC page has "NULL" owner, indicating
		 * it's unused. No action required for
		 * this case.
		 *
		 * No new owner can be assigned when SGX
		 * is "frozen".
		 */
		if (!epc_page->owner)
			continue;

		/*
		 * Try to "unuse" all SGX memory used by enclaves
		 * on bare-metal.
		 *
		 * Failures might be caused by the following reasons:
		 * 1. EREMOVE failure due to other threads executing
		 *    in enclave. Return -EBUSY to notify userspace
		 *    for a later retry.
		 * 2. Other EREMOVE failures. For example, a bug in
		 *    SGX memory management like a leak that lost
		 *    track of an SGX EPC page. Upon these failures,
		 *    do not even attempt EUPDATESVN.
		 */
		if (!(epc_page->flags & SGX_EPC_PAGE_GUEST)) {
			ret = sgx_zap_encl_page(section, epc_page, secs_pages_list);
			if (ret)
				return ret;
		}
	}

	return ret;
}

/**
 * sgx_zap_pages - unuse all EPC sections' pages
 *
 * This function is called while microcode_mutex lock is held
 * from the caller, it ensures that the update process will not
 * run concurrently.
 *
 * Returns:
 * 0:			All enclaves have been torn down and
 *			all EPC pages are unused.
 * -ERESTARTSYS:	Interrupted by a signal.
 * -EBUSY:		EREMOVE failed for other threads executing
 *			in enclave.
 * -EIO:		Other EREMOVE failures, like EPC leaks.
 */
int sgx_zap_pages(void)
{
	struct sgx_epc_section *section;
	struct sgx_epc_page *epc_page, *tmp;
	int i, ret;

	LIST_HEAD(secs_pages_list);

	/*
	 * A non-NULL "zap_waiting_count", means
	 * a failure of last CPUSVN update, which
	 * increases the chance of failure this
	 * time.
	 */
	WARN_ON(atomic_read(&zap_waiting_count));

	for (i = 0; i < ARRAY_SIZE(sgx_epc_sections); i++) {
		section = &sgx_epc_sections[i];
		if (!section->pages)
			break;
		/*
		 * Go through the section's pages and try to EREMOVE
		 * each one, except the ones associated with enclaves
		 * in releasing.
		 */
		ret = sgx_zap_section_pages(section, &secs_pages_list);
		if (WARN_ON_ONCE(ret))
			goto out;
	}

	/*
	 * The SECS page should have no associations now, try
	 * EREMOVE them again.
	 */
	list_for_each_entry_safe(epc_page, tmp, &secs_pages_list, list) {
		section = &sgx_epc_sections[epc_page->section];
		ret = sgx_zap_encl_page(section, epc_page, NULL);
		if (ret)
			goto out;
	}

	/*
	 * There might be pages in the process of being freed
	 * by exiting enclaves. Wait for the exiting process
	 * to succeed or fail.
	 */
	ret = wait_event_interruptible(sgx_zap_waitq,
				       (!atomic_read(&zap_waiting_count) ||
					sgx_zap_abort_wait));
	if (ret == -ERESTARTSYS) {
		pr_err("CPUSVN update is not finished yet, but killed by userspace\n");
		goto out;
	}

	mutex_lock(&sgx_zap_abort_lock);
	if (sgx_zap_abort_wait) {
		ret = -EIO;
		pr_err("exit-side EREMOVE failure. Aborting CPUSVN update\n");
		mutex_unlock(&sgx_zap_abort_lock);
		goto out;
	}
	mutex_unlock(&sgx_zap_abort_lock);

out:
	return ret;
}

/**
 * sgx_zap_wakeup - wake up CPUSVN update process
 *
 * Whenever enclave is freed, this function will
 * be called to check if all EPC pages are unused.
 * Wake up the CPUSVN update process if it's true.
 */
void sgx_zap_wakeup(void)
{
	if (wq_has_sleeper(&sgx_zap_waitq) &&
	    !atomic_read(&zap_waiting_count))
		wake_up(&sgx_zap_waitq);
}

/**
 * sgx_zap_abort - abort SGX CPUSVN update process
 *
 * When EPC leaks happen in enclave release process,
 * it will set flag sgx_zap_abort_wait as true to
 * abort the CPUSVN update process.
 */
void sgx_zap_abort(void)
{
	mutex_lock(&sgx_zap_abort_lock);

	sgx_zap_abort_wait = true;
	wake_up(&sgx_zap_waitq);

	mutex_unlock(&sgx_zap_abort_lock);
}

static LIST_HEAD(sgx_kvm_notifier_list);
static DEFINE_MUTEX(sgx_kvm_notifier_lock);

void sgx_kvm_notifier_register(struct sgx_kvm_notifier *notifier)
{
	mutex_lock(&sgx_kvm_notifier_lock);
	list_add_tail(&notifier->list, &sgx_kvm_notifier_list);
	mutex_unlock(&sgx_kvm_notifier_lock);
}
EXPORT_SYMBOL(sgx_kvm_notifier_register);

void sgx_kvm_notifier_unregister(struct sgx_kvm_notifier *notifier)
{
	mutex_lock(&sgx_kvm_notifier_lock);
	list_del(&notifier->list);
	mutex_unlock(&sgx_kvm_notifier_lock);
}
EXPORT_SYMBOL(sgx_kvm_notifier_unregister);

void sgx_kvm_notifier_halt(void)
{
	struct sgx_kvm_notifier *notifier;

	mutex_lock(&sgx_kvm_notifier_lock);
	list_for_each_entry(notifier, &sgx_kvm_notifier_list, list) {
		notifier->ops->halt(notifier);
	}
	mutex_unlock(&sgx_kvm_notifier_lock);
}

void sgx_kvm_notifier_resume(void)
{
	struct sgx_kvm_notifier *notifier;

	mutex_lock(&sgx_kvm_notifier_lock);
	list_for_each_entry(notifier, &sgx_kvm_notifier_list, list) {
		notifier->ops->resume(notifier);
	}
	mutex_unlock(&sgx_kvm_notifier_lock);
}
