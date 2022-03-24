#include <linux/migrate.h>
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>

static bool dma_migrate_enabled __read_mostly;
static unsigned int dma_migrate_segment = 32;

#ifdef CONFIG_SYSFS
static int __dma_page_copy_sg(struct scatterlist *src, struct scatterlist *dst,
			      unsigned int nents)
{
	struct dma_async_tx_descriptor *tx;
	struct dma_chan *dma_copy_chan = NULL;
	struct device *dev;
	dma_cap_mask_t mask;
	dma_cookie_t cookie;
	enum dma_status status;
	unsigned int nr_sgs, nr_sgd = 0;
	int err = 0;

	/* acquire DMA chan */
	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY_SG, mask);
	dma_copy_chan = dma_request_chan_by_mask(&mask);
	if (IS_ERR(dma_copy_chan))
		return -ENODEV;

	dev = dmaengine_get_dma_device(dma_copy_chan);
	/* map scatterlist entries */
	nr_sgs = dma_map_sg(dev, src, nents, DMA_TO_DEVICE);
	if (!nr_sgs) {
		pr_err("DMA dev cannot map address\n");
		err = -EINVAL;
		goto unmap_sg;
	}
	nr_sgd = dma_map_sg(dev, dst, nents, DMA_FROM_DEVICE);
	if (!nr_sgd) {
		pr_err("DMA dev cannot map address\n");
		err = -EINVAL;
		goto unmap_sg;
	}

	/* prep DMA scatterlist memcpy */
	tx = dmaengine_prep_dma_memcpy_sg(dma_copy_chan, dst, nents,
					src, nents, 0);
	if (!tx) {
		pr_err("DMA dev prep copy failed\n");
		err = -EIO;
		goto unmap_sg;
	}

	/* submit DMA request */
	cookie = dmaengine_submit(tx);
	if (dma_submit_error(cookie)) {
		pr_err("Failed to do DMA submit\n");
		err = -EIO;
		goto unmap_sg;
	}

	status = dma_sync_wait(dma_copy_chan, cookie);
	if (status != DMA_COMPLETE)
		err = -EIO;

unmap_sg:
	if (nr_sgs)
		dma_unmap_sg(dev, src, nr_sgs, DMA_TO_DEVICE);
	if (nr_sgd)
		dma_unmap_sg(dev, dst, nr_sgd, DMA_FROM_DEVICE);
	if (dma_copy_chan)
		dma_release_channel(dma_copy_chan);
	return err;
}

static ssize_t migrate_dma_enabled_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%s\n", dma_migrate_enabled ? "true" : "false");
}
static ssize_t migrate_dma_enabled_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	if (!strncmp(buf, "true", 4) || !strncmp(buf, "1", 1))
		dma_migrate_enabled = true;
	else if (!strncmp(buf, "false", 5) || !strncmp(buf, "0", 1))
		dma_migrate_enabled = false;
	else
		return -EINVAL;

	return count;
}
static struct kobj_attribute dma_migrate_enabled_attr =
	__ATTR(dma_enabled, 0644, migrate_dma_enabled_show,
	       migrate_dma_enabled_store);

static ssize_t migrate_dma_segment_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", dma_migrate_segment);
}

static ssize_t migrate_dma_segment_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	unsigned int nr_segment;
	int err;

	err = kstrtouint(buf, 10, &nr_segment);
	if (err)
		return -EINVAL;

	dma_migrate_segment = nr_segment;

	return count;
}
static struct kobj_attribute dma_migrate_segment_attr =
	__ATTR(dma_migrate_segment, 0644, migrate_dma_segment_show,
	       migrate_dma_segment_store);

static struct attribute *migrate_attrs[] = {
	&dma_migrate_enabled_attr.attr,
	&dma_migrate_segment_attr.attr,
	NULL,
};

static const struct attribute_group migrate_attr_group = {
	.attrs = migrate_attrs,
};

static int __init dma_migrate_init_sysfs(void)
{
	struct kobject *migrate_kobj;
	int err;

	migrate_kobj = kobject_create_and_add("migrate", mm_kobj);
	if (unlikely(!migrate_kobj)) {
		pr_err("failed to create migrate kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(migrate_kobj, &migrate_attr_group);
	if (err) {
		pr_err("failed to register migrate group\n");
		goto delete_obj;
	}

	return 0;

delete_obj:
	kobject_put(migrate_kobj);
	return err;
}
subsys_initcall(dma_migrate_init_sysfs);
#endif

bool migrate_use_dma(void)
{
	return READ_ONCE(dma_migrate_enabled);
}

int dma_migrate_pages_copy(const struct list_head *pages,
			  const struct list_head *new_pages)
{
	struct page *page, *newpage;
	struct scatterlist *src_sg, *dst_sg = NULL;
	struct scatterlist *src_ptr, *dst_ptr;
	unsigned int order, nents = 0;
	int err = 0;

	src_sg = kmalloc_array(dma_migrate_segment, sizeof(*src_sg),
			GFP_KERNEL);
	if (!src_sg) {
		err = -ENOMEM;
		goto done;
	}

	dst_sg = kmalloc_array(dma_migrate_segment, sizeof(*dst_sg),
			GFP_KERNEL);
	if (!dst_sg) {
		err = -ENOMEM;
		goto done;
	}

	src_ptr = src_sg;
	dst_ptr = dst_sg;

	/* segment */
	newpage = list_first_entry(new_pages, struct page, lru);
	list_for_each_entry(page, pages, lru) {
		if (PageHuge(page)) {
			struct hstate *hs;

			hs = page_hstate(page);
			if (!hs) {
				err = -ENOENT;
				goto done;
			}
			order = huge_page_order(hs);
		} else if (PageTransHuge(page)) {
			order = thp_order(page);
		} else {
			order = 0;
		}
		memset(src_ptr, 0, sizeof(*src_ptr));
		memset(dst_ptr, 0, sizeof(*dst_ptr));
		sg_set_page(src_ptr++, page, PAGE_SIZE << order, 0);
		sg_set_page(dst_ptr++, newpage, PAGE_SIZE << order, 0);
		nents++;

		if (nents == dma_migrate_segment) {
			sg_mark_end(src_ptr - 1);
			sg_mark_end(dst_ptr - 1);

			if (__dma_page_copy_sg(src_sg, dst_sg, nents)) {
				err = -ENODEV;
				goto done;
			}

			/* reset iterator */
			src_ptr = src_sg;
			dst_ptr = dst_sg;
			nents = 0;
		}

		newpage = list_next_entry(newpage, lru);
	}

	/* last remain */
	if (nents) {
		sg_mark_end(src_ptr - 1);
		sg_mark_end(dst_ptr - 1);

		if (__dma_page_copy_sg(src_sg, dst_sg, nents)) {
			err = -ENODEV;
			goto done;
		}
	}

done:
	if (src_sg)
		kfree(src_sg);
	if (dst_sg)
		kfree(dst_sg);
	return err;
}
