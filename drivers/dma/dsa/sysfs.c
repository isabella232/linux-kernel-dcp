/*
 * Intel I/OAT DMA Linux driver
 * Copyright(c) 2004 - 2015 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in
 * the file called "COPYING".
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/dmaengine.h>
#include <linux/pci.h>
#include "dma.h"
#include "registers.h"
#include "hw.h"

#include "../dmaengine.h"

static ssize_t cap_show(struct dma_chan *c, char *page)
{
	struct dma_device *dma = c->device;

	return sprintf(page, "copy%s\n",
	       dma_has_cap(DMA_INTERRUPT, dma->cap_mask) ? " intr" : "");

}
struct dsa_sysfs_entry dsa_cap_attr = __ATTR_RO(cap);

static ssize_t version_show(struct dma_chan *c, char *page)
{
	struct dma_device *dma = c->device;
	struct dsadma_device *dsa_dma = to_dsadma_device(dma);

	return sprintf(page, "%d.%d\n",
		       dsa_dma->version >> 8, dsa_dma->version & 0xff);
}
struct dsa_sysfs_entry dsa_version_attr = __ATTR_RO(version);

static ssize_t
dsa_attr_show(struct kobject *kobj, struct attribute *attr, char *page)
{
	struct dsa_sysfs_entry *entry;
	struct dsa_work_queue *dsa_wq;

	entry = container_of(attr, struct dsa_sysfs_entry, attr);
	dsa_wq = container_of(kobj, struct dsa_work_queue, kobj);

	if (!entry->show)
		return -EIO;
	return entry->show(&dsa_wq->dma_chan, page);
}

const struct sysfs_ops dsa_sysfs_ops = {
	.show	= dsa_attr_show,
};

void dsa_kobject_add(struct dsadma_device *dsa_dma, struct kobj_type *type)
{
	struct dma_device *dma = &dsa_dma->dma_dev;
	struct dma_chan *c;

	list_for_each_entry(c, &dma->channels, device_node) {
		struct dsa_work_queue *dsa_wq = to_dsa_wq(c);
		struct kobject *parent = &c->dev->device.kobj;
		int err;

		err = kobject_init_and_add(&dsa_wq->kobj, type,
					   parent, "quickdata");
		if (err) {
			dev_warn(to_dev(dsa_wq),
				 "sysfs init error (%d), continuing...\n", err);
			kobject_put(&dsa_wq->kobj);
			set_bit(DSA_KOBJ_INIT_FAIL, &dsa_wq->state);
		}
	}
}

void dsa_kobject_del(struct dsadma_device *dsa_dma)
{
	struct dma_device *dma = &dsa_dma->dma_dev;
	struct dma_chan *c;

	list_for_each_entry(c, &dma->channels, device_node) {
		struct dsa_work_queue *dsa_wq = to_dsa_wq(c);

		if (!test_bit(DSA_KOBJ_INIT_FAIL, &dsa_wq->state)) {
			kobject_del(&dsa_wq->kobj);
			kobject_put(&dsa_wq->kobj);
		}
	}
}

static ssize_t wq_size_show(struct dma_chan *c, char *page)
{
	struct dsa_work_queue *dsa_wq = to_dsa_wq(c);

	return sprintf(page, "%d\n", dsa_wq->wq_size);
}
static struct dsa_sysfs_entry wq_size_attr = __ATTR_RO(wq_size);

static ssize_t wq_active_show(struct dma_chan *c, char *page)
{
	struct dsa_work_queue *dsa_wq = to_dsa_wq(c);

	/* ...taken outside the lock, no need to be precise */
	return sprintf(page, "%d\n", dsa_wq->wq_enabled);
}
static struct dsa_sysfs_entry wq_active_attr = __ATTR_RO(wq_active);

static struct attribute *dsa_attrs[] = {
	&wq_size_attr.attr,
	&wq_active_attr.attr,
	&dsa_cap_attr.attr,
	&dsa_version_attr.attr,
	NULL,
};

struct kobj_type dsa_ktype = {
	.sysfs_ops = &dsa_sysfs_ops,
	.default_attrs = dsa_attrs,
};
