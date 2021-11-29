// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) Intel Corporation. All rights rsvd. */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/mdev.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/irq-ims-msi.h>
#include <uapi/linux/idxd.h>
#include "idxd.h"
#include "mdev.h"

extern const struct vfio_pci_regops vfio_pci_dma_fault_regops;

int idxd_mdev_host_init(struct idxd_device *idxd, const struct mdev_parent_ops *ops)
{
	struct device *dev = &idxd->pdev->dev;
	struct ims_array_info ims_info;
	int rc;

	if (!test_bit(IDXD_FLAG_IMS_SUPPORTED, &idxd->flags))
		return -EOPNOTSUPP;

	rc = iommu_dev_enable_feature(dev, IOMMU_DEV_FEAT_AUX);
	if (rc < 0) {
		dev_warn(dev, "Failed to enable aux-domain: %d\n", rc);
		return rc;
	}

	ims_info.max_slots = idxd->ims_size;
	ims_info.slots = idxd->reg_base + idxd->ims_offset;
	idxd->ims_domain = pci_ims_array_create_msi_irq_domain(idxd->pdev, &ims_info);
	if (!idxd->ims_domain) {
		dev_warn(dev, "Fail to acquire IMS domain\n");
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		return -ENODEV;
	}

	rc = mdev_register_device(dev, ops);
	if (rc < 0) {
		dev_warn(dev, "mdev register failed\n");
		irq_domain_remove(idxd->ims_domain);
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		return rc;
	}

	mutex_init(&idxd->vfio_pdev.igate);
	idxd->vfio_pdev.pdev = idxd->pdev;
	rc = vfio_pci_dma_fault_init(&idxd->vfio_pdev, true);
	if (rc < 0) {
		dev_err(dev, "dma fault region init failed\n");
		irq_domain_remove(idxd->ims_domain);
		iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
		mdev_unregister_device(dev);
		return rc;
	}

	idxd->mdev_host_init = true;
	return 0;
}

void idxd_mdev_host_release(struct kref *kref)
{
	struct idxd_device *idxd = container_of(kref, struct idxd_device, mdev_kref);
	struct device *dev = &idxd->pdev->dev;
	struct vfio_pci_core_device *vfio_pdev = &idxd->vfio_pdev;
	int i;

	if (!idxd->mdev_host_init)
		return;

	WARN_ON(iommu_unregister_device_fault_handler(dev));

	for (i = 0; i < vfio_pdev->num_regions; i++)
		vfio_pdev->region[i].ops->release(vfio_pdev, &vfio_pdev->region[i]);
	vfio_pdev->num_regions = 0;
	kfree(vfio_pdev->region);
	vfio_pdev->region = NULL;
	iommu_unregister_device_fault_handler(&idxd->pdev->dev);
	for (i = 0; i < vfio_pdev->num_ext_irqs; i++)
		vfio_pci_set_ext_irq_trigger(vfio_pdev,
					     VFIO_IRQ_SET_DATA_NONE | VFIO_IRQ_SET_ACTION_TRIGGER,
					     VFIO_PCI_NUM_IRQS + i, 0, 0, NULL);
	vfio_pdev->num_ext_irqs = 0;
	kfree(vfio_pdev->ext_irqs);
	vfio_pdev->ext_irqs = NULL;

	irq_domain_remove(idxd->ims_domain);
	mdev_unregister_device(dev);
	iommu_dev_disable_feature(dev, IOMMU_DEV_FEAT_AUX);
	idxd->mdev_host_init = false;
}
