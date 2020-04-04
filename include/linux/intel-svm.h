/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright © 2015 Intel Corporation.
 *
 * Authors: David Woodhouse <David.Woodhouse@intel.com>
 */

#ifndef __INTEL_SVM_H__
#define __INTEL_SVM_H__

struct device;

struct svm_dev_ops {
	void (*fault_cb)(struct device *dev, int pasid, u64 address,
			 void *private, int rwxp, int response);
};

/* Values for rxwp in fault_cb callback */
#define SVM_REQ_READ	(1<<3)
#define SVM_REQ_WRITE	(1<<2)
#define SVM_REQ_EXEC	(1<<1)
#define SVM_REQ_PRIV	(1<<0)

/*
 * The SVM_FLAG_PRIVATE_PASID flag requests a PASID which is *not* the "main"
 * PASID for the current process. Even if a PASID already exists, a new one
 * will be allocated. And the PASID allocated with SVM_FLAG_PRIVATE_PASID
 * will not be given to subsequent callers. This facility allows a driver to
 * disambiguate between multiple device contexts which access the same MM,
 * if there is no other way to do so. It should be used sparingly, if at all.
 */
#define SVM_FLAG_PRIVATE_PASID		(1<<0)

/*
 * The SVM_FLAG_SUPERVISOR_MODE flag requests a PASID which can be used only
 * for access to kernel addresses. No IOTLB flushes are automatically done
 * for kernel mappings; it is valid only for access to the kernel's static
 * 1:1 mapping of physical memory — not to vmalloc or even module mappings.
 * A future API addition may permit the use of such ranges, by means of an
 * explicit IOTLB flush call (akin to the DMA API's unmap method).
 *
 * It is unlikely that we will ever hook into flush_tlb_kernel_range() to
 * do such IOTLB flushes automatically.
 */
#define SVM_FLAG_SUPERVISOR_MODE	(1<<1)
/*
 * The SVM_FLAG_GUEST_MODE flag is used when a guest process bind to a device.
 * In this case the mm_struct is in the guest kernel or userspace, its life
 * cycle is managed by VMM and VFIO layer. For IOMMU driver, this API provides
 * means to bind/unbind guest CR3 with PASIDs allocated for a device.
 */
#define SVM_FLAG_GUEST_MODE	(1<<2)
/*
 * The SVM_FLAG_GUEST_PASID flag is used when a guest has its own PASID space,
 * which requires guest and host PASID translation at both directions. We keep
 * track of guest PASID in order to provide lookup service to device drivers.
 * One such example is a physical function (PF) driver that supports mediated
 * device (mdev) assignment. Guest programming of mdev configuration space can
 * only be done with guest PASID, therefore PF driver needs to find the matching
 * host PASID to program the real hardware.
 */
#define SVM_FLAG_GUEST_PASID	(1<<3)

#endif /* __INTEL_SVM_H__ */
