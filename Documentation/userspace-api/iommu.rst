.. iommu:

=====================================
IOMMU Userspace API
=====================================

For native usage, IOMMU is a system device which does not need to
communicate with user space. However, userspace interactions are
needed for virtualization the use cases that involve guest Shared
Virtual Address (SVA) and guest IO virtual address (IOVA). Both guest
IOVA and SVA requires a virtual IOMMU in the guest and communicate
with the physical IOMMU in the host.

IOMMU UAPI is designed to facilitate the communications between guest
and host IOMMUs.

.. contents:: :local:


Functionality
====================================================
IOMMU UAPI relies on VFIO, a ubiquitos userspace driver framework, for
all its communications.
VFIO is IOMMU aware and support device model, domain, process address
space ID (PASID), and many key concepts. Communications of user and
kernel are supported for both directions. The supported APIs are as follows:

1. Alloc/Free PASID
2. Bind/unbind guest PASID (Vt-d)
3. Bind/unbind guest PASID table (sMMU)
4. Cache invalidate
5. Page request service

Requirements
====================================================
The UAPI must support the following:

1. Emulated and paravirtualied vIOMMUs
2. Multiple vendors (Intel VT-d, ARM sMMU, etc.)
3. Kernel maintains backward compatibility and follow existing
   protocols to phase out features

Interfaces
====================================================
Moderate extensions to the current VFIO interface are needed to
support the functionalities above. This section covers the scheme for
feature checking, data passing, and the handling of future extensions.

Feature Checking
----------------------------------------------------
While launching a guest with vIOMMU, it is important to ensure that host
can support the UAPI data structures to be used for vIOMMU-pIOMMU
communications. Without the upfront compatibility checking, future
faults are difficult to report even in normal conditions. For example,
TLB invalidations should always succeed from vIOMMU's
perspective. There is no architectual way to report back the vIOMMU if
the UAPI data is not compatible. For this reason the following IOMMU
UAPIs cannot fail:

1. Free PASID
2. Unbind guest PASID
3. Unbind guest PASID table (SMMU)
4. Cache invalidate
5. Page response

User applications such as QEMU is expected to import kernel UAPI
headers. Only backward compatibility is supported. For example, an
older QEMU (with older kernel header), can run on newer kernel. Newer
QEMU (with new kernel header) would fail on older kernel.

User space shall use VFIO_CHECK_EXTENSION for checking if individual
IOMMU UAPI is available and meeting minimum requirements.

::

   //New extensions
   #define VFIO_IOMMU_BIND_GPASID	9
   #define VFIO_IOMMU_INVALIDATE	10
   #define VFIO_IOMMU_PAGE_REQUEST	11

   //Example of checking bind guest PASID UAPI extension
   extension = ioctl(container, VFIO_CHECK_EXTENSION, VFIO_IOMMU_BIND_GPASID);
   if (extension >= IOMMU_GPASID_BIND_VERSION_1) {
       /* Kernel has newer extensions, we are good */
       goto check_next_extension;
   } else {
       stop_viommu();
   }

Data Passing
----------------------------------------------------
Unlike typical user data passed via VFIO IOTCL, IOMMU driver is the
ultimate consumer. At VFIO layer, the IOMMU UAPI data is wrapped in a
VFIO UAPI data for basic sanity checking. It follows the pattern below:
::

   struct {
	__u32 argsz;
	__u32 flags;
	__u8  data[];
  }

Here data[] is the IOMMU UAPI data structures.

In order to determine the size and feature set of the user data, size
and flags are also embedded in the IOMMU UAPI data structures.
A "__u32 size" field is *always* at the beginning of each structure.

For example:
::

   struct iommu_gpasid_bind_data {
	__u32 size;
	__u32 version;
	#define IOMMU_PASID_FORMAT_INTEL_VTD	1
	__u32 format;
	#define IOMMU_SVA_GPASID_VAL	(1 << 0)
	__u64 flags;
	__u64 gpgd;
	__u64 hpasid;
	__u64 gpasid;
	__u32 addr_width;
	__u8  padding[12];
	/* Vendor specific data */
	union {
		struct iommu_gpasid_bind_data_vtd vtd;
	};
  };

When IOMMU APIs get extended, the data structures can *only* be
modified in two ways:

1. Adding new fields by repurposing the padding[] field. No size change.
2. Adding new union members at the end. May increase size.

No new fields can be added *after* the variable size union. In both
ways, a new flag must be accompanied with a new field such that the
IOMMU driver can process the data based on the new flag. Version field
is only reserved for the unlikely event of UAPI upgrade at its entirety.

Similar to VFIO,  it's *always* the caller's responsibility to
indicate the size of the structure passed by setting argsz
appropriately.

When IOMMU UAPI entension results in size increase, VFIO has to handle
the following scenarios:

0. User and kernel has exact size match
1. An older user with older kernel header (smaller UAPI size) running on a
   newer kernel (larger UAPI size)
2. A newer user with newer kernel header (larger UAPI size) running
   on a older kernel.
3. A malicious/misbehaving user pass illegal/invalid size but within
   range. The data may contain garbage.

Use bind guest PASID as an example, VFIO code shall process IOMMU UAPI
request as follows:

::

 1        /* Minsz must include IOMMU UAPI argsz of __u32 */
 2        minsz = offsetofend(struct vfio_iommu_type1_bind, flags) +
                              sizeof(u32);
 3        copy_from_user(&vfio_bind, (void __user *)arg, minsz);
 4
 5        /* Check VFIO argsz */
 6        if (vfio_bind.argsz < minsz)
 7                return -EINVAL;
 8
 9        /* VFIO flags must be included in minsz */
 10        switch (vfio_bind.flags) {
 11        case VFIO_IOMMU_BIND_GUEST_PGTBL:
 12                /*
 13                 * Get the current IOMMU bind GPASID data size,
 14                 * which accounted for the largest union member.
 15                 */
 16                data_size = sizeof(struct iommu_gpasid_bind_data);
 17                iommu_size = *(u32 *) &vfio_bind.data;
 18                if (iommu_size > data_size) {
 19                        /* User data > current kernel */
 20                        return -E2BIG;
 21                }
 22                copy_from_user(&iommu_bind, (void __user *)
 23                               vfio_bind.data, iommu_argsz);
 24               /*
 25                * Deal with trailing bytes that is bigger than user
 26                * privided UAPI size but smaller than the current
 27                * kernel data size. Zero fill the trailing bytes.
 28                */
 29                memset(iommu_bind + iommu_size, 0, data_size -
 30                       iommu_size;
 31
 32                iommu_sva_bind_gpasid(domain, dev, iommu_bind_data);
 33                break;

Case 1 is supported. Case 2 will fail with -E2BIG at line #20. Case
3 may result in other error processed by IOMMU vendor driver. However,
the damage shall not exceed the scope of the offending user.

