.. ioasid:

=====================================
IO Address Space ID
=====================================

IOASID is a generic name for PCIe Process Address ID (PASID) or ARM
SMMU sub-stream ID. An IOASID identifies an address space that DMA
requests can target.

Primary use cases for IOASID are SVA and IOVA. However the
requirements for IOASID management can vary among hardware architectures.
This focus of this document is on Intel x86 platform with VT-d 3.0+ features.

.. contents:: :local:


Glossary
====================================================
IOASID - IO Address Space ID

PASID - Process Address Space ID

SVA/SVM - Shared Virtual Addressing/Memory

ENQCMD - New Intel X86 ISA for efficient workqueue submission [1]

DSA - Intel Data Streaming Accelerator [2] 

VDCM - Virtual device composition module [3]

SIOV - Intel Scalable IO Virtualization

Allocation
====================================================
IOASIDs are allocated for both host and guest SVA/IOVA usage. However,
the allocators can be different. On VT-d, guest allocation must be
performed via a virtual command interface which is
emulated by VMM.

Custom allocators are supported by the IOASID code such that guest can
register virtual command allocator that precedes the default one.

Storage
====================================================
IOASIDs are stored in a table that can be referenced by HW at per
device/endpoint level. Sharing IOASID tables among devices is optional
but not allowed on VT-d for security reasons.

Namespaces
====================================================
IOASIDs are limited system resources that default to 20 bits in
size. Since each device has its own table, theoretically the namespace
can be per device also. However, VT-d also supports shared workqueue
and ENQCMD[1] where one IOASID could be used to submit work on
multiple devices. This requires IOASID to be system-wide on Intel VT-d
platforms. This is also the reason why guest must use emulated virtual
command interface to allocate IOASID from the host.

On VT-d, storage of IOASID table is at per device while the
granularity of assignment is per IOASID. Even though, each guest
IOASID must have a backing host IOASID, guest IOASID can be different
than its host IOASID. The namespace of guest IOASID is controlled by
VMM, which decideds whether identity mapping of G-H IOASIDs is necessary.

On ARM SMMU platform, system-wide IOASID is not required. Each VM
could have its own namespace. Granularity of device assignment is at
per endpoint. PASID table is per IOMMU domain. In most cases, there is
a single device per domain which reference to its IOASID table. Unless
userspace puts all devices in the same VFIO container (hence in the
same IOMMU domain).


IOASID set
====================================================




Life cycle
====================================================
There is similarity between native and VM use of IOASID. However, due
to the lack of availability of guest MMU notifier, when guest MM
terminates unexpectedly, the fault handling can be different.

Native IOASID Life Cycle
----------------------------------------------------

The normal flow of native SVA code with Intel Data Streaming
Accelerator(DSA) [2] as example:

1. Host user opens accelerator FD, e.g. DSA driver, or uacce;
2. DSA driver allocate WQ, do sva_bind_device();
3. IOMMU driver calls ioasid_alloc(), then bind PASID with device,
   mmu_notifier_get()
4. DMA starts by DSA driver userspace
5. DSA userspace close FD
6. DSA/uacce kernel driver handles FD.close()
7. DSA driver stops DMA
8. DSA driver calls sva_unbind_device();
9. IOMMU driver does unbind, clears PASID context in IOMMU, flush
   TLBs. mmu_notifier_put() called.
10. mmu_notifier.release() called, IOMMU SVA code calls ioasid_free()*
11. The IOASID is returned to the pool, reclaimed.

::
 
   * With ENQCMD, PASID used on VT-d is not released in mmu_notifier() but
     mmdrop(). mmdrop comes after FD close. Should not matter.
     If user process dies unexpectedly, Step #10 may come before Step #5,
     in between, all DMA faults discarded. PRQ responded with code
     INVALID.

Guest IOASID Life Cycle
----------------------------------------------------
Guest IOASID life cycle starts with guest driver open(), this could be
uacce or individual accelerator driver such as IDXD. At FD open,
sva_bind_device() is called which triggers a series actions.

The example below is a illustration of *normal* operations that
involves *all* the SW components in VT-d. The flow can be simpler if
no ENQCMD support.

::

     VFIO        IOMMU        KVM        VDCM        IOASID       Ref
   ..................................................................
   1             register_ioasid_notifier(all)
   2 ioasid_alloc()                                  ->           1
   3 bind_gpasid()
   4             ioasid_get()                        ->           2
   5             iommu_bind()
   6             ioasid_notify(BIND)                 ->
   7                          -> ioasid_get()        ->           3
   8                          -> vmcs_update()
   9 mdev_write(gpasid)                       ->
   10                                   ioasid_get() ->           4
   11                                   ioasid_get_hpasid()
   12                                   vdev_write(hpasid)
   13 -------- GUEST STARTS DMA --------------------------
   14 -------- GUEST STOPS DMA --------------------------
   15 mdev_clear(gpasid)                ->
   16                                   vdev_clear(hpasid)
   17                                   ioasid_put() ->           3
   18 unbind_gpasid()
   19            iommu_ubind()
   20            ioasid_notify(UNBIND)                ->
   21                          -> vmcs_update()
   22                          -> ioasid_put()        ->           2
   23            ioasid_put()                         ->           1
   24 ioasid_free()                                   ->           0
   25                                                 Reclaimed
   -------------- New Life Cycle Begin ----------------------------
   1  ioasid_alloc()                                  ->           1

   Note: IOASID Notification Events: FREE, BIND, UNBIND

Exception cases may arise when a guest crashes or a malicious guest
attempt to cause disruption on the host system. The falut handling
rules are:

1. IOASID free must *always* succeed.
2. An inactive period may be required before the freed IOASID is
   reclaimed. During this period, consumers of IOASID performs cleanup.
3. Malfunction is limited to the guest owned resources for all
   programming errors.

The primary source of exception is when the following are out of
order:

1. Start/Stop of DMA activity
   (guest device driver & host VFIO PCI)
2. Setup/Teardown of IOMMU PASID context, IOTLB, DevTLB flushes
   (Host IOMMU driver bind/unbind)
3. Setup/Teardown of VMCS PASID translation table entries (KVM)
4. Programming/Clearing host PASID in VDCM (Host VDCM driver)
5. IOASID alloc/free (Host IOASID)

VFIO is the *only* user-kernel interface, which is ultimately
responsible for exception handlings.

#1 is processed the same way as assigned device today based on device
file descriptors and events. There is no special handling.

#4 is naturally aligned with IOASID life cycle in that an illegal
guest PASID programming would fail in obtaining reference of the
matching host IOASID.

#5 is similar to #4. Fault will be reported to the user if PASID used
in the ENQCMD is not set up in VMCS PASID translation table.

Therefore, the remaining out of order problem is between #2 and
#5. I.e. unbind vs. free. More specifically, free before unbind.

IOASID notifier and refcounting are used to ensure ordering. Following
a publisher-subscriber pattern where:

- Publishers: VFIO & IOMMU
- Subscribers: KVM, VDCM, IOMMU

IOASID notifier is atomic which requires subscribers to do quick
handling of the event in atomic context. Workqueue can be used for
any processing that requires thread context. IOASID reference must be
acquired before receiving the FREE event. The reference must be
dropped at the end of the processing in order to return the IOASID to
the pool.
  
Let's example the IOASID life cycle again with free happens before
unbind. This could be a result of misbehaving guest or crash. Assuming
VFIO cannot enforce unbind->free order.

::

     VFIO        IOMMU        KVM        VDCM        IOASID       Ref
   ..................................................................
   1             register_ioasid_notifier(all)
   2 ioasid_alloc()                                  ->           1
   3 bind_gpasid()
   4             ioasid_get()                        ->           2
   5             iommu_bind()
   6             ioasid_notify(BIND)                 ->
   7                          -> ioasid_get()        ->           3
   8                          -> vmcs_update()
   9 mdev_write(gpasid)                 ->
   10                                   ioasid_get() ->           4
   11                                   ioasid_get_hpasid()
   12                                   vdev_write(hpasid)
   13 -------- GUEST STARTS DMA --------------------------
   14 -------- *GUEST MISBEHAVES!!!* ----------------
   15 ioasid_free()
   16                                             ioasid_notify(FREE)
   17                                             mark_ioasid_inactive[1]
   18 ioasid_free() returns                                       3
   19                          rcvd_notify(FREE)
   20                          vmcs_update_atomic()
   21                          ioasid_put()          ->           2
   22                                   rcvd_notify(FREE)
   23                                   vdev_clear_wk(hpasid)
   24            rcvd_notify(FREE)
   25            teardown_pasid_wk()
   26                                   ioasid_put() ->           1
   27            ioasid_put()                                     0
   28                                                 Reclaimed
   29 unbind_gpasid()
   30 ioasid_get() Fails
   31 unbind_gpasid() Returns
   -------------- New Life Cycle Begin ----------------------------


Note:

1. By marking IOASID inactive at step #17, no new references can be
   held. ioasid_get/find() will return -ENOENT;
2. After step #18, all events can go out of order. Shall not affect
   the outcome.

KVM PASID Translation Table Updates
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Per VM PASID translation table is maintained by KVM in order to
support ENQCMD in the guest. The table contains host-guest PASID
translations to be consumed by CPU ucode. The synchronization of the
PASID states depends on VFIO/IOMMU driver, where IOCTL and atomic
notifiers are used. KVM must register IOASID notifier per VM instance
during launch time. The following events are handled:

1. BIND/UNBIND
2. FREE

Rules:
   
1. Multiple devices can bind the same PASID, this can be different PCI
   devices or mdevs within the same PCI deivce. However, only the
   *first* BIND and *last* UNBIND emits notifications.
2. IOASID code is responsible for ensuring the correctness of H-G
   PASID mapping. There is no need for KVM to validate the
   notification data.
3. When UNBIND happens *after* FREE, KVM will see error in
   ioasid_get() even when the reclaim is not done. IOMMU driver will
   also avoid sending UNBIND if the PASID is already FREE.
4. When KVM terminates *before* FREE & UNBIND, references will be
   dropped for all host PASIDs.

VDCM PASID Programming
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
VDCM composes virtual devices and expose them to the guests. When
guest allocates a PASID then program it to the virtual device, VDCM
intercepts the programming attempt then program the matching host
PASID on to the hardware.
Conversely, when a device is going away, VDCM must be informed such
that PASID context on the hardware can be cleared. There could be
multiple mdevs assigned to different guests in the same VDCM. Since
the PASID table is shared at PCI device level, lazy clearing is not
secure. A malicious guest can attack by using newly freed PASIDs that
are allocated by another guest.

By holding a refcount of the PASID until VDCM cleans up the HW context,
it is guaranteed that PASID life cycles does not cross within the same
device.


Reference
====================================================
1. https://software.intel.com/sites/default/files/managed/c5/15/architecture-instruction-set-extensions-programming-reference.pdf

2. https://01.org/blogs/2019/introducing-intel-data-streaming-accelerator

3. https://software.intel.com/en-us/download/intel-data-streaming-accelerator-preliminary-architecture-specification
