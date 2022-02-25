Sapphire Rapids Best Known Configuration (BKC) kernel
=====================================================
https://github.com/intel-innersource/os.linux.sapphirerapids.thirdparty.kernel

Purpose
=======
Prepare for releasing public SPR BKC kernel to external and internal customers.
The public SPR BKC kernel will be hosted in a separate public github TBD repository.

SPR feature repositories
========================
Code and descriptions in each repository must only contain public information.
------------------------------------------------------------------------------

SPR-BKC-PC-v4.2
----------------
66. Updated TDX guest (Kirill A. Shutemov):
- https://github.com/intel/tdx.git tdx-guest-v5.15-4

SPR-BKC-PC-v3.21
----------------
65. Fix https://nvd.nist.gov/vuln/detail/CVE-2022-23222 (Mark Horn and Miguel Bernal Marin):
- https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-5.10.y&id=35ab8c9085b0af847df7fac9571ccd26d9f0f513
- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=e60b0d12a95dcf16a63225cead4541567f5cb517
- https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ca796fe66f7fceff17679ee6cc5fe4b4023de44d

64. Add SPR-BKC-PC-v3.config (Jair Gonzalez)

SPR-BKC-PC-v3.20
----------------
63. Fix vIOMMU GIOVA by avoiding reserved IOASIDs (Jacob Pan):

SPR-BKC-PC-v3.19
----------------
62. Remove POC dynamic MSIX allocation code (Dave Jiang):
- https://github.com/intel-sandbox/idxd.git djiang5/bkc-5.15-fixes

SPR-BKC-PC-v3.18
----------------
61. Back port some high/critical Common Vulnerabilities and Exposures (CVE) fixes from upstream (Mark Horn):
- commit: ec6af094ea28f0f2dda1a6a33b14cd57e36a9755
- commit: f9d87929d451d3e649699d0f1d74f71f77ad38f5
- commit: dfd0743f1d9ea76931510ed150334d571fbab49d
- commit: 83912d6d55be10d65b5268d1871168b9ebe1ec4b
- commit: 054aa8d439b9185d4f5eb9a90282d1ce74772969

SPR-BKC-PC-v3.17
----------------
60. Fix WQ config fails with sm_off (Dave Jiang):
- https://github.com/intel-sandbox/idxd.git djiang5/bkc-5.15-fixes

59. Revert IOASID range adjustment (Jacob Pan):
- https://github.com/intel-sandbox/idxd.git djiang5/bkc-5.15-fixes

SPR-BKC-PC-v3.16
----------------
58. Fix ZSWAP breakage (Tom Zanussi):
- https://github.com/intel-sandbox/idxd.git tzanussi/iax-crypto-5.15-bkc-v2

57. Rollback microcode (Ashok Raj):
- https://github.com/intel-innersource/os.linux.packaging.io4l.bkc-centos-stream-8.kernel-spr-bkc-pc.git

56. Fix TDX seamcall (Isaku Yamahata):
- 0001-REVERTME-KVM-TDX-Retry-seamcall-when-TDX_OPERAND_BUS.patch

SPR-BKC-PC-v3.15
----------------
55. Fix a NULL domain issue in IOMMU (Jacob Pan):

SPR-BKC-PC-v3.14
----------------
54. Check on PT SRE support on stepping (Jacob Pan):
- https://github.com/intel-sandbox/linux-svm-kernel.git SPR-BKC-PC-v3.5-dma-pasid-nowa

SPR-BKC-PC-v3.13
----------------
53. Enable PASID for DMA API users (Jacob Pan):
- https://github.com/intel-sandbox/linux-svm-kernel.git SPR-BKC-PC-v3.5-dma-pasid-nowa

SPR-BKC-PC-v3.12
----------------
52. sched/fair: Force progress on min_vruntime (Tim Chen):
- https://git.kernel.org/pub/scm/linux/kernel/git/peterz/queue.git sched/wip.migrate

SPR-BKC-PC-v3.11
----------------
51. dmaengine: idxd: restore traffic class defaults after wq reset (Dave Jiang):
- https://github.com/intel-sandbox/idxd/commit/594690f7b81e7fbc3dc8e967ac8fd1e977067020

SPR-BKC-PC-v3.10
----------------
50. Fix VMD booting issue (Adrian Huang <ahuang12@lenovo.com>):
- 5.16 commit: 2565e5b69c44b4e42469afea3cc5a97e74d1ed45

SPR-BKC-PC-v3.9
----------------
49. Sequential split lock (Tony Luck):

SPR-BKC-PC-v3.8
----------------
48. SST HFI (Pandruvada, Srinivas):
- https://gitlab.devtools.intel.com/spandruv/linux-po-spr.git  SPR-BKC-PC-v3.4

SPR-BKC-PC-v3.7
----------------
47. More IDXD fixes (Dave Jiang):
- https://github.com/intel-sandbox/idxd.git   djiang5/bkc-5.15-fixes

SPR-BKC-PC-v3.6
----------------
46. Update AMX KVM to upstream version (tip for 5.17) (Yang Zhong):
- https://gitlab.devtools.intel.com/yangzhon/amx-kvm.git  amx-bkc-backport

SPR-BKC-PC-v3.5
----------------
45. IDXD fix (Dave Jiang):

SPR-BKC-PC-v3.4
----------------
44. TDX: fix nosmap booting issue (Kirill Shutemov)

SPR-BKC-PC-v3.3
----------------
43. x86/microcode: adjust sequence of controlling KVM guest and EPC (Cathy Zhang)

SPR-BKC-PC-v3.2
----------------
42. Fix TDX issue (Chenyi Qiang):
- 0001-x86-cpu-tdx-Fix-the-seamcall-invalid-op-issue.patch
- 0002-DMA-SWIOTLB-Retry-memory-allocation-when-fails-from-.patch

41. Arch-lbr (Weijiang Yang);
- https://gitlab.devtools.intel.com/yangweij/kvm-pmu.git  SPR-BKC-PC-v3.1-arch-lbr

40. Fix TDX issue in LCK-10779 (Kirill Shutemov):

SPR-BKC-PC-v3.1
----------------
39.  iommu/vt-d: Fix PCI bus rescan device hot add (Jacob Pan):
- 0001-iommu-vt-d-Fix-PCI-bus-rescan-device-hot-add.patch 

SPR-BKC-PC-v2.10
----------------
38. Enable MDEV and VFIO (Dave Jiang and Yi Liu):
- https://github.com/intel-sandbox/idxd.git  djiang5/bkc-5.15-work

SPR-BKC-PC-v2.9
----------------
37. Fix TDX issues (Chenyi Qiang):
- Fix: LCK-10844. TDX: SEAM: check the tdx_host parameter to avoid NULL pointer dereference
- Fix: LCK-10807, LCK-10725, LCK-10827. efi/x86-stub: force boot_params-accepted_memory to 0 when no unaccepted memory

SPR-BKC-PC-v2.8
----------------
36. Add SPR-BKC-PC-v2.config (Miguel Bernal Martin):
https://github.com/miguelinux/os.linux.sapphirerapids.thirdparty.kernel update-kconfig-to-v2

SPR-BKC-PC-v2.7
----------------
35. Prevent SGX reclaimer from running during SGX SVN update (Cathy Zhang):
https://github.com/bjzhjing/os.linux.sapphirerapids.thirdparty.kernel sgx/edmm-seamless-spr-bkc-v1.22

SPR-BKC-PC-v2.6
----------------
34. Perf Inject fix itrace space allowed for new attributes (Adrian Hunter):
0001-perf-inject-Fix-itrace-space-allowed-for-new-attribu.patch

SPR-BKC-PC-v2.5
----------------
33. firmware updates/telemetry support (Chen, Yu C):
0001-efi-Introduce-EFI_FIRMWARE_MANAGEMENT_CAPSULE_HEADER.patch
0002-ACPI-Introduce-Platform-Firmware-Runtime-Update-devi.patch
0003-ACPI-Introduce-Platform-Firmware-Runtime-Telemetry.patch
0004-ACPI-tools-Introduce-utility-for-firmware-updates-te.patch

SPR-BKC-PC-v2.4
----------------
31. VM Preserving Run-time Fixes (Chao Gao)
https://gitlab.devtools.intel.com/cqiang/linux.git  for-bkc-12-24
32. TDVMCALL[GetQuote] driver (Chenyi Qiang)
https://gitlab.devtools.intel.com/cqiang/linux.git  for-bkc-12-24

SPR-BKC-PC-v2.3
----------------
30. IAX Crypto (Dave Jiang):
https://github.com/intel-sandbox/idxd.git    djiang5/bkc-5.15-iax

SPR-BKC-PC-v2.2
----------------
28. SGX EDMM (Reinette Chatre):
https://github.com/bjzhjing/os.linux.sapphirerapids.thirdparty.kernel sgx/edmm-seamless-spr-bkc-v1.22

29. Updated SGX Seamless (old one reverted) (Cathy Zhang):
https://github.com/bjzhjing/os.linux.sapphirerapids.thirdparty.kernel sgx/edmm-seamless-spr-bkc-v1.22

SPR-BKC-PC-v2.1
----------------
24. AMX fixes (Chang Seok Bae):
0001-signal-Skip-the-altstack-update-when-not-needed.patch
0001-x86-fpu-Optimize-out-sigframe-xfeatures-when-in-init.patch
0001-x86-fpu-signal-Initialize-sw_bytes-in-save_xstate_ep.patch

25. TDX fixes (Chao Gao):
https://gitlab.devtools.intel.com/cqiang/linux.git  for-bkc-12-16

26. VM Preserving Run-time (Chao Gao):
https://gitlab.devtools.intel.com/cqiang/linux.git  for-bkc-12-16

27. TDX Guest fixes (Kirill):
Updated to the latest TDX Guest

SPR-BKC-PC-v1.23
----------------
22. SPR-BKC-PC-v1.config (Gonzalez Plascencia, Jair De Jesus)
https://github.com/intel-innersource/os.linux.packaging.io4l.bkc-centos-stream-8.kernel-spr-bkc-pc/blob/cs8-spr-1.22-0.el8/kernel-x86_64-intel.config

23. Seamless (Yu Chen):
Four patches

SPR-BKC-PC-v1.22
----------------
21. SPR BKC PC kernel banne (Fenghua Yu):
0001-x86-boot-Print-an-SPR-BKC-PC-kernel-banner.patch

SPR-BKC-PC-v1.21
----------------
20. KVM TDP/TDX fixes (Chao Gao):
https://gitlab.devtools.intel.com/cqiang/linux.git    for-bkc-12-8

SPR-BKC-PC-v1.20
----------------
19. SPI-NOR (Mika Westerberg):
https://gitlab.devtools.intel.com/mwesterb/linux.git spi-for-SPR-BKC-PC-v1.rc7

SPR-BKC-PC-v1.19
----------------
18. AMX-KVM (Jing Liu):
https://gitlab.devtools.intel.com/liujing/amx-kvm.git spr-bkc-amx

SPR-BKC-PC-v1.18
----------------
17. SDSI (Dave Box):
https://gitlab.devtools.intel.com/kyungmin/iommu.git v5.15-sdsi-for-spr

SPR-BKC-PC-v1.17
----------------
16. SGX Seamless fix (Cathy Zhang):
https://github.com/bjzhjing/os.linux.sapphirerapids.thirdparty.kernel.git sgx-seamless-spr-bkc-v1.15

SPR-BKC-PC-v1.16
----------------
15. SAF (Jithu Joseph and Kyung Min Park):
https://gitlab.devtools.intel.com/kyungmin/iommu.git   forbkc

SPR-BKC-PC-v1.15
----------------
14. SEAM TDX bug fix (Chenyi Qiang)

SPR-BKC-PC-v1.14
----------------
13. SIOV (Jacob Pan):
https://github.com/intel-sandbox/linux-svm-kernel.git  SPR-BKC-PC-v1.rc7.siov

SPR-BKC-PC-v1.13
----------------
12. DSA/IAX (Dave Jiang):
https://github.com/intel-sandbox/idxd     djiang5/bkc-5.15

SPR-BKC-PC-v1.12
----------------

Linux kernel 5.15+tip/x86/fpu+following features.

tip/x86/fpu top commit: d7a9590f608d
    Documentation/x86: Add documentation for using dynamic XSTATE features

1. AMX (Chang Seok Bae):
tip/x86/fpu
2. ENQCMD and PASID (Fenghua Yu):
gitlab.devtools.intel.com/fyu1/kernel     pasid_spr_bkc
3. PKS (Ira Weiny):
https://github.com/intel-sandbox/iweiny-0day-linux-kernel.git pks-po-spr-5.15-01-11-2021
4. TDX for guest (Kuppuswamy Sathyanarayanan):
https://github.com/intel/tdx.git       guest
5. SGX Reset (Yang Zhong):
https://gitlab.devtools.intel.com/yangzhon/amx-kvm.git    sgx-reset
6. KVM Interrupt (Guang Zeng):
https://gitlab.devtools.intel.com/zengguan/bkc-kvm-INT.git   BKC-KVM-int
7. SGX Seamless (Cathy Zhang):
https://github.com/bjzhjing/os.linux.sapphirerapids.thirdparty.kernel.git sgx-seamless-spr-bkc-5.15
8. PKS-KVM and Notify VM Exit (Chenyi Qiang):
https://gitlab.devtools.intel.com/cqiang/linux.git   for-bkc
9. HFI (Ricardo Neri and Srinivas Pandruvada):
https://gitlab.devtools.intel.com/ranerica/linux-dev.git   rneri/hfi-for-SPR-BKC-PC-v1.rc5
10. TDX for host (Yuan Yao):
https://github.com/YuanYao0329/os.linux.sapphirerapids.thirdparty.kernel tdx-host-v1.9-ready
11. Fixes for TDX host and KVM (Yuan Yao):
https://github.com/YuanYao0329/os.linux.sapphirerapids.thirdparty.kernel host-tdx-quick-fix-for-SPR-BKC-PC-v1.10
