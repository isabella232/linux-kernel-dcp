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
