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

Features cannot be merged to SPR BKC kernel
-------------------------------------------
1. SAF (KM Park):
The SAF spec will be available in Nov.
