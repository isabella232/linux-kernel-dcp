Purpose
=======
Provide Best Known Configuration (BKC) kernel for Sapphire Rapids (SPR)
customers.

The BKC kernel is based on v5.15. New SPR feautre patches which are not
in v5.15 are added to the BKC kernel.

The public SPR BKC kernel is hosted in https://github.com/intel/linux-kernel-dcp

WARNING this kernel contains technology preview code that is
subject to change once it goes upstream. This kernel is
strictly for hardware validation, not production. Applications
tested against this kernel may behave differently, or may not
operate at all once the code is finalized in the mainline kernel.
Use at your own risk.

Release History
===============

SPR-BKC-PC-v2.1
---------------
27. AMX fixes (Chang Seok Bae)

26. TDX fixes (Chao Gao)

25. VM Preserving Run-time (Chao Gao)

24. TDX Guest fixes (Kirill)

SPR-BKC-PC-v1.23
----------------
23. SPR-BKC-PC-v1.config (Gonzalez Plascencia, Jair De Jesus)
22. Seamless (Yu Chen)

SPR-BKC-PC-v1.22
----------------
21. SPR BKC PC kernel banne (Fenghua Yu)

SPR-BKC-PC-v1.21
----------------
20. KVM TDP/TDX fixes (Chao Gao)

SPR-BKC-PC-v1.20
----------------
19. SPI-NOR (Mika Westerberg)

SPR-BKC-PC-v1.19
----------------
18. AMX-KVM (Jing Liu)

SPR-BKC-PC-v1.18
----------------
17. SDSI (Dave Box)

SPR-BKC-PC-v1.17
----------------
16. SGX Seamless fix (Cathy Zhang):

SPR-BKC-PC-v1.16
----------------
15. SAF (Jithu Joseph and Kyung Min Park):

SPR-BKC-PC-v1.15
----------------
14. SEAM TDX bug fix (Chenyi Qiang)

SPR-BKC-PC-v1.14
----------------
13. SIOV (Jacob Pan)

SPR-BKC-PC-v1.13
----------------
12. DSA/IAX (Dave Jiang):

SPR-BKC-PC-v1.12
----------------

Linux kernel 5.15+tip/x86/fpu+following features.

tip/x86/fpu top commit: d7a9590f608d
    Documentation/x86: Add documentation for using dynamic XSTATE features

1. AMX (Chang Seok Bae)
2. ENQCMD and PASID (Fenghua Yu)
3. PKS (Ira Weiny)
4. TDX for guest (Kuppuswamy Sathyanarayanan)
5. SGX Reset (Yang Zhong)
6. KVM Interrupt (Guang Zeng)
7. SGX Seamless (Cathy Zhang)
8. PKS-KVM and Notify VM Exit (Chenyi Qiang)
9. HFI (Ricardo Neri and Srinivas Pandruvada)
10. TDX for host (Yuan Yao)
11. Fixes for TDX host and KVM (Yuan Yao)
