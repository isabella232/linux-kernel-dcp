/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#ifndef _SAF_H_
#define _SAF_H_

/* These bits are in the IA32_CORE_CAPABILITIES MSR */
#define MSR_IA32_CORE_CAPS_INTEGRITY_BIT	2
#define MSR_IA32_CORE_CAPS_INTEGRITY		BIT(MSR_IA32_CORE_CAPS_INTEGRITY_BIT)

#endif
