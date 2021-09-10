/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright(c) 2021 Intel Corporation.
 *
 * Author: Kyung Min Park <kyung.min.park@intel.com>
 */

#ifndef _SAF_SYSFS_H_
#define _SAF_SYSFS_H_

extern int trigger_mce;
extern int thread_wait;
extern bool quiet;
extern bool noint;

extern const struct attribute_group scan_attr_group;
extern const struct attribute_group cpu_scan_attr_group;
extern const struct attribute_group *cpu_scan_attr_groups[];

#endif
