/*
 * Copyright(c) 2004 - 2009 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called COPYING.
 */
#ifndef _DSA_REGISTERS_H_
#define _DSA_REGISTERS_H_

/* PCI Config Space Registers */
#define DSA_PCI_DEVICE_ID_OFFSET               0x02

/* MMIO Device BAR-0 Registers */
#define DSA_VER_OFFSET		        	0x0
#define DSA_GENCAP_OFFSET			0x10
#define DSA_WQCAP_OFFSET			0x20
#define DSA_GRPCAP_OFFSET			0x30
#define DSA_ENGCAP_OFFSET			0x38
#define DSA_OPCAP_OFFSET			0x40
#define DSA_TABLE_OFFSET			0x60

#define DSA_GENCFG_OFFSET        		0x80
#define DSA_GENCTRL_OFFSET	        	0x88
#define DSA_GENSTS_OFFSET	        	0x90
#define DSA_INTCAUSE_OFFSET			0x98
#define DSA_CMD_OFFSET				0xA0
#define DSA_CMDSTS_OFFSET			0xA4
#define DSA_SWERR_OFFSET   	        	0xC0
#define DSA_HWERR_OFFSET   	        	0xE0
#define DSA_LOWBW_BASE_OFFSET 	        	0x100

/*
#define DSA_GRPCFG_OFFSET			0x1000
#define DSA_WQCFG_OFFSET			0x2000
#define DSA_PERF_OFFSET	        		0x4000

#define DSA_MSIX_TABLE_OFFSET	       		0x6000
#define DSA_MSIX_PBA_OFFSET	       		0x7000
#define DSA_IMS_OFFSET   	       		0x8000
*/

#define DSA_VER_MAJOR_MASK			0xF0
#define DSA_VER_MINOR_MASK			0x0F
#define GET_DSA_VER_MAJOR(x)			(((x) & DSA_VER_MAJOR_MASK) >> 4)
#define GET_DSA_VER_MINOR(x)			((x) & DSA_VER_MINOR_MASK)

/* General Capabilities */
#define DSA_CAP_BLOCK_ON_FAULT			0x0000000000000001
#define DSA_CAP_OVERLAP_COPY			0x0000000000000002
#define DSA_CAP_CACHE_MEM_CTRL			0x0000000000000004
#define DSA_CAP_CACHE_FLUSH_CTRL		0x0000000000000008
#define DSA_CAP_INT_HANDLE			0x0000000000000080
#define DSA_CAP_DEST_RDBACK			0x0000000000000100
#define DSA_CAP_DUR_WRITE			0x0000000000000200

#define DSA_CAP_MAX_XFER_MASK			0x00000000001F0000
#define DSA_CAP_MAX_XFER_SHIFT			16

#define DSA_CAP_MAX_BATCH_MASK			0x0000000001E00000
#define DSA_CAP_MAX_BATCH_SHIFT			21

#define DSA_CAP_IMS_MASK			0x000000007E000000
#define DSA_CAP_IMS_SHIFT			25
#define DSA_CAP_IMS_MULTIPLIER			256

#define DSA_CAP_CONFIG				0x0000000080000000

#define DSA_CAP_DESC_IN_PROGRESS		0x000000FF00000000
#define DSA_CAP_DESC_IN_PROGRESS_SHIFT		32

#define DSA_CAP_MAX_LOW_BW_RANGES		0x00000F0000000000
#define DSA_CAP_LOW_BW_RANGES_SHIFT		40

#define DSA_CAP_USER_MASK  (DSA_CAP_BLOCK_ON_FAULT | DSA_CAP_OVERLAP_COPY \
			| DSA_CAP_CACHE_MEM_CTRL | DSA_CAP_CACHE_FLUSH_CTRL \
			| DSA_CAP_DEST_RDBACK | DSA_CAP_DUR_WRITE)

/* Work Queue Capabilities */
#define DSA_CAP_WQ_SIZE_MASK			0x000000000000FFFF

#define DSA_CAP_MAX_WQ_MASK			0x0000000000FF0000
#define DSA_CAP_MAX_WQ_SHIFT			16

#define DSA_CAP_SWQ				0x0001000000000000
#define DSA_CAP_DWQ				0x0002000000000000
#define DSA_CAP_ORDERING			0x0004000000000000
#define DSA_CAP_PRIORITY			0x0008000000000000
#define DSA_CAP_OCCUPANCY			0x0010000000000000
#define DSA_CAP_OCCUPANCY_INT			0x0020000000000000

/* Group Capabilities */
#define DSA_CAP_MAX_GRP_MASK			0x00000000000000FF

#define DSA_CAP_BW_TOKEN_MASK			0x000000000000FF00
#define DSA_CAP_BW_TOKEN_SHIFT			8

/* Engine Capabilities */
#define DSA_CAP_MAX_ENG_MASK			0x00000000000000FF

/* Operations capabilities */

/* Table Offsets */
#define DSA_TABLE_GRPCFG_MASK			0x000000000000FFFF

#define DSA_TABLE_WQCFG_MASK			0x00000000FFFF0000
#define DSA_TABLE_WQCFG_SHIFT			16

#define DSA_TABLE_MSIX_PERM_MASK		0x0000FFFF00000000
#define DSA_TABLE_MSIX_PERM_SHIFT		32

#define DSA_TABLE_IMS_MASK			0xFFFF000000000000
#define DSA_TABLE_IMS_SHIFT			48

/* General Config */
#define DSA_GENCTRL_STEERTAG_MASK		0x000000FF

#define DSA_GENCTRL_DUR_STEERTAG_MASK		0x0000FF00
#define DSA_GENCTRL_DUR_STEERTAG_SHIFT		8

#define DSA_GENCTRL_LOWBW_LIMIT_MASK		0x00FF0000
#define DSA_GENCTRL_LOWBW_LIMIT_SHIFT		16

#define DSA_GENCTRL_LOWBW_RANGE_ENABLE		0x80000000

/* General Control */
#define DSA_GENCTRL_HWERR_ENABLE		0x1
#define DSA_GENCTRL_SWERR_ENABLE		0x2

/* General Status */
#define DSA_GENSTS_STATE_MASK			0x3

#define DSA_GENSTS_DISABLED			0x0
#define DSA_GENSTS_ENABLED			0x1
#define DSA_GENSTS_DISABLE_IN_PROGRESS		0x2

/* Interrupt Cause */
#define DSA_INTCAUSE_HWERR		0x1
#define DSA_INTCAUSE_SWERR		0x2
#define DSA_INTCAUSE_CMD_COMPLETION	0x4
#define DSA_INTCAUSE_WQ_OCCUPANCY	0x8

/* Commands */
union dsa_command_reg {
	struct {
		uint32_t operand:20;
		uint32_t cmd:5;
		uint32_t rsvd:6;
		uint32_t rci:1;
	}fields;
	uint32_t val;
};

#define DSA_ENABLE		1
#define DSA_DISABLE		2
#define DSA_DRAIN_ALL		3
#define DSA_ABORT_ALL		4
#define DSA_RESET		5
#define DSA_ENABLE_WQ		6
#define DSA_DISABLE_WQ		7
#define DSA_DRAIN_WQ		8
#define DSA_ABORT_WQ		9
#define DSA_RESET_WQ		10
#define DSA_DRAIN_PASID		11
#define DSA_ABORT_PASID		12
#define DSA_INT_HANDLE		13
#define DRAIN_CMD_TIMEOUT    100

/* Command Status */
#define DSA_CMD_ERRCODE_MASK		0xFF

#define DSA_CMD_ACTIVE			0x80000000

#define DSA_CMD_SUCCESS			0x0

/* swerror */
struct dsa_swerr_reg {
	union {
		struct {
                        u64 valid:1;
                        u64 overflow:1;
			u64 desc_valid:1;
			u64 wqidx_valid:1;
			u64 batch:1;
			u64 rw:1;
			u64 priv:1;
			u64 rsvd:1;
			u64 err_code:8;
			u64 wq_idx:8;
			u64 rsvd1:8;
			u64 op:8;
			u64 pasid:20;
			u64 rsvd2:4;
                }qw1_fields;
                u64     val;
        }qw1;

        union {
                struct {
                        u64 batch_idx:16;
                        u64 inval_flags:24;
                        u64 rsvd3:24;
                }qw2_fields;
                u64     val;
        }qw2;

	u64 qw3_address;

	u64 qw4_rsvd4;
};

/* Miscellaneous */
#define MEMMOVE_SUPPORT_BIT		0x8
#define MEMMOVE_SUPPORT(opcap)		(opcap & MEMMOVE_SUPPORT_BIT)

#define MEMFILL_SUPPORT_BIT		0x10
#define MEMFILL_SUPPORT(opcap)		(opcap & MEMFILL_SUPPORT_BIT)

#endif /* _DSA_REGISTERS_H_ */
