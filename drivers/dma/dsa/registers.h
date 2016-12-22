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
#define DSA_OPCAP_OFFSET			0x30
#define DSA_GENCFG_OFFSET        		0x50
#define DSA_GENCTRL_OFFSET	        	0x58
#define DSA_ENABLE_OFFSET	        	0x60
#define DSA_INTCAUSE_OFFSET			0x68
#define DSA_CMD_OFFSET				0x70
#define DSA_SWERR_OFFSET   	        	0x80
#define DSA_HWERR_OFFSET   	        	0x90

#define DSA_GRPCFG_OFFSET			0x1000
#define DSA_WQCFG_OFFSET			0x2000
#define DSA_PERF_OFFSET	        		0x4000

#define DSA_MSIX_TABLE_OFFSET	       		0x2000
#define DSA_MSIX_PBA_OFFSET	       		0x3000
#define DSA_IMS_OFFSET   	       		0x4000

#define DSA_VER_MAJOR_MASK			0xF0
#define DSA_VER_MINOR_MASK			0x0F
#define GET_DSA_VER_MAJOR(x)			(((x) & DSA_VER_MAJOR_MASK) >> 4)
#define GET_DSA_VER_MINOR(x)			((x) & DSA_VER_MINOR_MASK)

/* General Control */
#define DSA_GENCTRL_HWERR_ENABLE		0x1
#define DSA_GENCTRL_SWERR_ENABLE		0x2

/* General Capabilities */
#define DSA_CAP_BLOCK_ON_FAULT			0x0000000000000001
#define DSA_CAP_DEST_CACHE_FILL			0x0000000000000002
#define DSA_CAP_IMS				0x0000000000000040
#define DSA_CAP_DEST_RDBACK			0x0000000000000100
#define DSA_CAP_DUR_WRITE			0x0000000000000200

#define DSA_CAP_MAX_BATCH_MASK			0x00000000FFFF0000
#define DSA_CAP_MAX_BATCH_SHIFT			16

#define DSA_CAP_MAX_XFER_MASK			0x0000000F00000000
#define DSA_CAP_MAX_XFER_SHIFT			32

#define DSA_CAP_IMS_MASK			0x000003F000000000
#define DSA_CAP_IMS_SHIFT			36

#define DSA_CAP_USER_MASK  (DSA_CAP_BLOCK_ON_FAULT | DSA_CAP_DEST_CACHE_FILL | \
			DSA_CAP_DEST_RDBACK | DSA_CAP_DUR_WRITE | \
			DSA_CAP_MAX_BATCH_MASK | DSA_CAP_MAX_XFER_MASK)

/* Work Queue Capabilities */
#define DSA_CAP_SWQ				0x0001000000000000
#define DSA_CAP_DWQ				0x0002000000000000
#define DSA_CAP_WQCONFIG			0x0004000000000000

#define DSA_CAP_WQ_SIZE_MASK			0x000000000000FFFF

#define DSA_CAP_MAX_WQ_MASK			0x0000000000FF0000
#define DSA_CAP_MAX_WQ_SHIFT			16

#define DSA_CAP_MAX_ENG_MASK			0x00000000FF000000
#define DSA_CAP_MAX_ENG_SHIFT			24

#define DSA_ENABLE_BIT			0x1
#define DSA_ENABLED_BIT			0x2
#define DSA_RESET_BIT			0x4
#define DSA_ERR_BITS			0xFF00

#define MEMMOVE_SUPPORT_BIT		0x8
#define MEMMOVE_SUPPORT(opcap)		(opcap & MEMMOVE_SUPPORT_BIT)

#define MEMFILL_SUPPORT_BIT		0x10
#define MEMFILL_SUPPORT(opcap)		(opcap & MEMFILL_SUPPORT_BIT)

#define DSA_WQ_ENABLE_BIT			0x1
#define DSA_WQ_ENABLED_BIT			0x2
#define DSA_WQ_ERR_BITS				0xFF00

#define DSA_INTCAUSE_HWERR		0x1
#define DSA_INTCAUSE_SWERR		0x2
#define DSA_INTCAUSE_CMD_COMPLETION	0x4
#define DSA_INTCAUSE_WQ_OCCUPANCY	0x8

union dsa_command_reg {
	struct {
		uint32_t operand:20;
		uint32_t rci:1;
		uint32_t rsvd:3;
#define DRAIN_ALL    1
#define DRAIN_PASID  2
#define DRAIN_WQ     3
#define DRAIN_CMD_TIMEOUT    10000
		uint32_t cmd:4;
		uint32_t abort:1;
		uint32_t rsvd2:2;
		uint32_t status:1;
	}fields;
	uint32_t val;
};

#endif /* _DSA_REGISTERS_H_ */
