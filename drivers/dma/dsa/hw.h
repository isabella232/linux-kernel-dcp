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
#ifndef _DSA_HW_H_
#define _DSA_HW_H_

/* PCI Configuration Space Values */
#define DSA_MMIO_BAR		0
#define DSA_WQ_BAR		2
#define DSA_GUEST_WQ_BAR	4

/* CB device ID's */
#define PCI_DEVICE_ID_INTEL_DSA_SPR0	0x6f30

#define DSA_VER_1_0            0x100    /* Version 1.0 */


/* descriptor flags */
#define DSA_OP_FLAG_FNC    0x1
#define DSA_OP_FLAG_BOF    0x2
#define DSA_OP_FLAG_CRAV   0x4
#define DSA_OP_FLAG_RCR    0x8
#define DSA_OP_FLAG_RCI    0x10
#define DSA_OP_FLAG_IMS    0x20
#define DSA_OP_FLAG_CQE    0x40
#define DSA_OP_FLAG_CR     0x80
#define DSA_OP_FLAG_DCF    0x100
#define DSA_OP_FLAG_DNSNP  0x200
#define DSA_OP_FLAG_STORD  0x2000
#define DSA_OP_FLAG_DRDBK  0x4000

/* Opcode */

#define DSA_OPCODE_MEMMOVE   0x3
#define DSA_OPCODE_BATCH     0x1

/* Completion record status */
#define DSA_COMP_SUCCESS         0x1
#define DSA_COMP_SUCCESS_PRED    0x2

struct dsa_dma_descriptor {
	uint32_t	pasid:20;
	uint32_t	rsvd:11;
	uint32_t	u_s:1;
	uint32_t	flags:24;
	uint32_t	opcode:8;
	uint64_t	compl_addr;
	uint64_t	src_addr;
	uint64_t	dst_addr;
	uint32_t	xfer_size;
	uint16_t	int_handle;
	union {
		uint16_t	op_specific[13];
		//struct dsa_move_desc  memmove;
		//struct dsa_fill_desc  memfill;
		//struct dsa_cmp_desc   compare;
		//struct dsa_cmpimm_desc cmpimmd;
		//struct dsa_cdelta_desc cdelta;
		//struct dsa_adelta_desc adelta;
		//struct dsa_dcast_desc  dcast;
		//struct dsa_crc_desc    crc;
		//struct dsa_copy_crc_desc cp_crc;
		//struct dsa_difins_desc  difins;
		//struct dsa_difstrp_desc difstrp;
		//struct dsa_difupdt_desc difupdt;
		//struct dsa_cflush_desc  cflush;
	};
};

struct dsa_raw_descriptor {
	uint64_t        field[8];
};

struct dsa_completion_record {
	uint8_t 	status;
	uint8_t		fault_code;
	uint8_t		rsvd;
	uint8_t		idx;
	uint32_t	bytes_completed;
	uint64_t	fault_addr;
	union {
		uint64_t	op_specific[2];
		//struct dsa_cdelta_completion  cdelta;

	};
};

struct dsa_raw_completion_record {
	uint64_t        field[4];
};

#endif
