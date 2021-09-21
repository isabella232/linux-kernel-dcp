/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Intel Corporation. All rights rsvd. */

#ifndef __IAX_CRYPTO_H__
#define __IAX_CRYPTO_H__

#include <linux/crypto.h>
#include <linux/idxd.h>
#include <uapi/linux/idxd.h>
#include "iax_crypto_stats.h"

#undef pr_fmt
#define	pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#define IAX_DECOMP_ENABLE		BIT(0)
#define IAX_DECOMP_FLUSH_OUTPUT		BIT(1)
#define IAX_DECOMP_CHECK_FOR_EOB	BIT(2)
#define IAX_DECOMP_STOP_ON_EOB		BIT(3)
#define IAX_DECOMP_SUPPRESS_OUTPUT	BIT(9)

#define IAX_COMP_FLUSH_OUTPUT		BIT(1)
#define IAX_COMP_APPEND_EOB		BIT(2)

#define IAX_COMPLETION_TIMEOUT		1000000

#define IAX_ANALYTICS_ERROR		0x0a
#define IAX_ERROR_COMP_BUF_OVERFLOW	0x19
#define IAX_ERROR_WATCHDOG_EXPIRED	0x24

#define DYNAMIC_HDR			0x2
#define DYNAMIC_HDR_SIZE		3

#define IAX_COMP_FLAGS			(IAX_COMP_FLUSH_OUTPUT | \
					 IAX_COMP_APPEND_EOB)

#define IAX_DECOMP_FLAGS		(IAX_DECOMP_ENABLE |	   \
					 IAX_DECOMP_FLUSH_OUTPUT | \
					 IAX_DECOMP_CHECK_FOR_EOB | \
					 IAX_DECOMP_STOP_ON_EOB)

struct iax_wq {
	struct list_head	list;
	struct idxd_wq		*wq;

	struct iax_device	*iax_device;

	u64			comp_calls;
	u64			comp_bytes;
	u64			decomp_calls;
	u64			decomp_bytes;
};

/* Representation of IAX device with wqs, populated by probe */
struct iax_device {
	struct list_head	list;
	struct idxd_device	*idxd;

	int			n_wq;
	struct list_head	wqs;

	u64			comp_calls;
	u64			comp_bytes;
	u64			decomp_calls;
	u64			decomp_bytes;
};

/*
 * Analytics Engine Configuration and State (AECS) contains parameters and
 * internal state of the analytics engine.
 */
struct aecs_table_record {
	u32 crc;
	u32 xor_checksum;
	u32 reserved0[5];
	u32 num_output_accum_bits;
	u8 output_accum[256];
	u32 ll_sym[286];
	u32 reserved1;
	u32 reserved2;
	u32 d_sym[30];
	u32 reserved_padding[2];
};

#if defined(CONFIG_CRYPTO_DEV_IAX_CRYPTO_STATS)
void	global_stats_show(struct seq_file *m);
void	device_stats_show(struct seq_file *m, struct iax_device *iax_device);
void	reset_iax_crypto_stats(void);
void	reset_device_stats(struct iax_device *iax_device);

#else
static inline void	global_stats_show(struct seq_file *m) {}
static inline void	device_stats_show(struct seq_file *m, struct iax_device *iax_device) {}
static inline void	reset_iax_crypto_stats(void) {}
static inline void	reset_device_stats(struct iax_device *iax_device) {}
#endif

#endif
