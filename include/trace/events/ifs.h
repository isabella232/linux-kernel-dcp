/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM ifs

#if !defined(_TRACE_IFS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IFS_H

#include <linux/ktime.h>
#include <linux/tracepoint.h>

TRACE_EVENT(ifs_status,

	TP_PROTO(union ifs_scan activate, union ifs_status status),

	TP_ARGS(activate, status),

	TP_STRUCT__entry(
		__field(	u8,	start	)
		__field(	u8,	stop	)
		__field(	u64,	status	)
	),

	TP_fast_assign(
		__entry->start	= activate.start;
		__entry->stop	= activate.stop;
		__entry->status	= status.data;
	),

	TP_printk("start: %.2x, stop: %.2x, status: %llx",
		__entry->start,
		__entry->stop,
		__entry->status)
);

#endif /* _TRACE_IFS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
