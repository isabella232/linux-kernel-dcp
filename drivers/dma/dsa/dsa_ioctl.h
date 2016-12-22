#ifndef __DSA_IOCTL_H__
#define __DSA_IOCTL_H__

#ifndef __KERNEL__
#include <sys/ioctl.h>
#endif

struct dsa_wq_alloc_req {
	int dedicated;
	int size;
	int wq_idx;
	unsigned long gencap;
	unsigned long opcap;
};

struct dsa_wq_drain_req {
	int shared;
	int size;
};

struct dsa_submit_desc_req {
	struct dsa_dma_descriptor desc;
	int wq_idx;
};

#define DSA_IOCTL_BASE                  'e'

#define DSA_IOCTL_WQ_ALLOC		_IOWR(DSA_IOCTL_BASE, 0x00, struct dsa_wq_alloc_req)
#define DSA_IOCTL_WQ_FREE		_IOWR(DSA_IOCTL_BASE, 0x01, struct dsa_wq_alloc_req)
#define DSA_IOCTL_WQ_DRAIN		_IOWR(DSA_IOCTL_BASE, 0x02, struct dsa_wq_drain_req)
#define DSA_IOCTL_SUBMIT_DESC		_IOW(DSA_IOCTL_BASE, 0x03, struct dsa_submit_desc_req)
#define DSA_IOCTL_COMPLETION_WAIT	_IO(DSA_IOCTL_BASE, 0x04)

#endif
