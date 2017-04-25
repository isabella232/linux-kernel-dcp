#ifndef __DSA_VDCM_H__
#define __DSA_VDCM_H__


/* MMIO bits */
#define DSA_CMD_INT_MASK  0x100000

#define DSA_MDEV_NAME_LEN  16
#define DSA_MDEV_DESCRIPTION_LEN  64

#define DSA_MDEV_TYPE_1_DWQ_0_SWQ 0
#define DSA_MDEV_TYPE_0_DWQ_1_SWQ 1
#define DSA_MDEV_TYPES  2

struct vdcm_dsa_type {
	char name[DSA_MDEV_NAME_LEN];
	char description[DSA_MDEV_DESCRIPTION_LEN];
	int type;
	unsigned int avail_instance;
};

#define VDSA_MAX_CFG_SPACE_SZ 4096

#define VDSA_CAP_CTRL_SZ 0xB0
#define VDSA_GRP_CTRL_SZ 0x100
#define VDSA_WQ_CTRL_SZ  0x80
#define VDSA_WQ_OCPY_INT_SZ 0x20
#define VDSA_MSIX_TBL_SZ  0x90

/* two 64-bit BARs implemented */
#define VDSA_MAX_BARS  3


#define VDSA_MAX_WQS  8

#define VDSA_BAR0_SIZE  0x10000
#define VDSA_BAR2_SIZE  0x80000

#define VDSA_BAR2_WQ_NP_OFFSET  0x0
#define VDSA_BAR2_WQ_P_OFFSET  0x8000

enum {
	VDSA_ATS_OFFSET = 0x100,
	VDSA_PRS_OFFSET = 0x110,
	VDSA_PASID_OFFSET = 0x120,
};

struct ims_irq_entry {
	struct vdcm_dsa *vdsa;
	int int_src;
};

#define VDSA_MSIX_TBL_SZ_OFFSET  0x42
struct vdcm_dsa_pci_bar0 {
	u8 cap_ctrl_regs[VDSA_CAP_CTRL_SZ];
	u8 grp_ctrl_regs[VDSA_GRP_CTRL_SZ];
	u8 wq_ctrl_regs[VDSA_WQ_CTRL_SZ];
	u8 wq_ocpy_int_regs[VDSA_WQ_OCPY_INT_SZ];
	u8 msix_table[VDSA_MSIX_TBL_SZ];
	u16 msix_pba;
};

#define VDSA_MAX_MSIX_ENTRIES  (VDSA_MSIX_TBL_SZ/0x10)

struct dsa_vdev {
	struct mdev_device *mdev;
	struct vfio_region *region;
	int num_regions;
	struct eventfd_ctx *msix_trigger[VDSA_MAX_MSIX_ENTRIES];
	struct rb_root cache;
	struct mutex cache_lock;
	struct notifier_block iommu_notifier;
	struct notifier_block group_notifier;
	struct kvm *kvm;
	struct work_struct release_work;
	atomic_t released;
};

struct vdcm_dsa {
	struct dsadma_device *dsa;
	struct dsa_work_queue *wqs[VDSA_MAX_WQS];
	int num_wqs;
	int id;
	struct list_head next;
	struct vdcm_dsa_type  *type;

	unsigned long handle;
	u64 pasid[8];
	u64 ims_index[VDSA_MAX_WQS];
	struct msix_entry ims_entries[VDSA_MAX_WQS];
	struct ims_irq_entry irq_entries[VDSA_MAX_WQS];

	u64 bar_val[VDSA_MAX_BARS];
	u64 bar_size[VDSA_MAX_BARS];

	u8 cfg[VDSA_MAX_CFG_SPACE_SZ];
	struct vdcm_dsa_pci_bar0 bar0;

	struct dsa_vdev  vdev;
};

struct vdsa_ops {
	int (*emulate_cfg_read)(struct vdcm_dsa *, unsigned int, void *,
				unsigned int);
	int (*emulate_cfg_write)(struct vdcm_dsa *, unsigned int, void *,
				unsigned int);
	int (*emulate_mmio_read)(struct vdcm_dsa *, u64, void *,
				unsigned int);
	int (*emulate_mmio_write)(struct vdcm_dsa *, u64, void *,
				unsigned int);
	struct vdcm_dsa *(*vdsa_create) (struct dsadma_device *dsa,
				struct vdcm_dsa_type *);
	void (*vdsa_destroy)(struct vdcm_dsa *);
	void (*vdsa_reset)(struct vdcm_dsa *);
};

#endif

