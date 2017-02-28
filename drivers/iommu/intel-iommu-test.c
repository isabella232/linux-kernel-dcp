/* Intel IOMMU test driver Based on pci-stub
 */
#define DEBUG
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/intel-iommu.h>
#include <linux/intel-svm.h>

static char ids[1024] __initdata;
struct page_req_dsc {
	u64 srr:1;
	u64 bof:1;
	u64 pasid_present:1;
	u64 lpig:1;
	u64 pasid:20;
	u64 bus:8;
	u64 private:23;
	u64 prg_index:9;
	u64 rd_req:1;
	u64 wr_req:1;
	u64 exe_req:1;
	u64 priv_req:1;
	u64 devfn:8;
	u64 addr:52;
};

module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the vtd_test driver, format is "
		 "\"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\""
		 " and multiple comma separated entries can be specified");


struct bind_info {
	struct iommu_domain *domain;
	struct pasid_table_config data;
};

#define PASIDPTR_MASK 0xFFFFFFFFFFFFFULL
#define TEST_PASIDPTR_UNBIND 1
#define TEST_INVALIDATE_ALL 2
#define TEST_PASID_BIND_MM 3
#if 0

static int prq_default_notifier(struct notifier_block *nb, unsigned long val,
                               void *data)
{
       struct iommu_fault_event *event = (struct iommu_fault_event *)data;;

       pr_info("%s %p count %llu\n", __func__, event, event ? event->paddr : 0);
       return NOTIFY_DONE;
}

static struct notifier_block prq_nb = {
       .notifier_call  = prq_default_notifier,
       /* lowest prio, we want it to run last. */
       .priority       = 0,
};
#endif

static struct iommu_domain *domain;
static ssize_t test_vtd_gapsid_table_ptr_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long num;
	struct iommu_group *group;
	int ret;
	struct bind_info bi;

	ret = kstrtoul(buf, 0, &num);
	if (ret)
		return ret;

	group = iommu_group_get(dev);
	if (!group) {
		pr_err("no group found \n");
		ret = -ENODEV;
		goto out;
	}
	if (num == TEST_PASID_BIND_MM)
		pr_info("test bind mm %d\n", intel_svm_available(dev));

	if ((num == TEST_PASIDPTR_UNBIND) && domain) {
		ret = iommu_unbind_pasid_table(domain, dev);
		if (ret)
			pr_err("unbind svm failed %d\n", ret);
//		iommu_unregister_fault_notifier(group, dev, &prq_nb);

		goto out;
	}


	if (!num && domain) {
		pr_debug("unbind svm\n");
		iommu_detach_device(domain, dev);
		iommu_domain_free(domain);
		domain = NULL;
		goto out;
	}

	if (domain && num) {
		pr_warn("Already bound, try enter 0 to unbind\n");
		goto out;
	}


	if (!num && !domain)
		goto out;

	domain = iommu_domain_alloc(&pci_bus_type);
	if (!domain) {
		pr_err("alloc domain failed\n");
		ret = -ENODEV;
		goto out;
	}

	group = iommu_group_get(dev);
	if (!group) {
		pr_err("no group found \n");
		ret = -ENODEV;
		iommu_domain_free(domain);
		domain = NULL;
		goto out;
	}
	ret = count;

	pr_debug("Test bind gpasid ptr %lx\n", num);
	bi.domain = domain;
	bi.data.base_ptr = num;
	bi.data.pasid_bits = 10;
	ret = iommu_attach_device(domain, dev);
	if (ret) {
		dev_err(dev, "attach device failed ret %d", ret);
		return ret;
	}

	ret = iommu_bind_pasid_table(bi.domain, dev, &bi.data);
	if (ret) {
		pr_debug("Failed bind gpasid ptr %lx\n", num);
		iommu_detach_device(domain, dev);
		iommu_domain_free(domain);
		domain = NULL;
	}
//	iommu_register_fault_notifier(group, &prq_nb, dev, 0);
	iommu_group_put(group);
out:
	return count;
}

static ssize_t test_vtd_gapsid_table_ptr_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return 0;
}

static DEVICE_ATTR(vtd_gpasid_table_ptr, S_IRUGO|S_IWUSR,
	test_vtd_gapsid_table_ptr_show,
	test_vtd_gapsid_table_ptr_store);

/* Test various invalidation caches */
static struct tlb_invalidate_info tinfo[IOMMU_INV_NR_TYPE] =
{
	/* IOTLB with PASID, global */
	{
		{
			TLB_INV_HDR_VERSION_1,
			IOMMU_INV_TYPE_TLB,
		},
		IOMMU_INV_GRANU_PAGE_PASID,
		IOMMU_INVALIDATE_DMA_PASID | IOMMU_INVALIDATE_GLOBAL_PAGE,
		0, 1234, 0x12345 >> VTD_PAGE_SHIFT,
	},
	/* IOTLB without PASID, domain sel */
	{
		{
			TLB_INV_HDR_VERSION_1,
			IOMMU_INV_TYPE_TLB,
		},
		IOMMU_INV_GRANU_DOMAIN,
		IOMMU_INVALIDATE_NO_PASID,
		0, 0xeeffc00, 0x126789 >> VTD_PAGE_SHIFT,
	},

	/* context cache, device sel, with pasid */
	{
		{
			TLB_INV_HDR_VERSION_1,
			IOMMU_INV_TYPE_CONTEXT,
		},
		IOMMU_INV_GRANU_DEVICE,
		IOMMU_INVALIDATE_DMA_PASID,
		4, 1234, 0x123456789 >> VTD_PAGE_SHIFT,
	},
	/* PASID cache, PASID sel */
	{
		{
			TLB_INV_HDR_VERSION_1,
			IOMMU_INV_TYPE_PASID,
		},
		IOMMU_INV_GRANU_PASID_SEL,
		IOMMU_INVALIDATE_DMA_PASID,
		4, 1234, 0x123456789 >> VTD_PAGE_SHIFT,
	},
};

#if 0
static int intel_svm_notify(struct page_req_dsc *desc)
{
       struct iommu_fault_event event;
       struct pci_dev *pdev;
       struct device_domain_info *info;
       int ret = 0;
       struct iommu_domain *pdomain;

       pdev = pci_get_bus_and_slot(desc->bus, desc->devfn);
       if (!pdev) {
               pr_err("No PCI device found for PRQ %x:%x.%x\n",
                       desc->bus, PCI_SLOT(desc->devfn),
                       PCI_FUNC(desc->devfn));
               return -ENODEV;
       }

       pdomain = iommu_get_domain_for_dev(&pdev->dev);
	if (!pdomain) {
		pr_err("IOMMU domain for device found %x:%x.%x\n",
			desc->bus, PCI_SLOT(desc->devfn),
			PCI_FUNC(desc->devfn));
		return -ENODEV;
	}
	pr_debug("domain vs. pdomain %p:%p\n", domain, pdomain);
	event.dev = &pdev->dev;
	event.addr = desc->addr;
	event.count = 1;

       return iommu_fault_notifier_call_chain(domain, &event);
out:
       return ret;
}
#endif

static ssize_t test_vtd_invalidate_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	unsigned long num;
	int ret, i;
	struct iommu_group *group;

	ret = kstrtoul(buf, 0, &num);
	if (ret)
		return ret;
	

	group = iommu_group_get(dev);
	if (!group) {
		pr_err("no group found \n");
		ret = -ENODEV;
		goto out;
	}

	if ((num == TEST_INVALIDATE_ALL) && domain) {
		for (i = 0; i < IOMMU_INV_NR_TYPE; i++) {
			ret = iommu_invalidate(domain, dev, &tinfo[i]);
			if (ret)
				pr_err("invalidation failed %d\n", ret);
		}
		goto out;
	}
	ret = count;
#if 0
	desc.bus = 0;
	desc.devfn = num;
	pr_debug("Test prq notifier devfn %lu\n", num);
	if (!intel_svm_notify(&desc))
		pr_info("Notify OK, no need for response now\n");
#endif			
	iommu_group_put(group);
out:
	return count;
}

static ssize_t test_vtd_invalidate_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return 0;
}

static DEVICE_ATTR(vtd_invalidate, S_IRUGO|S_IWUSR,
	test_vtd_invalidate_show,
	test_vtd_invalidate_store);

static int pci_vtd_test_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int ret;

	dev_info(&dev->dev, "claimed by vtd_test\n");

	ret = device_create_file(&dev->dev, &dev_attr_vtd_gpasid_table_ptr);
	ret = device_create_file(&dev->dev, &dev_attr_vtd_invalidate);

	return ret;
}

static void pci_vtd_test_remove(struct pci_dev *pdev)
{
	device_remove_file(&pdev->dev, &dev_attr_vtd_gpasid_table_ptr);
	device_remove_file(&pdev->dev, &dev_attr_vtd_invalidate);
}

static struct pci_driver vtd_test_driver = {
	.name		= "pci_vtd_test",
	.id_table	= NULL,	/* only dynamic id's */
	.probe		= pci_vtd_test_probe,
	.remove = pci_vtd_test_remove,

};

static int __init pci_vtd_test_init(void)
{
	char *p, *id;
	int rc;

	rc = pci_register_driver(&vtd_test_driver);
	if (rc)
		return rc;

	/* no ids passed actually */
	if (ids[0] == '\0')
		return 0;

	/* add ids specified in the module parameter */
	p = ids;
	while ((id = strsep(&p, ","))) {
		unsigned int vendor, device, subvendor = PCI_ANY_ID,
			subdevice = PCI_ANY_ID, class = 0, class_mask = 0;
		int fields;

		if (!strlen(id))
			continue;

		fields = sscanf(id, "%x:%x:%x:%x:%x:%x",
				&vendor, &device, &subvendor, &subdevice,
				&class, &class_mask);

		if (fields < 2) {
			pr_warn("pci_vtd_test: invalid id string \"%s\"\n", id);
			continue;
		}

		pr_info("pci_vtd_test: add %04X:%04X sub=%04X:%04X cls=%08X/%08X\n",
			vendor, device, subvendor, subdevice, class, class_mask);

		rc = pci_add_dynid(&vtd_test_driver, vendor, device,
				subvendor, subdevice, class, class_mask, 0);
		if (rc)
			pr_warn("pci_vtd_test: failed to add dynamic id (%d)\n", rc);
	}

	return 0;
}

static void __exit pci_vtd_test_exit(void)
{
	pci_unregister_driver(&vtd_test_driver);
}

module_init(pci_vtd_test_init);
module_exit(pci_vtd_test_exit);

MODULE_LICENSE("GPL");

