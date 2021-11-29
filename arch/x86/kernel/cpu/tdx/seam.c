// SPDX-License-Identifier: GPL-2.0
/* common helper functions for the P-SEAMLDR and the TDX module to VMXON/VMXOFF */

#define pr_fmt(fmt) "seam: " fmt

#include <linux/earlycpio.h>
#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/slab.h>

#include <asm/microcode.h>
#include <asm/virtext.h>
#include <asm/cpu.h>

#include "seam.h"

bool __init seam_get_firmware(struct cpio_data *blob, const char *name)
{
	if (get_builtin_firmware(blob, name))
		return true;

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_start) {
		static const char * const prepend[] = {
			"lib/firmware",
			/*
			 * Some tools which generate initrd image, for example,
			 * dracut, creates a symbolic link from lib/ to
			 * usr/lib/.  In such case, search in lib/firmware/
			 * doesn't find the file.  Search usr/lib too.
			 */
			"usr/lib/firmware",
		};
		int i;
		size_t len = strlen(name) + 18;
		char *path = kmalloc(len, GFP_KERNEL);

		if (!path)
			return false;

		for (i = 0; i < ARRAY_SIZE(prepend); i++) {
			sprintf(path, "%s/%s", prepend[i], name);
			*blob = find_cpio_file(path, (void *)initrd_start,
					       initrd_end - initrd_start);
			if (blob->data) {
				kfree(path);
				return true;
			}
		}
		kfree(path);
	}
#endif

	return false;
}

static u32 seam_vmxon_version_id __initdata;

/*
 * This function must be called after init_ia32_feat_ctl() that sets
 * X86_FEATURE_VMX.
 */
int __init seam_init_vmx_early(void)
{
	struct vmx_basic_info info;

	if (!this_cpu_has(X86_FEATURE_VMX))
		return -EOPNOTSUPP;

	if (cpu_vmx_get_basic_info(&info))
		return -EIO;

	seam_vmxon_version_id = info.rev_id;

	return 0;
}

/*
 * seam_init_vmxon_vmcs - initialize VMXON region with version id for this CPU.
 * @vmcs: vmxon region to initialize.  zero it before call.
 *
 * VMXON region has the same header format as the vmcs region.  It is assumed
 * that all CPUs have the same vmcs version.  The KVM kernel module has this
 * same assumption.  Even if the version differs, VMXON fails with
 * seam_vmxon_on_each_cpu() to catch it.
 */
void __init seam_init_vmxon_vmcs(struct vmcs *vmcs)
{
	vmcs->hdr.revision_id = seam_vmxon_version_id;
}

static void __init seam_vmxon(void *data)
{
	atomic_t *error = data;
	int r;

	r = cpu_vmx_get();
	if (r)
		atomic_set(error, r);
}

int __init seam_vmxon_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxon, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how about many CPUs failed
	 * and about the exact error code.
	 */
	return atomic_read(&error);
}

static void __init seam_vmxoff(void *data)
{
	cpu_vmx_put();
}

int __init seam_vmxoff_on_each_cpu(void)
{
	atomic_t error;

	atomic_set(&error, 0);
	on_each_cpu(seam_vmxoff, &error, 1);

	/*
	 * Check if any of the CPUs fail.  Don't care how many CPUs failed and
	 * about the exact error code.
	 */
	return atomic_read(&error);
}
