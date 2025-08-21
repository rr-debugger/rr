// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright 2020 Mike Hommey <mh@glandium.org>
 * Copyright 2025 RR Community
*/

#include <linux/module.h>
#include <linux/tracepoint.h>
#include <linux/suspend.h>
#include <linux/version.h>
#include <asm/msr.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6,16,0)
#define wrmsrq_safe 	wrmsrl_safe
#define rdmsrq_safe 	rdmsrl_safe
#define native_wrmsrq	native_wrmsrl
#endif

#define MODULE_NAME "zen_workaround"

#define SPECLOCKMAP_DISABLE BIT_64(54)

static u64 set_speclockmap_disable(u64 msr) {
	return msr | SPECLOCKMAP_DISABLE;
}

static u64 unset_speclockmap_disable(u64 msr) {
	return msr & ~SPECLOCKMAP_DISABLE;
}

typedef u64 (*edit_msr_func_t)(u64);

static void edit_ls_cfg_on_cpu(void *info)
{
	int cpu = get_cpu();
	u64 value = 0;

	if (!rdmsrq_safe(MSR_AMD64_LS_CFG, &value)) {
		edit_msr_func_t edit_msr = (edit_msr_func_t) info;
		u64 new_value = edit_msr(value);
		if (!wrmsrq_safe(MSR_AMD64_LS_CFG, new_value)) {
			pr_info("MSR_AMD64_LS_CFG for cpu %d was 0x%llx, setting to 0x%llx\n",
			        cpu, value, new_value);
		} else {
			pr_err("MSR_AMD64_LS_CFG for cpu %d was 0x%llx, setting to 0x%llx failed\n",
			       cpu, value, new_value);
		}
	}

	put_cpu();
}

static void do_zen_workaround(edit_msr_func_t edit_msr)
{
	smp_call_function(edit_ls_cfg_on_cpu, edit_msr, 1);
	edit_ls_cfg_on_cpu(edit_msr);
}

void on_write_msr(void *data, unsigned int msr, u64 val, int failed)
{
	if (msr == MSR_AMD64_LS_CFG && !(val & SPECLOCKMAP_DISABLE)) {
		native_wrmsrq(MSR_AMD64_LS_CFG, set_speclockmap_disable(val));
	}
}

static int install_probe(void)
{
	return !boot_cpu_has(X86_FEATURE_AMD_SSBD) && !boot_cpu_has(X86_FEATURE_VIRT_SSBD);
}

static int enable_zen_workaround(void)
{
	if (install_probe()) {
		int ret = tracepoint_probe_register(&__tracepoint_write_msr, on_write_msr, NULL);
		if (ret) {
			pr_err("Registering tracepoint probe failed\n");
			return ret;
		}
	}
	do_zen_workaround(set_speclockmap_disable);
	return 0;
}

static int pm_notification(struct notifier_block *this, unsigned long event, void *ptr)
{
	switch (event) {
		case PM_POST_SUSPEND:
		case PM_POST_HIBERNATION:
		case PM_POST_RESTORE:
			enable_zen_workaround();
			break;
		case PM_HIBERNATION_PREPARE:
		case PM_SUSPEND_PREPARE:
			if (install_probe()) {
				tracepoint_probe_unregister(&__tracepoint_write_msr, on_write_msr, NULL);
			}
			break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block pm_notifier = {
	.notifier_call = pm_notification,
};

static int __init zen_workaround_init(void)
{
	if (!boot_cpu_has(X86_FEATURE_ZEN)) {
		pr_err("Cannot use the Zen workaround on a non-Zen CPU\n");
		return -EINVAL;
	}
	enable_zen_workaround();
	register_pm_notifier(&pm_notifier);
	return 0;
}
module_init(zen_workaround_init);

static void __exit zen_workaround_exit(void)
{
	unregister_pm_notifier(&pm_notifier);
	if (install_probe()) {
		tracepoint_probe_unregister(&__tracepoint_write_msr, on_write_msr, NULL);
	}
	do_zen_workaround(unset_speclockmap_disable);
}
module_exit(zen_workaround_exit);

MODULE_LICENSE("GPL");