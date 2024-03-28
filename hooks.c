#define EXPORT_SYMTAB
#include <linux/kprobes.h>
#include <linux/slab.h>

#include "reference_monitor.h"
#include "path_list.h"

#define unlink "__x64_sys_unlink"

#define get(regs) regs = (struct pt_regs *)the_regs->di;

// kretprobes
struct kretprobe unlink_kretprobe;

static int the_pre_unlink_hook(struct kprobe *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    char *path;
    int ret = 0;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out_off;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // get pathname
    path = (char *)kmalloc((PATH_MAX_LEN + 1), GFP_KERNEL);
    if (!path)
    {
        printk("%s: kmalloc failing for unlink path\n", MODNAME);
        return -ENOMEM;
    }
    ret = strncpy_from_user(path, (const char __user *)regs->di, PATH_MAX_LEN + 1);
    if (ret < 0)
    {
        printk("%s: Failed to copy pathname from user space with error %d\n", MODNAME, ret);
        goto out_free_path;
    }

    if (check_path(path) == 0)
    {
        printk("%s: The unlink target %s is a protected pathname.\n", MODNAME, path);
        regs->di = (unsigned long)NULL;
    }
    
    ret = 0;

out_free_path:
    kfree(path);
out_off:
    return ret;
}

int register_hooks(void)
{
    int ret;

    unlink_kretprobe.kp.symbol_name = unlink;
    unlink_kretprobe.entry_handler = (kretprobe_handler_t)the_pre_unlink_hook;
    unlink_kretprobe.maxactive = -1;

    // register unlink hook
    ret = register_kretprobe(&unlink_kretprobe);
    if (likely(ret != 0))
        printk("%s: kretprobe register of %s success\n", MODNAME, unlink);
    else
        printk("%s: kretprobe register of %s failed, returned %d\n", MODNAME, unlink, ret);

    return ret;
}

void unregister_hooks(void)
{
    unregister_kretprobe(&unlink_kretprobe);
}

int disable_hooks(void)
{
    int ret;

    ret = disable_kretprobe(&unlink_kretprobe);
    if (likely(ret == 0))
        printk("%s: kretprobe disable of %s success\n", MODNAME, unlink);
    else
        printk("%s: kretprobe disable of %s failed, returned %d\n", MODNAME, unlink, ret);

    return ret;
}

int enable_hooks(void)
{
    int ret;

    ret = enable_kretprobe(&unlink_kretprobe);
    if (likely(ret == 0))
        printk("%s: kretprobe enable of %s success\n", MODNAME, unlink);
    else
        printk("%s: kretprobe enable of %s failed, returned %d\n", MODNAME, unlink, ret);

    return ret;
}
