#define EXPORT_SYMTAB
#include <linux/kprobes.h>

#include "reference_monitor.h"

// where to look at when searching system call parmeters
#define get(regs) regs = (struct pt_regs *)the_regs->di;

int the_pre_unlink_hook(struct kprobe *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    char *path;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // get pathname
    path = (char *)regs->di;
    if (check_path(path))
    {
        printk("%s: The unlink target is a protected pathname.\n", MODNAME);
        regs->ax = -EPERM; // Return an error code
        return 0;          // Return 0 to stop the system call
    }

    return 1;
}

static int the_dummy_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    return 0;
}

int register_hook(struct kretprobe retprobe, char *target_func, kretprobe_handler_t the_pre_hook)
{
    int ret;

    retprobe.kp.symbol_name = target_func;
    retprobe.handler = (kretprobe_handler_t)the_dummy_hook;
    retprobe.entry_handler = the_pre_hook;
    retprobe.maxactive = -1; // lets' go for the default number of active kretprobes manageable by the kernel

    ret = register_kretprobe(&retprobe);
    if (ret < 0)
    {
        printk("%s: kretprobe of %s init failed, returned %d\n", MODNAME, target_func, ret);
        return ret;
    }
    return ret;
}
