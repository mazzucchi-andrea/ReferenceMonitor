#ifndef HOOKS_H
#define HOOKS_H

#include <linux/kprobes.h>

#define unlink "__x64_sys_unlink"

int register_hook(struct kretprobe, char*, kretprobe_handler_t);
int the_pre_unlink_hook(struct kprobe *, struct pt_regs *);

#endif