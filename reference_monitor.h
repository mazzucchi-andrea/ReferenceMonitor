#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#include <crypto/hash.h>
#include <linux/crypto.h>
#include <linux/buffer_head.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#define MODNAME "REFERENCE_MONITOR"

#define AUDIT if (1)

#define SHA256_DIGEST_SIZE 32

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

extern int8_t monitor_state;
extern bool fs_mounted;
extern struct mutex device_mutex;
extern struct workqueue_struct *log_queue;

bool is_mounted(void);
ssize_t write_logfilefs(char *, size_t);

#endif
