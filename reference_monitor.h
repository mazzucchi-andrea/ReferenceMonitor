#ifndef REFERENCE_MONITOR_H
#define REFERENCE_MONITOR_H

#define MODNAME "REFERENCE_MONITOR"

#define AUDIT if (1)

// password max length including NULL terminator
#define PASSWORD_MAX_LEN 65

#define SHA256 "sha256"
#define SHA256_DIGEST_SIZE 32

#define ADD 0
#define REMOVE 1

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

extern atomic_t fs_mounted;
extern struct rw_semaphore log_rw;
extern struct workqueue_struct *log_queue;

int try_log_write_lock(void);
int try_log_read_lock(void);
ssize_t write_logfilefs(char *, size_t);

#endif