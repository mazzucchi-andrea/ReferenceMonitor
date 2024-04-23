#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/workqueue.h>
#include <linux/uidgid.h>

#include "reference_monitor.h"
#include "path_list.h"

#define unlink "__x64_sys_unlink"
#define unlinkat "__x64_sys_unlinkat"
#define open "__x64_sys_open"
#define rename "__x64_sys_rename"
#define creat "__x64_sys_creat"
#define openat "__x64_sys_openat"

#define HOOKS 6

#define get(regs) regs = (struct pt_regs *)the_regs->di;

typedef struct _log_work
{
    struct work_struct the_work;
    struct tm tm_violation;
    kgid_t gid;
    pid_t ttid;
    kuid_t uid;
    kuid_t euid;
    const char *target_func;
    char *target_path;
    char *exe_pathname;
} log_work;

// kretprobes
struct kretprobe kretprobes[HOOKS];

int binary2hexadecimal(const u8 *bin, size_t bin_len, char *buf, size_t buf_len)
{
    static const char hex_table[] = "0123456789abcdef";
    size_t i;

    if (buf_len < bin_len * 2 + 1)
    {
        return -ENOBUFS;
    }

    for (i = 0; i < bin_len; ++i)
    {
        buf[i * 2] = hex_table[(bin[i] >> 4) & 0xF];
        buf[i * 2 + 1] = hex_table[bin[i] & 0xF];
    }
    buf[i * 2] = '\0';

    return 0;
}

int calculate_checksum(const char *filename, u8 *checksum)
{
    struct crypto_shash *tfm;
    struct shash_desc *desc;
    int ret = -ENOMEM;
    struct file *file;
    loff_t file_size, pos = 0;
    ssize_t bytes_read;
    u8 *data;

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("%s: failed to open file err %s\n", MODNAME, filename);
        ret = -PTR_ERR(file);
        goto out;
    }

    file_size = i_size_read(file->f_inode);

    data = (u8 *)kmalloc(file_size, GFP_KERNEL);
    if (!data)
    {
        ret = -ENOMEM;
        goto out_close_file;
    }

    while (pos < file_size)
    {
        bytes_read = kernel_read(file, data + pos, file_size, &pos);
        if (bytes_read <= 0)
            break;
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("%s: Unable to allocate tfm err %ld\n", MODNAME, PTR_ERR(tfm));
        ret = PTR_ERR(tfm);
        goto out_free_data;
    }

    desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        ret = -ENOMEM;
        goto out_free_tfm;
    }

    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, data, file_size, checksum);
    if (ret < 0)
        pr_err("%s: failing checksum calculation err %d\n", MODNAME, ret);

    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
out_free_data:
    kfree(data);
out_close_file:
    filp_close(file, NULL);
out:
    return ret;
}

int write_log_entry(log_work *entry_data, u8 *checksum)
{
    char *log_entry_base = "%d-%02d-%02d\t%02d:%02d:%02d\t%s\n"
                           "gid:\t%d\n"
                           "ttid:\t%d\n"
                           "uid:\t%d\n"
                           "euid:\t%d\n"
                           "target_file:%s\n"
                           "exe_file:\t%s\n"
                           "%s\n";
    char *log_entry, *checksum_hex;
    int ret, len = 0;

    checksum_hex = (char *)kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
    if (!checksum_hex)
    {
        pr_err("%s: failed memory allocation for hex checksum\n", MODNAME);
        goto skip_checksum;
    }

    // convert checksum to hex string
    ret = binary2hexadecimal(checksum, SHA256_DIGEST_SIZE, checksum_hex, SHA256_DIGEST_SIZE * 2 + 1);
    if (ret < 0)
    {
        pr_err("%s: error %d during checksum conversion to hex\n", MODNAME, ret);
    }

skip_checksum:
    // get log entry length
    len = snprintf(NULL, 0, log_entry_base,
                   entry_data->tm_violation.tm_year + 1900,
                   entry_data->tm_violation.tm_mon + 1,
                   entry_data->tm_violation.tm_mday,
                   entry_data->tm_violation.tm_hour,
                   entry_data->tm_violation.tm_min,
                   entry_data->tm_violation.tm_sec,
                   entry_data->target_func,
                   entry_data->gid,
                   entry_data->ttid,
                   entry_data->uid,
                   entry_data->euid,
                   entry_data->target_path,
                   entry_data->exe_pathname,
                   checksum_hex);
    if (len < 0)
    {
        pr_err("%s: error formatting log_entry with err %d \n", MODNAME, ret);
        goto out_hex;
    }

    log_entry = (char *)kmalloc(len + 1, GFP_KERNEL);
    if (!log_entry)
    {
        pr_err("%s: failed memory allocation for for log_entry\n", MODNAME);
        ret = -ENOMEM;
        goto out_hex;
    }

    ret = snprintf(log_entry, len + 1, log_entry_base,
                   entry_data->tm_violation.tm_year + 1900,
                   entry_data->tm_violation.tm_mon + 1,
                   entry_data->tm_violation.tm_mday,
                   entry_data->tm_violation.tm_hour,
                   entry_data->tm_violation.tm_min,
                   entry_data->tm_violation.tm_sec,
                   entry_data->target_func,
                   entry_data->gid,
                   entry_data->ttid,
                   entry_data->uid,
                   entry_data->euid,
                   entry_data->target_path,
                   entry_data->exe_pathname,
                   checksum_hex);
    if (ret < 0)
    {
        pr_err("%s: error formatting log_entry with err %d \n", MODNAME, ret);
        goto out;
    }

    ret = write_logfilefs(log_entry, len);
    if (ret < 0)
        pr_err("%s: error %d during header\n", MODNAME, ret);
    else if (ret == 0)
        pr_info("%s: no bytes written during header\n", MODNAME);

out:
    kfree(log_entry);
out_hex:
    if (checksum_hex)
        kfree(checksum_hex);
    return ret;
}

void logger(unsigned long data)
{
    log_work *work_data = container_of((void *)data, log_work, the_work);
    u8 checksum[SHA256_DIGEST_SIZE] = {0};
    int ret = -1;

    get_lock(); // get write lock

    if (!is_mounted())
    {
        pr_info("%s: The logfilefs is not mounted\n", MODNAME);
        goto out_lock;
    }

    ret = calculate_checksum(work_data->exe_pathname, checksum);
    if (ret < 0)
        pr_err("%s: failing calculate file checksum with error %d\n", MODNAME, ret);

    ret = write_log_entry(work_data, checksum);
    if (ret < 0)
        pr_err("%s: error %d during write_log_entry\n", MODNAME, ret);

out_lock:
    release_lock();
    kfree(work_data->target_path);
    kfree(work_data->exe_pathname);
    kfree(work_data);
    module_put(THIS_MODULE);
}

int reconstruct_complete_path(int dirfd, char *buf, size_t buf_size)
{
    struct file *dir_file;
    char *dir_path_buf, *dir_path, *filename;
    int ret;

    filename = (char *)kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!filename)
    {
        pr_err("%s: failed memory allocation for filename\n", MODNAME);
        return -ENOMEM;
    }
    memcpy(filename, buf, strlen(buf) + 1);

    dir_file = fget(dirfd);
    if (!dir_file)
    {
        pr_err("%s: failed to get file object for directory file descriptor\n", MODNAME);
        return -1;
    }

    dir_path_buf = d_path(&dir_file->f_path, buf, buf_size);
    if (IS_ERR(dir_path_buf))
    {
        ret = -PTR_ERR(dir_path_buf);
        goto out_free_filename;
    }

    dir_path = (char *)kmalloc(strlen(dir_path_buf) + 1, GFP_ATOMIC);
    if (!dir_path)
    {
        pr_err("%s: failed memory allocation for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_filename;
    }

    memcpy(dir_path, dir_path_buf, strlen(dir_path_buf) + 1);

    memcpy(buf, dir_path, strlen(dir_path) + 1);
    strcat(buf, "/");
    strcat(buf, filename);

    kfree(dir_path);
out_free_filename:
    kfree(filename);
    return ret;
}

static int the_pre_unlinkat_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct timespec64 now;
    struct tm tm_now;
    log_work *the_log_work;
    char *target_path, *exe_pathname, *exe_pathname_buf, *buf;
    int dirfd, flag, ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    dirfd = regs->di;

    flag = regs->dx;

    if ((flag & ~AT_REMOVEDIR) != 0)
        return -EINVAL;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        return -ENOMEM;
    }

    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret < 0)
    {
        pr_err("%s: %s failed to copy pathname from user space with error %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    if (dirfd != AT_FDCWD)
    {
        ret = reconstruct_complete_path(dirfd, buf, PATH_MAX);
        if (ret < 0)
            goto out_free_buf;
    }

    target_path = (char *)kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: failed memory allocation for pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    // copy pathname from buf
    memcpy(target_path, buf, strlen(buf) + 1);

    if (check_path(target_path) != 0)
    {
        ret = -1;
        goto out_free_path;
    }
    regs->si = (unsigned long)NULL;
    pr_notice("%s: The %s target %s is a protected pathname.\n", MODNAME, ri->rph->rp->kp.symbol_name, target_path);

    // d_path for exe_pathname
    exe_pathname_buf = d_path(&current->mm->exe_file->f_path, buf, PATH_MAX);
    if (IS_ERR(exe_pathname_buf))
    {
        ret = -PTR_ERR(exe_pathname_buf);
        goto out_free_path;
    }

    exe_pathname = (char *)kmalloc(strlen(exe_pathname_buf) + 1, GFP_ATOMIC);
    if (!exe_pathname)
    {
        pr_err("%s: failed memory allocation for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_path;
    }

    // copy exe_pathname from buf
    memcpy(exe_pathname, exe_pathname_buf, strlen(exe_pathname_buf) + 1);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    the_log_work->target_func = ri->rph->rp->kp.symbol_name;
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = target_path;
    the_log_work->exe_pathname = exe_pathname;

    ktime_get_real_ts64(&now);
    time64_to_tm(now.tv_sec, 0, &tm_now);
    the_log_work->tm_violation = tm_now;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    schedule_work(&(the_log_work->the_work));

    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    kfree(exe_pathname);
out_free_path:
    kfree(target_path);
out_free_buf:
    kfree(buf);
    return ret;
}

static int the_pre_open_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    log_work *the_log_work;
    struct timespec64 now;
    struct tm tm_now;
    char *pathname, *exe_pathname, *exe_pathname_buf, *buf;
    int ret = -1, flags;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    flags = regs->si;

    if (flags == O_RDONLY) // open read only are do not care
        return -1;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        return -ENOMEM;
    }

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->di, PATH_MAX);
    if (ret < 0)
    {
        pr_err("%s: %s failed to copy pathname from user space with error %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    pathname = (char *)kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!pathname)
    {
        pr_err("%s: failed memory allocation for pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    // copy pathname from buf
    memcpy(pathname, buf, strlen(buf) + 1);

    if (check_path(pathname) != 0)
    {
        ret = -1;
        goto out_free_path;
    }
    regs->di = (unsigned long)NULL;
    pr_notice("%s: The %s with %d flags target %s is a protected pathname.\n", MODNAME, ri->rph->rp->kp.symbol_name, flags, pathname);

    // d_path for exe_pathname
    exe_pathname_buf = d_path(&current->mm->exe_file->f_path, buf, PATH_MAX);
    if (IS_ERR(exe_pathname_buf))
    {
        ret = -PTR_ERR(exe_pathname_buf);
        goto out_free_path;
    }

    exe_pathname = (char *)kmalloc(strlen(exe_pathname_buf) + 1, GFP_ATOMIC);
    if (!exe_pathname)
    {
        pr_err("%s: failed memory allocation for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_path;
    }

    // copy exe_pathname from buf
    memcpy(exe_pathname, exe_pathname_buf, strlen(exe_pathname_buf) + 1);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    the_log_work->target_func = ri->rph->rp->kp.symbol_name;
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = pathname;
    the_log_work->exe_pathname = exe_pathname;

    ktime_get_real_ts64(&now);
    time64_to_tm(now.tv_sec, 0, &tm_now);
    the_log_work->tm_violation = tm_now;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    schedule_work(&(the_log_work->the_work));

    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    kfree(exe_pathname);
out_free_path:
    kfree(pathname);
out_free_buf:
    kfree(buf);
    return ret;
}

static int the_pre_openat_hook(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct timespec64 now;
    struct tm tm_now;
    log_work *the_log_work;
    char *target_path, *exe_pathname, *exe_pathname_buf, *buf;
    int dirfd, flags, ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    flags = regs->dx;

    if (flags == O_RDONLY) // open read only are do not care
        return -1;

    dirfd = regs->di;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        return -ENOMEM;
    }

    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret < 0)
    {
        pr_err("%s: %s failed to copy pathname from user space with error %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    if (dirfd != AT_FDCWD)
    {
        ret = reconstruct_complete_path(dirfd, buf, PATH_MAX);
        if (ret < 0)
            goto out_free_buf;
    }

    target_path = (char *)kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: failed memory allocation for pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    // copy pathname from buf
    memcpy(target_path, buf, strlen(buf) + 1);

    if (check_path(target_path) != 0)
    {
        ret = -1;
        goto out_free_path;
    }
    regs->si = (unsigned long)NULL;
    pr_notice("%s: The %s target %s is a protected pathname.\n", MODNAME, ri->rph->rp->kp.symbol_name, target_path);

    // d_path for exe_pathname
    exe_pathname_buf = d_path(&current->mm->exe_file->f_path, buf, PATH_MAX);
    if (IS_ERR(exe_pathname_buf))
    {
        ret = -PTR_ERR(exe_pathname_buf);
        goto out_free_path;
    }

    exe_pathname = (char *)kmalloc(strlen(exe_pathname_buf) + 1, GFP_ATOMIC);
    if (!exe_pathname)
    {
        pr_err("%s: failed memory allocation for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_path;
    }

    // copy exe_pathname from buf
    memcpy(exe_pathname, exe_pathname_buf, strlen(exe_pathname_buf) + 1);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    the_log_work->target_func = ri->rph->rp->kp.symbol_name;
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = target_path;
    the_log_work->exe_pathname = exe_pathname;

    ktime_get_real_ts64(&now);
    time64_to_tm(now.tv_sec, 0, &tm_now);
    the_log_work->tm_violation = tm_now;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    schedule_work(&(the_log_work->the_work));

    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    kfree(exe_pathname);
out_free_path:
    kfree(target_path);
out_free_buf:
    kfree(buf);
    return ret;
}


// pre handler for syscall that have the pathname as first arg
static int the_pre_hook_sys_first_arg(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    log_work *the_log_work;
    struct timespec64 now;
    struct tm tm_now;
    char *pathname, *exe_pathname, *exe_pathname_buf, *buf;
    int ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        return -ENOMEM;
    }

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->di, PATH_MAX);
    if (ret < 0)
    {
        pr_err("%s: %s failed to copy pathname from user space with error %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    pathname = (char *)kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!pathname)
    {
        pr_err("%s: failed memory allocation for pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    // copy pathname from buf
    memcpy(pathname, buf, strlen(buf) + 1);

    if (check_path(pathname) != 0)
    {
        ret = -1;
        goto out_free_path;
    }
    regs->di = (unsigned long)NULL;
    pr_notice("%s: The %s target %s is a protected pathname.\n", MODNAME, ri->rph->rp->kp.symbol_name, pathname);

    // d_path for exe_pathname
    exe_pathname_buf = d_path(&current->mm->exe_file->f_path, buf, PATH_MAX);
    if (IS_ERR(exe_pathname_buf))
    {
        ret = -PTR_ERR(exe_pathname_buf);
        goto out_free_path;
    }

    exe_pathname = (char *)kmalloc(strlen(exe_pathname_buf) + 1, GFP_ATOMIC);
    if (!exe_pathname)
    {
        pr_err("%s: failed memory allocation for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_path;
    }

    // copy exe_pathname from buf
    memcpy(exe_pathname, exe_pathname_buf, strlen(exe_pathname_buf) + 1);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    the_log_work->target_func = ri->rph->rp->kp.symbol_name;
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = pathname;
    the_log_work->exe_pathname = exe_pathname;

    ktime_get_real_ts64(&now);
    time64_to_tm(now.tv_sec, 0, &tm_now);
    the_log_work->tm_violation = tm_now;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    schedule_work(&(the_log_work->the_work));

    if (!try_module_get(THIS_MODULE))
    {
        ret = -ENODEV;
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    kfree(exe_pathname);
out_free_path:
    kfree(pathname);
out_free_buf:
    kfree(buf);
    return ret;
}

int register_hooks(void)
{
    int i, ret;

    kretprobes[0].kp.symbol_name = unlink;
    kretprobes[0].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[0].maxactive = -1;

    kretprobes[1].kp.symbol_name = unlinkat;
    kretprobes[1].entry_handler = (kretprobe_handler_t)the_pre_unlinkat_hook;
    kretprobes[1].maxactive = -1;

    kretprobes[2].kp.symbol_name = open;
    kretprobes[2].entry_handler = (kretprobe_handler_t)the_pre_open_hook;
    kretprobes[2].maxactive = -1;

    kretprobes[3].kp.symbol_name = rename;
    kretprobes[3].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[3].maxactive = -1;

    kretprobes[4].kp.symbol_name = creat;
    kretprobes[4].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[4].maxactive = -1;

    kretprobes[5].kp.symbol_name = openat;
    kretprobes[5].entry_handler = (kretprobe_handler_t)the_pre_openat_hook;
    kretprobes[5].maxactive = -1;

    for (i = 0; i < HOOKS; i++)
    {
        ret = register_kretprobe(&kretprobes[i]);
        if (ret == 0)
            pr_info("%s: kretprobes %s register success\n", MODNAME, kretprobes[i].kp.symbol_name);
        else
            pr_err("%s: kretprobes %s register failed, error %d\n", MODNAME, kretprobes[i].kp.symbol_name, ret);
    }

    return ret;
}

void unregister_hooks(void)
{
    int i;

    for (i = 0; i < HOOKS; i++)
        unregister_kretprobe(&kretprobes[i]);
}

int disable_hooks(void)
{
    int i, ret;

    for (i = 0; i < HOOKS; i++)
    {
        ret = disable_kretprobe(&kretprobes[i]);
        if (likely(ret == 0))
            pr_info("%s: kretprobe disable of %s success\n", MODNAME, kretprobes[i].kp.symbol_name);
        else
        {
            pr_err("%s: kretprobe disable of %s failed, err %d\n", MODNAME, kretprobes[i].kp.symbol_name, ret);
            unregister_hooks();
        }
    }

    return ret;
}

int enable_hooks(void)
{
    int i, ret;

    for (i = 0; i < HOOKS; i++)
    {
        ret = enable_kretprobe(&kretprobes[i]);
        if (likely(ret == 0))
            pr_info("%s: kretprobe enable of %s success\n", MODNAME, kretprobes[i].kp.symbol_name);
        else
        {
            pr_err("%s: kretprobe enable of %s failed, err %d\n", MODNAME, kretprobes[i].kp.symbol_name, ret);
            unregister_hooks();
            ret = register_hooks();
        }
    }

    return ret;
}
