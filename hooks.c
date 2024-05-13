#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/uidgid.h>

#include "reference_monitor.h"
#include "path_list.h"

#define unlink "__x64_sys_unlink"
#define unlinkat "__x64_sys_unlinkat"
#define rename "__x64_sys_rename"
#define renameat "__x64_sys_renameat"
#define renameat2 "__x64_sys_renameat2"
#define creat "__x64_sys_creat"
#define rmdir "__x64_sys_rmdir"
#define open "__x64_sys_open"
#define openat "__x64_sys_openat"
#define openat2 "__x64_sys_openat2"
#define mkdir "__x64_sys_mkdir"
#define mkdirat "__x64_sys_mkdirat"

#define calc_enoent "program attempting the illegal operation no longer exists"

#define HOOKS 12

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
    struct path *target_path;
    struct path *exe_path;
} log_work;

// kretprobes
struct kretprobe kretprobes[HOOKS];

int binary2hexadecimal(const u8 *bin, size_t bin_len, char *buf, size_t buf_len)
{
    static const char hex_table[] = "0123456789ABCDEF";
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
    struct file *file;
    int ret = -1;
    loff_t file_size, pos = 0;
    ssize_t bytes_read;
    u8 *data;

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("%s: failed to open file %s - err %ld\n", MODNAME, filename, PTR_ERR(filename));
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
        pr_err("%s: unable to allocate tfm - err %ld\n", MODNAME, PTR_ERR(tfm));
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
    if (ret)
        pr_err("%s: failing checksum calculation - err %d\n", MODNAME, ret);

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

void logger(unsigned long data)
{
    log_work *work_data = container_of((void *)data, log_work, the_work);
    u8 checksum[SHA256_DIGEST_SIZE] = {0};
    int ret, len;
    char *log_entry, *checksum_hex, *target_pathname, *exe_pathname, *buf_target, *buf_exe;
    char *log_entry_base = "%d-%02d-%02d\t%02d:%02d:%02d\t%s\n"
                           "gid:\t%d\n"
                           "ttid:\t%d\n"
                           "uid:\t%d\n"
                           "euid:\t%d\n"
                           "target:\t%s\n"
                           "exe_file:\t%s\n"
                           "%s\n";

    if (!is_mounted())
    {
        pr_info("%s: The logfilefs is not mounted\n", MODNAME);
        goto out_work;
    }

    buf_target = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf_target)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        goto out_work;
    }

    target_pathname = d_path(work_data->target_path, buf_target, PATH_MAX);
    if (IS_ERR(target_pathname))
    {
        pr_err("%s: target pathname resolve failed - err %ld\n", MODNAME, PTR_ERR(target_pathname));
        goto out_free_buf_target;
    }

    buf_exe = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf_exe)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        goto out_free_buf_target;
    }

    exe_pathname = d_path(work_data->exe_path, buf_exe, PATH_MAX);
    if (IS_ERR(exe_pathname))
    {
        pr_err("%s: exe pathname resolve failed - err %ld\n", MODNAME, PTR_ERR(exe_pathname));
        exe_pathname = NULL;
    }

    checksum_hex = (char *)kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
    if (!checksum_hex)
    {
        pr_err("%s: failed memory allocation for hex checksum\n", MODNAME);
        goto skip_checksum;
    }

    ret = calculate_checksum(exe_pathname, checksum);
    if (ret)
        pr_err("%s: failing calculate file checksum - err %d\n", MODNAME, ret);

    if (ret == -ENOENT)
        snprintf(checksum_hex, SHA256_DIGEST_SIZE * 2 + 1, calc_enoent);
    else
    { // convert checksum to hex string
        ret = binary2hexadecimal(checksum, SHA256_DIGEST_SIZE, checksum_hex, SHA256_DIGEST_SIZE * 2 + 1);
        if (ret)
            pr_err("%s: error %d during checksum conversion to hex\n", MODNAME, ret);
    }

skip_checksum:
    // get log entry length
    len = snprintf(NULL, 0, log_entry_base,
                   work_data->tm_violation.tm_year + 1900,
                   work_data->tm_violation.tm_mon + 1,
                   work_data->tm_violation.tm_mday,
                   work_data->tm_violation.tm_hour,
                   work_data->tm_violation.tm_min,
                   work_data->tm_violation.tm_sec,
                   work_data->target_func,
                   work_data->gid,
                   work_data->ttid,
                   work_data->uid,
                   work_data->euid,
                   target_pathname,
                   exe_pathname,
                   checksum_hex);
    if (len < 0)
    {
        pr_err("%s: error formatting log_entry - err %d \n", MODNAME, ret);
        goto out_hex;
    }

    log_entry = (char *)kmalloc(len + 1, GFP_KERNEL);
    if (!log_entry)
    {
        pr_err("%s: failed memory allocation for log_entry\n", MODNAME);
        ret = -ENOMEM;
        goto out_hex;
    }

    ret = snprintf(log_entry, len + 1, log_entry_base,
                   work_data->tm_violation.tm_year + 1900,
                   work_data->tm_violation.tm_mon + 1,
                   work_data->tm_violation.tm_mday,
                   work_data->tm_violation.tm_hour,
                   work_data->tm_violation.tm_min,
                   work_data->tm_violation.tm_sec,
                   work_data->target_func,
                   work_data->gid,
                   work_data->ttid,
                   work_data->uid,
                   work_data->euid,
                   target_pathname,
                   exe_pathname,
                   checksum_hex);
    if (ret < 0)
    {
        pr_err("%s: error formatting log_entry - err %d \n", MODNAME, ret);
        goto out;
    }

    ret = write_logfilefs(log_entry, len);
    if (ret < 0)
        pr_err("%s: error %d during log entry write\n", MODNAME, ret);
    else if (!ret)
        pr_info("%s: log entry no bytes written\n", MODNAME);

out:
    kfree(log_entry);
out_hex:
    if (checksum_hex)
        kfree(checksum_hex);
    kfree(buf_exe);
out_free_buf_target:
    kfree(buf_target);
out_work:
    path_put(work_data->target_path);
    kfree(work_data->target_path);
    path_put(work_data->exe_path);
    kfree(work_data->exe_path);
    kfree(work_data);
    module_put(THIS_MODULE);
}

int schedule_log_work(log_work *the_log_work, const char *target_func, struct path *target_path, struct path *exe_path)
{
    struct timespec64 now;
    struct tm tm_now;

    the_log_work->target_func = target_func;
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = target_path;
    the_log_work->exe_path = exe_path;

    ktime_get_real_ts64(&now);
    time64_to_tm(now.tv_sec, 0, &tm_now);
    the_log_work->tm_violation = tm_now;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    if (!queue_work(log_queue, &(the_log_work->the_work)))
        return -1;

    if (!try_module_get(THIS_MODULE))
        return -ENODEV;

    return 0;
}

// pre handler for syscall that have the pathname as first arg
static int the_pre_hook_sys_first_arg(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    int ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;
    
    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        return -ENOMEM;
    }

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    ret = kern_path((const char __user *)regs->di, LOOKUP_FOLLOW, target_path);
    if (ret == -ENOENT)
        goto out_free_path;
    if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s - err %d\n",
               MODNAME, ri->rph->rp->kp.symbol_name, (const char __user *)regs->di, ret);
        goto out_free_path;
    }

    if (check_path_or_parent_dir(target_path))
    {
        ret = -1;
        goto out_put_path;
    }
    regs->di = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_put_path;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: %s failed memory allocation for log_work\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, target_path, exe_path);
    if (ret)
    {
        pr_err("%s: failing schedule log work\n", MODNAME);
        goto out_free_work;
    }

    return -1;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
    return ret;
}

// pre handler for syscall that have the dirfd as first arg and pathname/filename as second arg
static int the_pre_hook_sys_at(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    char *buf;
    int dirfd, ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    dirfd = regs->di;

    if (buf[0] != '/') // relative path
        ret = user_path_at(dirfd, (const char __user *)regs->si, LOOKUP_FOLLOW, target_path);
    else // absolute path
        ret = kern_path((const char __user *)regs->si, LOOKUP_FOLLOW, target_path);

    if (ret == -ENOENT)
        goto out_free_path;
    if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s - err %d\n",
               MODNAME, ri->rph->rp->kp.symbol_name, buf, ret);
        goto out_free_path;
    }

    if (check_path_or_parent_dir(target_path) != 0)
    {
        ret = -1;
        goto out_free_path;
    }
    regs->si = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, target_path, exe_path);
    if (ret)
        goto out_free_work;

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_free_path:
    path_put(target_path);
    kfree(target_path);
out_free_buf:
    kfree(buf);
out:
    return 0;
}

// pre handler for open syscall
static int the_pre_hook_open(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *path, *exe_path;
    log_work *the_log_work;
    char *buf, *last;
    int flags, ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    flags = regs->si;

    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT))
        goto out;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->di, PATH_MAX);
    if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    if (flags & O_CREAT)
    {
        last = strrchr(buf, '/');
        if (!last) // filename
            ret = kern_path(".", LOOKUP_FOLLOW, path);
        else
        {
            *last = '\0';
            ret = kern_path(buf, LOOKUP_FOLLOW, path);
        }
    }
    else
        ret = kern_path(buf, LOOKUP_FOLLOW, path);

    if (ret == -ENOENT)
        goto out_free_path;
    if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, buf, ret);
        goto out_free_path;
    }

    if (check_path(path))
    {
        ret = -1;
        goto out_free_path;
    }
    regs->di = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: %s failed memory allocation for log_work\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, path, exe_path);
    if (ret)
    {
        pr_err("%s: failing schedule log work\n", MODNAME);
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_free_path:
    if (path)
        path_put(path);
    kfree(path);
out_free_buf:
    kfree(buf);
out:
    return ret;
}

// pre handler for openat syscall
static int the_pre_hook_openat(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    char *buf;
    int flags, dirfd, ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    flags = regs->dx;

    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT))
        goto out;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret == -EFAULT)
        goto out_free_buf;
    else if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    dirfd = regs->di;

    if (buf[0] != '/') // relative path
    {
        ret = user_path_at(dirfd, (const char __user *)regs->si, LOOKUP_FOLLOW, target_path);
        if (ret == -EFAULT)
            goto out_free_path;
    }
    else // absolute path
        ret = kern_path(buf, LOOKUP_FOLLOW, target_path);

    if (ret == -ENOENT)
        goto out_free_path;
    else if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s with dirfd %d - err %d\n",
               MODNAME, ri->rph->rp->kp.symbol_name, buf, dirfd, ret);
        goto out_free_path;
    }

    if (check_path(target_path))
    {
        ret = -1;
        goto out_free_path;
    }
    regs->si = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, target_path, exe_path);
    if (ret)
        goto out_free_work;

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_free_path:
    if (target_path)
        path_put(target_path);
    kfree(target_path);
out_free_buf:
    kfree(buf);
out:
    return ret;
}

// pre handler for openat2 syscall
static int the_pre_hook_openat2(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    char *buf;
    int flags, dirfd, ret = -1;
    struct open_how *how;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    how = (struct open_how *)regs->dx;
    flags = how->flags;
    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT))
        goto out;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    dirfd = regs->di;

    if (buf[0] != '/') // relative path
    {
        ret = user_path_at(dirfd, (const char __user *)regs->si, LOOKUP_FOLLOW, target_path);
        if (ret == -ENOENT || ret == -EFAULT)
            goto out_free_path;
        else if (ret)
        {
            pr_err("%s: %s cannot resolving target path %s - err %d\n",
                   MODNAME, ri->rph->rp->kp.symbol_name, buf, ret);
            goto out_free_path;
        }
    }
    else // absolute path
    {
        ret = kern_path(buf, LOOKUP_FOLLOW, target_path);
        if (ret == -ENOENT)
            goto out_free_path;
        else if (ret)
        {
            pr_err("%s: %s cannot resolving target path %s with dirfd %d - err %d\n",
                   MODNAME, ri->rph->rp->kp.symbol_name, buf, dirfd, ret);
            goto out_free_path;
        }
    }

    if (check_path(target_path))
    {
        ret = -1;
        goto out_free_path;
    }
    regs->si = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, target_path, exe_path);
    if (ret)
        goto out_free_work;

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_free_path:
    if (target_path)
        path_put(target_path);
    kfree(target_path);
out_free_buf:
    kfree(buf);
out:
    return ret;
}

// pre handler for creat syscall
static int the_pre_hook_creat(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *path, *exe_path;
    log_work *the_log_work;
    char *buf, *last;
    int ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->di, PATH_MAX);
    if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    last = strrchr(buf, '/');
    if (!last) // filename
        ret = kern_path(".", LOOKUP_FOLLOW, path);
    else
    {
        *last = '\0';
        ret = kern_path(buf, LOOKUP_FOLLOW, path);
    }

    if (ret == -ENOENT)
        goto out_free_path;
    if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, buf, ret);
        goto out_free_path;
    }

    if (check_path(path))
    {
        ret = -1;
        goto out_free_path;
    }
    regs->di = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: %s failed memory allocation for log_work\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, path, exe_path);
    if (ret)
    {
        pr_err("%s: failing schedule log work\n", MODNAME);
        goto out_free_work;
    }

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_free_path:
    if (path)
        path_put(path);
    kfree(path);
out_free_buf:
    kfree(buf);
out:
    return ret;
}

// pre handler for syscall that have the dirfd as first arg and pathname/filename as second arg
static int the_pre_hook_mkdirat(struct kretprobe_instance *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    char *buf, *last;
    int dirfd, ret = -1;
    struct filename *filename;
    struct file *dirfile;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        goto out;

    buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for buffer\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out;
    }

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
    if (ret <= 0)
    {
        pr_err("%s: %s failed to copy pathname from user space - err %d\n", MODNAME, ri->rph->rp->kp.symbol_name, ret);
        goto out_free_buf;
    }

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto out_free_buf;
    }

    dirfd = regs->di;

    last = strrchr(buf, '/');
    if (last)
        *last = '\0';

    if (buf[0] == '/') // absolute path
    {
        ret = kern_path(buf, LOOKUP_FOLLOW, target_path);
    }
    else if (!last) // filename
    {
        dirfile = fget(dirfd);
        if (IS_ERR(dirfile))
        {
            ret = -PTR_ERR(dirfile);
            goto out_free_path;
        }
        memcpy(target_path, &(dirfile->f_path), sizeof(struct path));
        path_get(target_path);
        ret = 0;
    }
    else // relative path
    {
        filename = getname_kernel(buf);
        if (IS_ERR(filename))
        {
            ret = -PTR_ERR(filename);
            goto out_free_path;
        }
        ret = user_path_at(dirfd, filename->uptr, LOOKUP_FOLLOW, target_path);
        putname(filename);
    }

    if (ret == -ENOENT)
        goto out_free_path;
    if (ret)
    {
        pr_err("%s: %s cannot resolving target path %s - err %d\n",
               MODNAME, ri->rph->rp->kp.symbol_name, buf, ret);
        goto out_free_path;
    }

    if (check_path_or_parent_dir(target_path) != 0)
    {
        ret = -1;
        goto out_put_path;
    }
    regs->si = (unsigned long)NULL;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->rph->rp->kp.symbol_name);
        ret = -ENOMEM;
        goto log_work;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

log_work:
    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    ret = schedule_log_work(the_log_work, ri->rph->rp->kp.symbol_name, target_path, exe_path);
    if (ret)
        goto out_free_work;

    ret = -1;
    goto out_free_buf;

out_free_work:
    kfree(the_log_work);
out_free_exe:
    if (exe_path)
    {
        path_put(exe_path);
        kfree(exe_path);
    }
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
out_free_buf:
    kfree(buf);
out:
    return 0;
}

int register_hooks(void)
{
    int i, ret;

    kretprobes[0].kp.symbol_name = unlink;
    kretprobes[0].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[0].maxactive = -1;

    kretprobes[1].kp.symbol_name = unlinkat;
    kretprobes[1].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_at;
    kretprobes[1].maxactive = -1;

    kretprobes[2].kp.symbol_name = rename;
    kretprobes[2].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[2].maxactive = -1;

    kretprobes[3].kp.symbol_name = renameat;
    kretprobes[3].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_at;
    kretprobes[3].maxactive = -1;

    kretprobes[4].kp.symbol_name = renameat2;
    kretprobes[4].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_at;
    kretprobes[4].maxactive = -1;

    kretprobes[5].kp.symbol_name = creat;
    kretprobes[5].entry_handler = (kretprobe_handler_t)the_pre_hook_creat;
    kretprobes[5].maxactive = -1;

    kretprobes[6].kp.symbol_name = rmdir;
    kretprobes[6].entry_handler = (kretprobe_handler_t)the_pre_hook_sys_first_arg;
    kretprobes[6].maxactive = -1;

    kretprobes[7].kp.symbol_name = open;
    kretprobes[7].entry_handler = (kretprobe_handler_t)the_pre_hook_open;
    kretprobes[7].maxactive = -1;

    kretprobes[8].kp.symbol_name = openat;
    kretprobes[8].entry_handler = (kretprobe_handler_t)the_pre_hook_openat;
    kretprobes[8].maxactive = -1;

    kretprobes[9].kp.symbol_name = openat2;
    kretprobes[9].entry_handler = (kretprobe_handler_t)the_pre_hook_openat2;
    kretprobes[9].maxactive = -1;

    kretprobes[10].kp.symbol_name = mkdir;
    kretprobes[10].entry_handler = (kretprobe_handler_t)the_pre_hook_creat;
    kretprobes[10].maxactive = -1;

    kretprobes[11].kp.symbol_name = mkdirat;
    kretprobes[11].entry_handler = (kretprobe_handler_t)the_pre_hook_mkdirat;
    kretprobes[11].maxactive = -1;

    for (i = 0; i < HOOKS; i++)
    {
        ret = register_kretprobe(&kretprobes[i]);
        if (ret)
            pr_err("%s: kretprobes %s register failed, error %d\n", MODNAME, kretprobes[i].kp.symbol_name, ret);
        else
            pr_info("%s: kretprobes %s register success\n", MODNAME, kretprobes[i].kp.symbol_name);
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
