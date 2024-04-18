#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/workqueue.h>
#include <linux/uidgid.h>

#include "reference_monitor.h"
#include "path_list.h"

#define unlink "__x64_sys_unlink"

#define BUFFER_SIZE 4096

#define get(regs) regs = (struct pt_regs *)the_regs->di;

typedef struct _log_work
{
    struct work_struct the_work;
    struct tm tm_violation;
    kgid_t gid;
    pid_t ttid;
    kuid_t uid;
    kuid_t euid;
    char *target_func;
    char *target_path;
    char *exe_pathname;
} log_work;

// kretprobes
struct kretprobe unlink_kretprobe;

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

    data = kmalloc(file_size, GFP_KERNEL);
    if (!data)
    {
        ret = -ENOMEM;
        goto out_close_file;
    }

    while (pos < file_size)
    {
        bytes_read = kernel_read(file, data + pos, BUFFER_SIZE, &pos);
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

    desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
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

    checksum_hex = kmalloc(SHA256_DIGEST_SIZE * 2 + 1, GFP_KERNEL);
    if (!checksum_hex)
    {
        pr_err("%s: error kmalloc for hex checksum\n", MODNAME);
        goto skip_checksum;
    }

    // convert checksum to hex string
    ret = binary2hexadecimal(checksum, SHA256_DIGEST_SIZE, checksum_hex, SHA256_DIGEST_SIZE * 2 + 1);
    if (ret < 0)
    {
        pr_err("%s: error %d during checksum conversion to hex\n", MODNAME, ret);
    }
    pr_info("%s: hex checksum len %ld\n", MODNAME, strlen(checksum_hex));

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
        goto out;
    }

    pr_info("%s: log_entry length %d\n", MODNAME, len);

    log_entry = kmalloc(len + 1, GFP_KERNEL);
    if (!log_entry)
    {
        pr_err("%s: failing kmalloc for log_entry\n", MODNAME);
        ret = -ENOMEM;
        goto out;
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

    // pr_info("%s: log_entry:\n%s", MODNAME, log_entry);

    ret = write_logfilefs(log_entry, len);
    if (ret < 0)
        pr_err("%s: error %d during header\n", MODNAME, ret);
    else if (ret == 0)
        pr_info("%s: no bytes written during header\n", MODNAME);
    else
        pr_info("%s: log entry written bytes %d\n", MODNAME, ret);

out:
    kfree(log_entry);
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

static int the_pre_unlink_hook(struct kprobe *ri, struct pt_regs *the_regs)
{
    struct pt_regs *regs;
    log_work *the_log_work;
    struct timespec64 now;
    struct tm tm_now;
    struct work_struct log_work;
    char *pathname, *exe_pathname, *exe_pathname_buf, *buf;
    int ret = -1;

    if (monitor_state == OFF || monitor_state == REC_OFF)
        return -1;

    buf = kmalloc(PATH_MAX, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: kmalloc failing for buffer\n", MODNAME);
        return -ENOMEM;
    }

    get(regs); // get the actual address of the CPU image seen by the system call (or its wrapper)

    // copy pathname from user space
    ret = strncpy_from_user(buf, (const char __user *)regs->di, PATH_MAX);
    if (ret < 0)
    {
        pr_err("%s: Failed to copy pathname from user space with error %d\n", MODNAME, ret);
        goto out_free_buf;
    }

    // kmalloc pathname
    pathname = kmalloc(strlen(buf) + 1, GFP_ATOMIC);
    if (!pathname)
    {
        pr_err("%s: kmalloc failing for pathname\n", MODNAME);
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
    pr_notice("%s: The unlink target %s is a protected pathname.\n", MODNAME, pathname);

    // d_path for exe_pathname
    exe_pathname_buf = d_path(&current->mm->exe_file->f_path, buf, PATH_MAX);
    if (IS_ERR(exe_pathname))
    {
        ret = -PTR_ERR(exe_pathname_buf);
        goto out_free_path;
    }

    // kmalloc exe_pathname
    exe_pathname = kmalloc(strlen(exe_pathname_buf) + 1, GFP_ATOMIC);
    if (!exe_pathname)
    {
        pr_err("%s: kmalloc failing for exe_pathname\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_path;
    }

    // copy exe_pathname from buf
    memcpy(exe_pathname, exe_pathname_buf, strlen(exe_pathname_buf) + 1);

    // prepare log_work
    the_log_work = kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: kmalloc failing for log_work\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_exe;
    }

    the_log_work->target_func = unlink;
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

    regs->di = (unsigned long)NULL;

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
    int ret;

    unlink_kretprobe.kp.symbol_name = unlink;
    unlink_kretprobe.entry_handler = (kretprobe_handler_t)the_pre_unlink_hook;
    unlink_kretprobe.maxactive = -1;

    // register unlink hook
    ret = register_kretprobe(&unlink_kretprobe);
    if (likely(ret == 0))
        pr_info("%s: kretprobe register of %s success\n", MODNAME, unlink);
    else
        pr_err("%s: kretprobe register of %s failed, returned %d\n", MODNAME, unlink, ret);

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
        pr_info("%s: kretprobe disable of %s success\n", MODNAME, unlink);
    else
        pr_err("%s: kretprobe disable of %s failed, returned %d\n", MODNAME, unlink, ret);

    return ret;
}

int enable_hooks(void)
{
    int ret;

    ret = enable_kretprobe(&unlink_kretprobe);
    if (likely(ret == 0))
        pr_info("%s: kretprobe enable of %s success\n", MODNAME, unlink);
    else
        pr_err("%s: kretprobe enable of %s failed, returned %d\n", MODNAME, unlink, ret);

    return ret;
}
