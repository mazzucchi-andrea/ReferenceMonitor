#include <crypto/hash.h>
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/kprobes.h>
#include <linux/namei.h>

#include "reference_monitor.h"
#include "path_list.h"

#define do_unlinkat "do_unlinkat"
#define do_rmdir "do_rmdir"
#define do_renameat2 "do_renameat2"
#define do_mkdirat "do_mkdirat"
#define do_sys_openat2 "do_sys_openat2"
#define file_open_root "file_open_root"

#define calc_enoent "program attempting the illegal operation no longer exists"

#define WRAPPERS 6
#define MAX_TRIES 10

unsigned long err = -EPERM;

typedef struct _log_work
{
    struct work_struct the_work;
    kgid_t gid;
    pid_t ttid;
    kuid_t uid;
    kuid_t euid;
    struct path *target_path;
    struct path *exe_path;
} log_work;

// kprobes struff
static struct kprobe **kprobes;
bool kps_reg = false; // the register state 

int binary2hexadecimal(const u8 *bin, size_t bin_len, char *buf, size_t buf_len)
{
    static const char hex_table[] = "0123456789ABCDEF";
    size_t i;

    if (buf_len < bin_len * 2 + 1)
        return -ENOBUFS;

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
    loff_t pos = 0;
    ssize_t bytes_read;
    u8 *data;

    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file))
    {
        pr_err("%s: failed to open file %s - err %ld\n", MODNAME, filename, PTR_ERR(filename));
        return -PTR_ERR(file);
    }

    tfm = crypto_alloc_shash(SHA256, 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("%s: unable to allocate tfm - err %ld\n", MODNAME, PTR_ERR(tfm));
        ret = PTR_ERR(tfm);
        goto out_close_file;
    }

    desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    if (!desc)
    {
        pr_err("%s: unamee to allocate desc\n", MODNAME);
        ret = -ENOMEM;
        goto out_free_tfm;
    }

    desc->tfm = tfm;

    ret = crypto_shash_init(desc);
    if (ret)
    {
        pr_err("%s: crypto_shash_init failed - err %d\n", MODNAME, ret);
        goto out_free_desc;
    }

    data = (u8 *)kmalloc(4096, GFP_KERNEL);
    if (!data)
    {
        ret = -ENOMEM;
        goto out_free_desc;
    }

    while ((bytes_read = kernel_read(file, data, 4096, &pos)) > 0)
    {
        ret = crypto_shash_update(desc, data, bytes_read);
        if (ret)
        {
            pr_err("%s: crypto_shash_update failed - err %d\n", MODNAME, ret);
            goto out_free_data;
        }
    }

    if (bytes_read < 0)
    {
        ret = bytes_read;
        goto out_free_data;
    }

    ret = crypto_shash_final(desc, checksum);
    if (ret)
        pr_err("%s: failing checksum calculation - err %d\n", MODNAME, ret);

out_free_data:
    kfree(data);
out_free_desc:
    kfree(desc);
out_free_tfm:
    crypto_free_shash(tfm);
out_close_file:
    filp_close(file, NULL);
    return ret;
}

void logger(unsigned long data)
{
    log_work *work_data = container_of((void *)data, log_work, the_work);
    u8 checksum[SHA256_DIGEST_SIZE] = {0};
    int ret, len;
    char *log_entry, *checksum_hex, *target_pathname, *exe_pathname, *buf_target, *buf_exe;
    char *log_entry_base = "gid:\t%d\n"
                           "ttid:\t%d\n"
                           "uid:\t%d\n"
                           "euid:\t%d\n"
                           "target:\t\t%s\n"
                           "exe_file:\t%s\n"
                           "%s\n";

    if (atomic_read(&fs_mounted))
        goto out_free_work;

    buf_target = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf_target)
    {
        pr_err("%s: failed memory allocation for buffer\n", MODNAME);
        goto out_free_work;
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

    if (!ret) // convert checksum to hex string
    {
        ret = binary2hexadecimal(checksum, SHA256_DIGEST_SIZE, checksum_hex, SHA256_DIGEST_SIZE * 2 + 1);
        if (ret)
            pr_err("%s: error %d during checksum conversion to hex\n", MODNAME, ret);
    }
    else if (ret == -ENOENT)
        snprintf(checksum_hex, SHA256_DIGEST_SIZE * 2 + 1, calc_enoent);

skip_checksum:
    // get log entry length
    len = snprintf(NULL, 0, log_entry_base,
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
        pr_err("%s: write_logfilefs failed - err %d\n", MODNAME, ret);
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
out_free_work:
    path_put(work_data->target_path);
    kfree(work_data->target_path);
    path_put(work_data->exe_path);
    kfree(work_data->exe_path);
    kfree(work_data);
    module_put(THIS_MODULE);
}

static inline int schedule_log_work(log_work *the_log_work, const char *target_func, struct path *target_path, struct path *exe_path)
{
    the_log_work->gid = current->cred->gid;
    the_log_work->ttid = task_pid_vnr(current);
    the_log_work->uid = current->cred->uid;
    the_log_work->euid = current->cred->euid;
    the_log_work->target_path = target_path;
    the_log_work->exe_path = exe_path;

    INIT_WORK(&(the_log_work->the_work), (void *)logger);
    if (!queue_work(log_queue, &(the_log_work->the_work)))
        return -1;

    if (!try_module_get(THIS_MODULE))
        return -ENODEV;

    return 0;
}

static int do_general_wrapper(struct kprobe *ri, struct pt_regs *regs)
{
    struct path *target_path, *exe_path;
    struct filename *filename;
    log_work *the_log_work;
    int dfd, ret;

    dfd = (int)regs->di;
    filename = (struct filename *)regs->si;

    if (IS_ERR(filename))
        return 0;

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }

    ret = user_path_at(dfd, filename->uptr, LOOKUP_FOLLOW, target_path);
    if (ret)
    {
        if (ret != -2)
            pr_err("%s: %s cannot resolving target path with dfd %d and name %s - err %d\n", MODNAME, ri->symbol_name, dfd, filename->name, ret);
        goto out_free_path;
    }

    if (check_path_or_parent_dir(target_path))
        goto out_put_path;

    regs->di = err;
    memcpy(&(regs->si), &(err), sizeof(unsigned long));

    if (atomic_read(&fs_mounted))
        goto out_put_path;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        goto out_put_path;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        goto out_free_exe;
    }

    if (!schedule_log_work(the_log_work, ri->symbol_name, target_path, exe_path))
        return 0;

    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
    return 0;
}

static int do_renameat2_wrapper(struct kprobe *ri, struct pt_regs *regs)
{
    struct path *target_path, *exe_path;
    struct filename *filename;
    log_work *the_log_work;
    int dfd, ret;
    bool first = true;

    dfd = (int)regs->di;
    filename = (struct filename *)regs->si;

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }

newname:
    if (IS_ERR(filename))
        goto out_free_path;

    ret = user_path_at(dfd, filename->uptr, LOOKUP_FOLLOW, target_path);
    if (ret)
    {
        if (ret != -2)
            pr_err("%s: %s cannot resolving target path with dfd %d and name %s - err %d\n", MODNAME, ri->symbol_name, dfd, filename->name, ret);
        goto out_free_path;
    }

    if (check_path_or_parent_dir(target_path))
    {
        if (first)
        {
            first = false;
            dfd = (int)regs->dx;
            filename = (struct filename *)regs->cx;
            path_put(target_path);
            target_path->dentry = NULL;
            target_path->mnt = NULL;
            goto newname;
        }
        goto out_put_path;
    }

    regs->di = err;
    memcpy(&(regs->si), &(err), sizeof(unsigned long));

    if (atomic_read(&fs_mounted))
        goto out_put_path;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        ret = 0;
        goto out_put_path;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        goto out_free_exe;
    }

    if (!schedule_log_work(the_log_work, ri->symbol_name, target_path, exe_path))
        return 0;

    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
    return 0;
}

static int do_mkdirat_wrapper(struct kprobe *ri, struct pt_regs *regs)
{
    struct path *target_path, *exe_path, dfd_path;
    struct filename *filename;
    struct file *f;
    log_work *the_log_work;
    int dfd, ret;
    size_t len;
    char *buf, *last;

    dfd = (int)regs->di;
    filename = (struct filename *)regs->si;

    if (IS_ERR(filename))
        return 0;

    len = strlen(filename->name);
    if (len == 0)
        return 0;

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }

    buf = (char *)kmalloc(len + 1, GFP_ATOMIC);
    if (!buf)
    {
        pr_err("%s: %s failed memory allocation for filename->name buffer\n", MODNAME, ri->symbol_name);
        goto out_free_path;
    }
    memcpy(buf, filename->name, len + 1);

    last = strrchr(buf, '/');
    if (!last) // only filename
    {
        if (dfd == AT_FDCWD)
        {
            get_fs_pwd(current->fs, target_path);
            ret = 0;
        }
        else
        {
            f = fget(dfd);
            if (!f)
            {
                pr_err("%s: %s can not get struct file\n", MODNAME, ri->symbol_name);
                kfree(buf);
                goto out_free_path;
            }
            memcpy(target_path, &(f->f_path), sizeof(struct path));
            path_get(target_path);
            fput(f);
            ret = 0;
        }
    }
    else if (buf[0] == '/') // absolute path
    {
        *last = '\0';
        ret = kern_path(buf, LOOKUP_FOLLOW, target_path);
    }
    else // relative path
    {
        *last = '\0';
        if (dfd == AT_FDCWD)
            get_fs_pwd(current->fs, &dfd_path);
        else
        {
            f = fget(dfd);
            if (!f)
            {
                kfree(buf);
                goto out_free_path;
            }
            memcpy(&dfd_path, &(f->f_path), sizeof(struct path));
            fput(f);
        }
        ret = vfs_path_lookup(dfd_path.dentry, dfd_path.mnt, buf, LOOKUP_FOLLOW, target_path);
    }
    kfree(buf);

    if (ret)
    {
        if (ret != -2)
            pr_err("%s: %s cannot resolving target path with dfd %d and name %s - err %d\n", MODNAME, ri->symbol_name, dfd, (const char __user *)regs->si, ret);
        goto out_free_path;
    }

    if (check_path(target_path))
        goto out_put_path;

    regs->di = err;
    memcpy(&(regs->si), &(err), sizeof(unsigned long));

    if (atomic_read(&fs_mounted))
        goto out_put_path;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        goto out_put_path;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        goto out_free_exe;
    }

    if (!schedule_log_work(the_log_work, ri->symbol_name, target_path, exe_path))
        return 0;

    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
    return 0;
}

static int do_sys_openat2_wrapper(struct kprobe *ri, struct pt_regs *regs)
{
    struct path *target_path, *exe_path, dfd_path;
    struct file *f;
    char *buf, *last;
    log_work *the_log_work;
    int dfd, flags, ret;

    dfd = (int)regs->di;
    flags = ((struct open_how *)regs->dx)->flags;

    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT))
        return 0;

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }

    ret = user_path_at(dfd, (const char __user *)regs->si, LOOKUP_FOLLOW, target_path);
    if (ret && (flags & O_CREAT))
    {
        buf = (char *)kmalloc(PATH_MAX, GFP_ATOMIC);
        if (!buf)
        {
            pr_err("%s: %s failed memory allocation for filename buffer\n", MODNAME, ri->symbol_name);
            goto out_free_path;
        }
        ret = strncpy_from_user(buf, (const char __user *)regs->si, PATH_MAX);
        if (ret <= 0)
        {
            if (!ret)
                pr_err("%s: %s failed strncpy_from_user filename\n", MODNAME, ri->symbol_name);
            kfree(buf);
            goto out_free_path;
        }
        last = strrchr(buf, '/');
        if (!last) // only filename
        {
            if (dfd == AT_FDCWD)
            {
                get_fs_pwd(current->fs, target_path);
                ret = 0;
            }
            else
            {
                f = fget(dfd);
                if (!f)
                {
                    kfree(buf);
                    goto out_free_path;
                }
                memcpy(target_path, &(f->f_path), sizeof(struct path));
                path_get(target_path);
                fput(f);
                ret = 0;
            }
        }
        else if (buf[0] == '/') // absolute path
        {
            *last = '\0';
            ret = kern_path(buf, LOOKUP_FOLLOW, target_path);
        }
        else // relative path
        {
            *last = '\0';
            if (dfd == AT_FDCWD)
                get_fs_pwd(current->fs, &dfd_path);
            else
            {
                f = fget(dfd);
                if (!f)
                {
                    kfree(buf);
                    goto out_free_path;
                }
                memcpy(&dfd_path, &(f->f_path), sizeof(struct path));
                fput(f);
            }
            ret = vfs_path_lookup(dfd_path.dentry, dfd_path.mnt, buf, LOOKUP_FOLLOW, target_path);
        }
        kfree(buf);
    }

    if (ret)
    {
        if (ret != -2)
            pr_err("%s: %s cannot resolving target path with dfd %d and name %s - err %d\n", MODNAME, ri->symbol_name, dfd, (const char __user *)regs->si, ret);
        goto out_free_path;
    }

    if (check_path(target_path))
        goto out_put_path;

    regs->di = (unsigned long)NULL;
    regs->si = (unsigned long)NULL;

    if (atomic_read(&fs_mounted))
        goto out_put_path;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        goto out_put_path;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        goto out_free_exe;
    }

    if (!schedule_log_work(the_log_work, ri->symbol_name, target_path, exe_path))
        return 0;

    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
out_free_path:
    kfree(target_path);
    return 0;
}

static int file_open_root_wrapper(struct kprobe *ri, struct pt_regs *regs)
{
    struct path *target_path, *exe_path;
    log_work *the_log_work;
    int flags;

    flags = regs->dx;

    if ((flags & O_ACCMODE) == O_RDONLY && !(flags & O_CREAT))
        return 0;

    target_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!target_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }

    memcpy(target_path, (struct path *)regs->di, sizeof(struct path));
    path_get(target_path);

    if (check_path(target_path))
        goto out_put_path;

    regs->di = (unsigned long)NULL;
    regs->si = (unsigned long)NULL;

    if (atomic_read(&fs_mounted))
        goto out_put_path;

    exe_path = (struct path *)kmalloc(sizeof(struct path), GFP_ATOMIC);
    if (!exe_path)
    {
        pr_err("%s: %s failed memory allocation for struct path\n", MODNAME, ri->symbol_name);
        return 0;
    }
    memcpy(exe_path, &current->mm->exe_file->f_path, sizeof(struct path));
    path_get(exe_path);

    // prepare log_work
    the_log_work = (log_work *)kzalloc(sizeof(log_work), GFP_ATOMIC);
    if (!the_log_work)
    {
        pr_err("%s: failed memory allocation for log_work\n", MODNAME);
        goto out_free_exe;
    }

    if (!schedule_log_work(the_log_work, ri->symbol_name, target_path, exe_path))
        return 0;

    kfree(the_log_work);
out_free_exe:
    path_put(exe_path);
    kfree(exe_path);
out_put_path:
    path_put(target_path);
    kfree(target_path);
    return 0;
}

int init_wrappers(void)
{
    int i;

    kprobes = kmalloc_array(WRAPPERS, sizeof(struct kprobe *), GFP_KERNEL);
    if (!kprobes)
    {
        pr_err("%s: Memory allocation for kprobes array failed\n", MODNAME);
        return -ENOMEM;
    }

    for (i = 0; i < WRAPPERS; i++)
    {
        kprobes[i] = kmalloc(sizeof(struct kprobe), GFP_KERNEL);
        if (!kprobes[i])
        {
            pr_err("%s: Memory allocation for kprobe %d failed\n", MODNAME, i);
            while (--i >= 0)
            {
                kfree(kprobes[i]);
            }
            kfree(kprobes);
            return -ENOMEM;
        }
        memset(kprobes[i], 0, sizeof(struct kprobe));
    }

    kprobes[0]->symbol_name = do_unlinkat;
    kprobes[0]->pre_handler = do_general_wrapper;

    kprobes[1]->symbol_name = do_rmdir;
    kprobes[1]->pre_handler = do_general_wrapper;

    kprobes[2]->symbol_name = do_renameat2;
    kprobes[2]->pre_handler = do_renameat2_wrapper;

    kprobes[3]->symbol_name = do_mkdirat;
    kprobes[3]->pre_handler = do_mkdirat_wrapper;

    kprobes[4]->symbol_name = do_sys_openat2;
    kprobes[4]->pre_handler = do_sys_openat2_wrapper;

    kprobes[5]->symbol_name = file_open_root;
    kprobes[5]->pre_handler = file_open_root_wrapper;

    if (register_kprobes(kprobes, WRAPPERS))
        return -1;
    kps_reg = true;
    return 0;;
}

void cleanup_wrappers(void)
{
    int i;

    unregister_kprobes(kprobes, WRAPPERS);

    for (i = 0; i < WRAPPERS; i++)
        kfree(kprobes[i]);

    kfree(kprobes);

    kps_reg = false;
}

int enable_wrappers(void)
{
    int i, tries;
    bool enabled;
    int disabled[WRAPPERS] = {0};

    if (!kps_reg)
        return init_wrappers();

    for (i = 0; i < WRAPPERS; i++)
    {
        if (kprobe_disabled(kprobes[i]))
        retry:
            disabled[i] = enable_kprobe(kprobes[i]);
    }

    for (i = 0; i < WRAPPERS; i++)
    {
        if (disabled[i])
        {
            if (tries > MAX_TRIES)
            {
                enabled = false;
                break;
            }
            else
            {
                tries++;
                goto retry;
            }
        }
    }

    if (enabled)
        return 0;

    cleanup_wrappers();
    return init_wrappers();
}

void disable_wrappers(void)
{
    int i, tries;
    bool disabled;
    int enabled[WRAPPERS] = {0};

    if (!kps_reg)
        return;

    for (i = 0; i < WRAPPERS; i++)
    {
        if (!kprobe_disabled(kprobes[i]))
        retry:
            enabled[i] = disable_kprobe(kprobes[i]);
    }

    for (i = 0; i < WRAPPERS; i++)
    {
        if (enabled[i])
        {
            if (tries > MAX_TRIES)
            {
                disabled = false;
                break;
            }
            else
            {
                tries++;
                goto retry;
            }
        }
    }

    if (disabled)
        return;

    cleanup_wrappers();
}
