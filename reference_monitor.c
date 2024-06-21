#define EXPORT_SYMTAB
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/version.h>
#include <linux/vmalloc.h>

#include "lib/include/scth.h"
#include "lib/include/usctm.h"
#include "reference_monitor.h"
#include "logfilefs.h"
#include "path_list.h"
#include "wrappers.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mazzucchi <mazzucchiandrea@gmail.com>");

u8 digest_password[SHA256_DIGEST_SIZE];
char *the_password;
module_param(the_password, charp, 0);

// file system stuff
struct super_block *device_sb;
DECLARE_RWSEM(log_rw);
DEFINE_SPINLOCK(fs_spinlock);
bool fs_mounted = false;

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

struct workqueue_struct *log_queue;

int8_t monitor_state = REC_ON;

int hash_password(const char *password, size_t password_len, u8 *hash)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        int ret = -ENOMEM;
        u8 *digest;

        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm))
        {
                pr_err("%s: unable to allocate crypto hash\n", MODNAME);
                return PTR_ERR(tfm);
        }

        desc = (struct shash_desc *)kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc)
                goto out_free_tfm;

        desc->tfm = tfm;

        digest = (u8 *)kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if (!digest)
                goto out_free_desc;

        ret = crypto_shash_digest(desc, password, password_len, digest);
        if (ret)
        {
                pr_err("%s: error hashing password with err %d\n", MODNAME, ret);
                goto out_free_digest;
        }

        memcpy(hash, digest, SHA256_DIGEST_SIZE);

out_free_digest:
        kfree(digest);
out_free_desc:
        kfree(desc);
out_free_tfm:
        crypto_free_shash(tfm);
        return ret;
}

int check_password(char *password)
{
        u8 digest[SHA256_DIGEST_SIZE];

        if (strlen(password) <= 0)
                return -1;

        if (hash_password(password, strlen(password), digest) < 0)
                return -1;

        if (memcmp(digest_password, digest, SHA256_DIGEST_SIZE) != 0)
                return -1;

        return 0;
}

int check_root(void)
{
        kuid_t euid = current_cred()->euid;
        if (euid.val != 0)
                return -1;
        return 0;
}

void print_current_monitor_state(void)
{
        switch (monitor_state)
        {
        case ON:
                pr_info("%s: current state is ON.\n", MODNAME);
                break;
        case OFF:
                pr_info("%s: current state is OFF.\n", MODNAME);
                break;
        case REC_ON:
                pr_info("%s: current state is REC_ON.\n", MODNAME);
                break;
        case REC_OFF:
                pr_info("%s: current state is REC_OFF.\n", MODNAME);
                break;
        default:
                break;
        }
}

int check_rec_state(void)
{
        if (monitor_state == ON || monitor_state == OFF)
                return -1;
        return 0;
}

__SYSCALL_DEFINEx(2, _change_state, const char __user *, password, int, state)
{
        int ret;
        long copied;
        char passwd_buf[PASSWORD_MAX_LEN];

        pr_info("%s: _change_state called.\n", MODNAME);

        if (check_root() < 0)
        {
                pr_notice("%s: only root can change the monitor state.\n", MODNAME);
                return -EPERM;
        }

        copied = strncpy_from_user(passwd_buf, password, PASSWORD_MAX_LEN);
        if (copied < 0)
        {
                return -EFAULT;
        }

        if (check_password(passwd_buf) < 0)
        {
                pr_notice("%s: invalid password.\n", MODNAME);
                return -1;
        }

        print_current_monitor_state();

        if (state < 0 || state > 3)
        {
                pr_notice("%s: invalid state %d.\n", MODNAME, state);
                return -1;
        }

        if ((state == ON || state == REC_ON) && (monitor_state == OFF || monitor_state == REC_OFF))
        {
                ret = register_wrappers();
                if (unlikely(ret != 0))
                        return ret;
                refresh_list();
                print_paths();
        }
        else if ((state == OFF || state == REC_OFF) && (monitor_state == ON || monitor_state == REC_ON))
                unregister_wrappers();

        monitor_state = state;

        pr_info("%s: state changed.\n", MODNAME);

        print_current_monitor_state();

        return 0;
}

__SYSCALL_DEFINEx(3, _edit_paths, const char __user *, password, const char __user *, path, int, mode)
{
        struct path _path;
        long copied;
        int ret = 0;
        char passwd_buf[PASSWORD_MAX_LEN];

        pr_info("%s: _edit_paths called.\n", MODNAME);

        if (check_root() < 0)
        {
                pr_notice("%s: only root can edit the monitor paths.\n", MODNAME);
                return -EPERM;
        }

        if (mode != ADD && mode != REMOVE)
        {
                pr_notice("%s: invalid mode\n", MODNAME);
                return -EINVAL;
        }

        if (check_rec_state() < 0)
        {
                pr_notice("%s: invalid monitor state.\n", MODNAME);
                return -1;
        }

        copied = strncpy_from_user(passwd_buf, password, PASSWORD_MAX_LEN);
        if (copied < 0)
        {
                pr_err("%s: failing copy password from user\n", MODNAME);
                return -EFAULT;
        }

        if (check_password(passwd_buf) < 0)
        {
                pr_notice("%s: invalid password.\n", MODNAME);
                return -1;
        }

        ret = user_path_at(AT_FDCWD, path, LOOKUP_FOLLOW, &_path);
        if (ret)
        {
                pr_err("%s: cannot resolving path\n", MODNAME);
                return ret;
        }

        if (mode == ADD)
                ret = add_path(&_path);
        else
                ret = remove_path(&_path);

        if (!ret)
                print_paths();
        else
                path_put(&_path);

        return ret;
}

__SYSCALL_DEFINEx(2, _change_password, const char __user *, old_password, const char __user *, new_password)
{
        int ret;
        long copied;
        u8 new_digest[SHA256_DIGEST_SIZE];
        char old_passwd_buf[PASSWORD_MAX_LEN];
        char new_passwd_buf[PASSWORD_MAX_LEN];

        pr_info("%s: _change_password called\n", MODNAME);

        if (check_root() < 0)
        {
                pr_notice("%s: only root can change the monitor password\n", MODNAME);
                return -EPERM;
        }

        copied = strncpy_from_user(old_passwd_buf, old_password, PASSWORD_MAX_LEN);
        if (copied < 0)
        {
                return -EFAULT;
        }

        copied = strncpy_from_user(new_passwd_buf, new_password, PASSWORD_MAX_LEN);
        if (copied < 0)
        {
                return -EFAULT;
        }

        if (check_password(old_passwd_buf) < 0)
        {
                pr_notice("%s: invalid password.\n", MODNAME);
                return -1;
        }

        if (strlen(new_passwd_buf) <= 0)
        {
                pr_notice("%s: invalid new password length\n", MODNAME);
                return -1;
        }

        ret = hash_password(new_passwd_buf, strlen(new_passwd_buf), new_digest);
        if (ret)
        {
                pr_err("%s: failing hashing new password\n", MODNAME);
                return ret;
        }

        memcpy(digest_password, new_digest, SHA256_DIGEST_SIZE);

        pr_info("%s: password changed\n", MODNAME);
        return 0;
}

long sys_change_state = (unsigned long)__x64_sys_change_state;
long sys_edit_paths = (unsigned long)__x64_sys_edit_paths;
long sys_change_password = (unsigned long)__x64_sys_change_password;

static struct super_operations logfilefs_super_ops = {};

static struct dentry_operations logfilefs_dentry_ops = {};

int logfilefs_fill_super(struct super_block *sb, void *data, int silent)
{
        struct inode *root_inode;
        struct buffer_head *bh;
        struct logfilefs_sb_info *sb_disk;
        struct timespec64 curr_time;
        uint64_t magic;
        long long int data_blocks;
        loff_t maxbytes;

        // Unique identifier of the filesystem
        sb->s_magic = MAGIC;

        bh = sb_bread(sb, SB_BLOCK_NUMBER);
        if (!sb)
        {
                pr_err("%s: logfilefs super_block read failed.\n", MODNAME);
                return -EIO;
        }
        sb_disk = (struct logfilefs_sb_info *)bh->b_data;
        magic = sb_disk->magic;
        brelse(bh);

        // check on the expected magic number
        if (magic != sb->s_magic)
        {
                pr_err("%s: logfilefs wrong magic number.\n", MODNAME);
                return -EBADF;
        }

        sb->s_fs_info = NULL;            // FS specific data (the magic number) already reported into the generic superblock
        sb->s_op = &logfilefs_super_ops; // set our own operations

        data_blocks = (long long int)(get_capacity(sb->s_bdev->bd_disk) * bdev_logical_block_size(sb->s_bdev) / DEFAULT_BLOCK_SIZE) - 2;
        pr_info("%s: logfilefs data blocks number %lld.\n", MODNAME, data_blocks);

        maxbytes = data_blocks * DEFAULT_BLOCK_SIZE;
        sb->s_maxbytes = maxbytes;
        pr_info("%s: logfilefs maxbytes %lld.\n", MODNAME, maxbytes);

        root_inode = iget_locked(sb, LOGFILEFS_ROOT_INODE_NUMBER); // get a root inode from cache
        if (!root_inode)
        {
                pr_err("%s: logfilefs can not get root_inode.\n", MODNAME);
                return -ENOMEM;
        }

        inode_init_owner(sb->s_user_ns, root_inode, NULL, S_IFDIR); // set the root user as owner of the FS root
        root_inode->i_sb = sb;
        root_inode->i_op = &logfilefs_inode_ops;       // set our inode operations
        root_inode->i_fop = &logfilefs_dir_operations; // set our file operations
        // update access permission
        root_inode->i_mode = S_IFDIR | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;

        // baseline alignment of the FS timestamp to the current time
        ktime_get_real_ts64(&curr_time);
        root_inode->i_atime = root_inode->i_mtime = root_inode->i_ctime = curr_time;

        // no inode from device is needed - the root of our file system is an in memory object
        root_inode->i_private = NULL;

        sb->s_root = d_make_root(root_inode);
        if (!sb->s_root)
        {
                pr_err("%s: logfilefs d_make_root failed.\n", MODNAME);
                return -ENOMEM;
        }

        sb->s_root->d_op = &logfilefs_dentry_ops; // set our dentry operations

        // unlock the inode to make it usable
        unlock_new_inode(root_inode);

        device_sb = sb;

        return 0;
}

static void logfilefs_kill_superblock(struct super_block *s)
{
        unsigned long flags;

        down_write(&log_rw);

        spin_lock_irqsave(&fs_spinlock, flags);
        fs_mounted = false;
        spin_unlock_irqrestore(&fs_spinlock, flags);
        device_sb = NULL;

        kill_block_super(s);
        pr_info("%s: logfilefs unmount succesful.\n", MODNAME);

        up_write(&log_rw);

        return;
}

// called on file system mounting
struct dentry *logfilefs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
        struct dentry *ret;
        unsigned long irq_flags;

        down_write(&log_rw);

        ret = mount_bdev(fs_type, flags, dev_name, data, logfilefs_fill_super);

        if (unlikely(IS_ERR(ret)))
        {
                pr_err("%s: error mounting logfilefs\n", MODNAME);
                up_write(&log_rw);
                return ret;
        }
        else
                pr_info("%s: logfilefs is succesfully mounted on from device %s\n", MODNAME, dev_name);

        spin_lock_irqsave(&fs_spinlock, irq_flags);
        fs_mounted = true;
        spin_unlock_irqrestore(&fs_spinlock, irq_flags);
        up_write(&log_rw);

        return ret;
}

// file system structure
static struct file_system_type logfilefs_type = {
    .owner = THIS_MODULE,
    .name = "logfilefs",
    .mount = logfilefs_mount,
    .kill_sb = logfilefs_kill_superblock,
};

void logfilefs_update_file_size(loff_t file_size)
{
        struct buffer_head *bh;
        logfilefs_inode *inode;

        bh = sb_bread(device_sb, LOGFILEFS_INODES_BLOCK_NUMBER);
        if (!bh)
                return;
        inode = (logfilefs_inode *)bh->b_data;
        inode->file_size = file_size;
        mark_buffer_dirty(bh);
        sync_dirty_buffer(bh);
        brelse(bh);
}

loff_t logfilefs_get_file_size(void)
{
        struct buffer_head *bh;
        logfilefs_inode *inode;
        loff_t file_size;

        bh = sb_bread(device_sb, LOGFILEFS_INODES_BLOCK_NUMBER);
        if (!bh)
                return -EIO;
        inode = (logfilefs_inode *)bh->b_data;
        file_size = inode->file_size;
        brelse(bh);

        return file_size;
}

bool is_mounted(void)
{
        bool ret = false;
        unsigned long flags;
        spin_lock_irqsave(&fs_spinlock, flags);
        ret = fs_mounted;
        spin_unlock_irqrestore(&fs_spinlock, flags);
        return ret;
}

/*
 * Return: -ENODEV if logfilefs is not mounted, -EBUSY if lock is busy,
 * 0 on success
 */
int try_log_write_lock(void)
{
        unsigned long flags;
        int ret = 0;
        spin_lock_irqsave(&fs_spinlock, flags);
        if (fs_mounted)
        {
                if (!down_write_trylock(&log_rw))
                {
                        ret = -EBUSY;
                }
        }
        else
                ret = -ENODEV;
        spin_unlock_irqrestore(&fs_spinlock, flags);
        return ret;
}

/*
 * Return: -ENODEV if logfilefs is not mounted, -EBUSY if lock is busy,
 * 0 on success
 */
int try_log_read_lock(void)
{
        unsigned long flags;
        int ret = 0;
        spin_lock_irqsave(&fs_spinlock, flags);
        if (fs_mounted)
        {
                if (!down_read_trylock(&log_rw))
                        ret = -EBUSY;
        }
        else
                ret = -ENODEV;
        spin_unlock_irqrestore(&fs_spinlock, flags);
        return ret;
}

ssize_t write_logfilefs(char *data, size_t len)
{
        int block_to_write, ret;
        loff_t file_size, offset;
        loff_t maxbytes = device_sb->s_maxbytes;
        ssize_t bytes_written = 0;
        struct buffer_head *bh;

        ret = try_log_write_lock();
        if (ret)
                return ret;

        file_size = logfilefs_get_file_size();
        if (file_size < 0)
        {
                up_write(&log_rw);
                return -EIO;
        }

        offset = file_size; // always append

        // check file size
        if (file_size == maxbytes)
        {
                // pr_err("%s: logfile is full\n", MODNAME);
                up_write(&log_rw);
                return -ENOSPC; // fs full
        }

        if (file_size + len > maxbytes)
                len = maxbytes - file_size; // can't write all the bytes

        // write log_entry
        while (bytes_written < len)
        {
                int bytes_to_write = min(len - bytes_written, (size_t)(DEFAULT_BLOCK_SIZE - (offset % DEFAULT_BLOCK_SIZE)));
                block_to_write = offset / DEFAULT_BLOCK_SIZE + 2;

                bh = sb_bread(device_sb, block_to_write);
                if (!bh)
                {
                        pr_err("%s: can not get the block for logging work\n", MODNAME);
                        logfilefs_update_file_size(file_size);
                        up_write(&log_rw);
                        return -EIO;
                }
                memcpy((bh->b_data + (offset % DEFAULT_BLOCK_SIZE)), (data + bytes_written), bytes_to_write);
                mark_buffer_dirty(bh);
                sync_dirty_buffer(bh);
                brelse(bh);

                bytes_written += bytes_to_write;
                offset += bytes_to_write;
                file_size += bytes_to_write;
                logfilefs_update_file_size(file_size);
        }

        up_write(&log_rw);
        return bytes_written;
}

int init_module(void)
{
        int i, ret;

        if (LINUX_VERSION_CODE < KERNEL_VERSION(4, 17, 0))
        {
                pr_notice("%s: unsupported kernel version", MODNAME);
                return -1;
        };

        syscall_table_finder();
        if (sys_call_table_address == 0x0)
        {
                pr_notice("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
                return -1;
        }

        ret = strlen(the_password);
        if (ret <= 0)
        {
                pr_notice("%s: invalid password length.\n", MODNAME);
                return ret;
        }

        ret = hash_password(the_password, strlen(the_password), digest_password);
        if (ret)
        {
                pr_err("%s: failed to hash password: %d\n", MODNAME, ret);
                return ret;
        }

        AUDIT
        {
                pr_info("%s: reference_monitor received sys_call_table address %px\n", MODNAME, (void *)sys_call_table_address);
                pr_info("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
        }

        new_sys_call_array[0] = (unsigned long)sys_change_state;
        new_sys_call_array[1] = (unsigned long)sys_edit_paths;
        new_sys_call_array[2] = (unsigned long)sys_change_password;

        ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)sys_call_table_address, &the_ni_syscall);

        if (ret != HACKED_ENTRIES)
        {
                pr_err("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
                return -1;
        }

        unprotect_memory();

        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)sys_call_table_address)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        AUDIT
        {
                pr_notice("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);
                pr_notice("%s: %s is at table entry %d\n", MODNAME, "_change_state", restore[0]);
                pr_notice("%s: %s is at table entry %d\n", MODNAME, "_edit_paths", restore[1]);
                pr_notice("%s: %s is at table entry %d\n", MODNAME, "_change_password", restore[2]);
        }

        // register filesystem
        ret = register_filesystem(&logfilefs_type);
        if (likely(ret == 0))
        {
                pr_info("%s: sucessfully registered logfilefs\n", MODNAME);
        }
        else
        {
                pr_err("%s: failed to register logfilefs - error %d", MODNAME, ret);
                return -1;
        }

        // spinlock init
        spin_lock_init(&fs_spinlock);

        // workqueue init
        log_queue = create_singlethread_workqueue("log_queue");

        ret = register_wrappers();
        if (likely(ret == 0))
        {
                pr_info("%s: sucessfully registered wrappers\n", MODNAME);
        }
        else
        {
                pr_err("%s: failed to register wrappers - error %d", MODNAME, ret);
                return -1;
        }

        return ret;
}

void cleanup_module(void)
{
        int i, ret;

        pr_info("%s: shutting down\n", MODNAME);

        cleanup_list();
        pr_info("%s: cleaning path list\n", MODNAME);

        // unregister filesystem
        ret = unregister_filesystem(&logfilefs_type);
        if (likely(ret == 0))
                pr_info("%s: sucessfully unregistered logfilefs driver\n", MODNAME);
        else
                pr_err("%s: failed to unregister logfilefs driver - error %d", MODNAME, ret);

        destroy_workqueue(log_queue);

        unregister_wrappers();
        pr_info("%s: unregistered wrappers\n", MODNAME);

        unprotect_memory();
        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)sys_call_table_address)[restore[i]] = the_ni_syscall;
        }
        protect_memory();
        pr_info("%s: sys-call table restored to its original content\n", MODNAME);
}
