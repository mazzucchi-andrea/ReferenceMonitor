#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/cred.h>
#include <crypto/hash.h>
#include <linux/init.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/genhd.h>

#include "lib/include/scth.h"
#include "reference_monitor.h"
#include "hooks.h"
#include "logfilefs.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mazzucchi <mazzucchiandrea@gmail.com>");

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

#define SHA256_DIGEST_SIZE 256
#define PASSWORD_MAX_LEN 64
#define HASH_LEN SHA256_DIGEST_SIZE

u8 digest_password[SHA256_DIGEST_SIZE];
char *the_password;
module_param(the_password, charp, 0);

unsigned long the_ni_syscall;
unsigned long new_sys_call_array[] = {0x0, 0x0, 0x0};
#define HACKED_ENTRIES (int)(sizeof(new_sys_call_array) / sizeof(unsigned long))
int restore[HACKED_ENTRIES] = {[0 ...(HACKED_ENTRIES - 1)] - 1};

int hash_password(const char *password, size_t password_len, u8 *hash)
{
        struct crypto_shash *tfm;
        struct shash_desc *desc;
        int ret = -ENOMEM;
        unsigned char *digest;

        tfm = crypto_alloc_shash("sha256", 0, 0);
        if (IS_ERR(tfm))
        {
                printk("%s: Unable to allocate crypto hash\n", MODNAME);
                return PTR_ERR(tfm);
        }

        desc = kmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
        if (!desc)
                goto out_free_tfm;

        desc->tfm = tfm;

        digest = kmalloc(SHA256_DIGEST_SIZE, GFP_KERNEL);
        if (!digest)
                goto out_free_desc;

        ret = crypto_shash_digest(desc, password, password_len, digest);
        if (ret)
        {
                printk("%s: Error hashing password: %d\n", MODNAME, ret);
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

int check_password_length(char *password)
{
        if (strlen(password) > PASSWORD_MAX_LEN || strlen(password) <= 0)
                return -1;
        return 0;
}

int check_password(char *password)
{
        u8 digest[SHA256_DIGEST_SIZE];

        // check old_password length
        if (check_password_length(password) < 0)
        {
                return -1;
        }
        if (hash_password(password, strlen(password), digest) < 0)
        {
                return -1;
        }

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

#define AUDIT if (1)

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

int monitor_state = ON;

void print_current_monitor_state(void)
{
        switch (monitor_state)
        {
        case ON:
                printk("%s: current state is ON.\n", MODNAME);
                break;
        case OFF:
                printk("%s: current state is OFF.\n", MODNAME);
                break;
        case REC_ON:
                printk("%s: current state is REC_ON.\n", MODNAME);
                break;
        case REC_OFF:
                printk("%s: current state is REC_OFF.\n", MODNAME);
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

#define ADD 0
#define REMOVE 1

struct path_entry
{
        struct list_head list;
        char *path;
};

LIST_HEAD(paths);

int add_path(const char *new_path)
{
        struct path_entry *new_path_entry = kmalloc(sizeof(struct path_entry), GFP_KERNEL);
        if (new_path_entry == NULL)
        {
                printk("%s: Memory allocation failed\n", MODNAME);
                return -1;
        }

        new_path_entry->path = kmalloc(strlen(new_path), GFP_KERNEL);
        if (new_path_entry->path == NULL)
        {
                printk("%s: Memory allocation failed\n", MODNAME);
                kfree(new_path_entry->path);
                kfree(new_path_entry);
                return -1;
        }
        strcpy(new_path_entry->path, new_path);

        INIT_LIST_HEAD(&new_path_entry->list);

        list_add_tail(&new_path_entry->list, &paths);
        return 0;
}

int remove_path(const char *path_to_remove)
{
        struct path_entry *entry, *tmp;
        list_for_each_entry_safe(entry, tmp, &paths, list)
        {
                if (strcmp(entry->path, path_to_remove) == 0)
                {
                        list_del(&entry->list);
                        kfree(entry->path);
                        kfree(entry);
                        printk("%s: Path '%s' removed.\n", MODNAME, path_to_remove);
                        return 0;
                }
        }
        printk("%s: Path '%s' not found in the list.\n", MODNAME, path_to_remove);
        return -1;
}

int check_path(char *path)
{
        struct path_entry *entry;
        list_for_each_entry(entry, &paths, list)
        {
                if (strcmp(entry->path, path) == 0)
                        return -1;
        }
        printk("%s: Path '%s' not found in the list.\n", MODNAME, path);
        return 0;
}

void print_paths(void)
{
        struct path_entry *entry;

        printk("%s: Paths:\n", MODNAME);

        // Iterate over each entry in the list
        list_for_each_entry(entry, &paths, list)
        {
                printk("%s: %s\n", MODNAME, entry->path);
        }
}

void cleanup_list(void)
{
        struct path_entry *entry, *tmp;

        list_for_each_entry_safe(entry, tmp, &paths, list)
        {
                list_del(&entry->list);

                kfree(entry->path);

                kfree(entry);
        }
}

__SYSCALL_DEFINEx(2, _change_state, char *, password, int, state)
{
        printk("%s: _change_state called.\n", MODNAME);

        if (check_root() < 0)
        {
                printk("%s: only root can change the monitor state.\n", MODNAME);
                return -1;
        }

        if (check_password(password) < 0)
        {
                printk("%s: invalid password.\n", MODNAME);
                return -1;
        }

        print_current_monitor_state();

        if (state < 0 || state > 3)
        {
                printk("%s: invalid state %d.\n", MODNAME, state);
                return -1;
        }

        monitor_state = state;

        printk("%s: state changed.\n", MODNAME);

        print_current_monitor_state();

        return 0;
}

__SYSCALL_DEFINEx(3, _edit_path, char *, password, char *, path, int, mode)
{
        struct path path_struct;

        printk("%s: _edit_path called.\n", MODNAME);

        if (check_root() < 0)
        {
                printk("%s: only root can edit the monitor paths.\n", MODNAME);
                return -1;
        }

        if (check_password(password) < 0)
        {
                printk("%s: invalid password.\n", MODNAME);
                return -1;
        }

        if (check_rec_state() < 0)
        {
                printk("%s: invalid monitor state.\n", MODNAME);
                return -1;
        }

        if (kern_path(path, LOOKUP_FOLLOW, &path_struct) < 0)
        {
                printk("%s: Error resolving path.\n", MODNAME);
                return -1;
        }

        if (mode == ADD)
        {
                if (add_path(path) < 0)
                        return -1;
        }
        else if (mode == REMOVE)
        {
                if (remove_path(path) < 0)
                        return -1;
        }

        print_paths();

        return 0;
}

__SYSCALL_DEFINEx(2, _change_password, char *, old_password, char *, new_password)
{
        int ret;
        u8 new_digest[SHA256_DIGEST_SIZE];

        printk("%s: _change_password called.\n", MODNAME);

        if (check_root() < 0)
        {
                printk("%s: only root can change the monitor password.\n", MODNAME);
                return -1;
        }

        if (check_password(old_password) < 0)
        {
                printk("%s: invalid password.\n", MODNAME);
                return -1;
        }

        if (check_password_length(new_password) < 0)
        {
                printk("%s: invalid new password length.\n", MODNAME);
                return -1;
        }

        ret = hash_password(new_password, strlen(new_password), new_digest);
        if (ret < 0)
        {
                printk("%s: failing hashing new password.\n", MODNAME);
                return ret;
        }

        memcpy(digest_password, new_digest, HASH_LEN);

        printk("%s: password changed.\n", MODNAME);
        return 0;
}

long sys_change_state = (unsigned long)__x64_sys_change_state;
long sys_edit_path = (unsigned long)__x64_sys_edit_path;
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
                printk(KERN_ERR "%s: logfilefs super_block read failed.\n", MODNAME);
                return -EIO;
        }
        sb_disk = (struct logfilefs_sb_info *)bh->b_data;
        magic = sb_disk->magic;
        brelse(bh);

        // check on the expected magic number
        if (magic != sb->s_magic)
        {
                printk(KERN_ERR "%s: logfilefs wrong magic number.\n", MODNAME);
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
                printk(KERN_ERR "%s: logfilefs can not get root_inode.\n", MODNAME);
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
                printk(KERN_ERR "%s: logfilefs d_make_root failed.\n", MODNAME);
                return -ENOMEM;
        }

        sb->s_root->d_op = &logfilefs_dentry_ops; // set our dentry operations

        // sb->s_maxbytes = (loff_t)(get_capacity(sb->s_bdev->bd_disk) * DEFAULT_BLOCK_SIZE);

        // unlock the inode to make it usable
        unlock_new_inode(root_inode);

        return 0;
}

static void logfilefs_kill_superblock(struct super_block *s)
{
        kill_block_super(s);
        printk(KERN_INFO "%s: logfilefs unmount succesful.\n", MODNAME);
        return;
}

// called on file system mounting
struct dentry *logfilefs_mount(struct file_system_type *fs_type, int flags, const char *dev_name, void *data)
{
        struct dentry *ret;

        ret = mount_bdev(fs_type, flags, dev_name, data, logfilefs_fill_super);

        if (unlikely(IS_ERR(ret)))
                printk("%s: error mounting logfilefs", MODNAME);
        else
                printk("%s: logfilefs is succesfully mounted on from device %s\n", MODNAME, dev_name);

        return ret;
}

// file system structure
static struct file_system_type logfilefs_type = {
    .owner = THIS_MODULE,
    .name = "logfilefs",
    .mount = logfilefs_mount,
    .kill_sb = logfilefs_kill_superblock,
};

// kretprobes
// static struct kretprobe unlink_kretprobe;

int init_module(void)
{
        int i, ret;

        if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0))
        {
                printk("%s: unsupported kernel version", MODNAME);
                return -1;
        };

        if (the_syscall_table == 0x0)
        {
                printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
                return -1;
        }

        if (check_password_length(the_password) < 0)
        {
                printk("%s: invalid password length.\n", MODNAME);
                return ret;
        }

        ret = hash_password(the_password, strlen(the_password), digest_password);
        if (ret < 0)
        {
                printk("%s: failed to hash password: %d\n", MODNAME, ret);
                return ret;
        }
        else
        {
                printk("%s: password hashed successfully\n", MODNAME);
        }

        AUDIT
        {
                printk("%s: reference_monitor received sys_call_table address %px\n", MODNAME, (void *)the_syscall_table);
                printk("%s: initializing - hacked entries %d\n", MODNAME, HACKED_ENTRIES);
        }

        new_sys_call_array[0] = (unsigned long)sys_change_state;
        new_sys_call_array[1] = (unsigned long)sys_edit_path;
        new_sys_call_array[2] = (unsigned long)sys_change_password;

        ret = get_entries(restore, HACKED_ENTRIES, (unsigned long *)the_syscall_table, &the_ni_syscall);

        if (ret != HACKED_ENTRIES)
        {
                printk("%s: could not hack %d entries (just %d)\n", MODNAME, HACKED_ENTRIES, ret);
                return -1;
        }

        unprotect_memory();

        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)the_syscall_table)[restore[i]] = (unsigned long)new_sys_call_array[i];
        }

        protect_memory();

        printk("%s: all new system-calls correctly installed on sys-call table\n", MODNAME);

        // register filesystem
        ret = register_filesystem(&logfilefs_type);
        if (likely(ret == 0))
                printk("%s: sucessfully registered logfilefs\n", MODNAME);
        else
        {
                printk("%s: failed to register logfilefs - error %d", MODNAME, ret);
                return -1;
        }

        // register hooks
        /*         ret = register_hook(unlink_kretprobe, unlink, (kretprobe_handler_t)the_pre_unlink_hook);
                if (likely(ret == 0))
                        printk("%s: sucessfully registered unlink kretprobe\n", MODNAME);
                else
                {
                        printk("%s: failed to register unlink kretprobe - error %d\n", MODNAME, ret);
                        return -1;
                } */

        return 0;
}

void cleanup_module(void)
{
        int i, ret;

        printk("%s: shutting down\n", MODNAME);

        cleanup_list();

        // unregister filesystem
        ret = unregister_filesystem(&logfilefs_type);

        if (likely(ret == 0))
                pr_info("%s: sucessfully unregistered logfilefs driver\n", MODNAME);
        else
                pr_err("%s: failed to unregister logfilefs driver - error %d", MODNAME, ret);

        unprotect_memory();
        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();

        printk("%s: sys-call table restored to its original content\n", MODNAME);
}
