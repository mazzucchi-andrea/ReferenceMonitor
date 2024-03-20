#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
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

#include "lib/include/scth.h"
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _change_state, char *, password, int, state)
{
#else
asmlinkage long sys_change_state(char *password, int state)
{
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(3, _edit_path, char *, password, char *, path, int, mode)
{
#else
asmlinkage long sys_edit_path(char *password, char *path, int mode)
{
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _change_password, char *, old_password, char *, new_password)
{
#else
asmlinkage long sys_change_password(char *old_password, char *new_password)
{
#endif
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
long sys_change_state = (unsigned long)__x64_sys_change_state;
long sys_edit_path = (unsigned long)__x64_sys_edit_path;
long sys_change_password = (unsigned long)__x64_sys_change_password;
#else
#endif

// file system structure
static struct file_system_type logfilefs_type = {
    .owner = THIS_MODULE,
    .name = "logfilefs",
    .mount = logfilefs_mount,
    .kill_sb = logfilefs_kill_superblock,
};


int init_module(void)
{
        int i, ret;

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
                printk("%s: sucessfully registered singlefilefs\n", MODNAME);
        else
                printk("%s: failed to register singlefilefs - error %d", MODNAME, ret);

        return 0;
}

void cleanup_module(void)
{
        int i;

        printk("%s: shutting down\n", MODNAME);

        unprotect_memory();
        for (i = 0; i < HACKED_ENTRIES; i++)
        {
                ((unsigned long *)the_syscall_table)[restore[i]] = the_ni_syscall;
        }
        protect_memory();

        printk("%s: sys-call table restored to its original content\n", MODNAME);

        cleanup_list();
}
