#define EXPORT_SYMTAB
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/crypto.h>
#include <linux/slab.h>
#include <crypto/hash.h>

#include "lib/include/scth.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mazzucchi <mazzucchiandrea@gmail.com>");

#define MODNAME "REFERENCE_MONITOR"

#define SHA256_DIGEST_SIZE 256
#define PASSWORD_MAX_LEN 64
#define HASH_LEN SHA256_DIGEST_SIZE

unsigned long the_syscall_table = 0x0;
module_param(the_syscall_table, ulong, 0660);

u8 digest_password[SHA256_DIGEST_SIZE];
char *password;
module_param(password, charp, 0);

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
                pr_err("Unable to allocate crypto hash\n");
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
                pr_err("Error hashing password: %d\n", ret);
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

#define AUDIT if (1)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(2, _change_state, char *, passwd, int, state)
{
#else
asmlinkage long sys_change_state(char *passwd, int state)
{
#endif
        printk("%s: _change_state called.\n", MODNAME);
        return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
__SYSCALL_DEFINEx(3, _edit_path, char *, passwd, char *, path, int, to_do)
{
#else
asmlinkage long sys_edit_path(char *passwd, char *path, int to_do)
{
#endif
        printk("%s: _edit_path called.\n", MODNAME);
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
        u8 old_digest[SHA256_DIGEST_SIZE];
        u8 new_digest[SHA256_DIGEST_SIZE];

        printk("%s: _change_password called.\n", MODNAME);

        // check old_password length
        if (strlen(old_password) > PASSWORD_MAX_LEN || strlen(old_password) <= 0)
        {
                printk("%s: invalid password.\n", MODNAME);
                return -1;
        }
        ret = hash_password(old_password, strlen(old_password), old_digest);
        if (ret < 0)
        {
                printk("%s: failing hashing old password.\n", MODNAME);
                return -1;
        }

        // check new_password length
        if (strlen(new_password) > PASSWORD_MAX_LEN || strlen(new_password) <= 0)
        {
                printk("%s: invalid new password length.\n", MODNAME);
                return -1;
        }
        ret = hash_password(new_password, strlen(new_password), new_digest);
        if (ret < 0)
        {
                printk("%s: failing hashing new password.\n", MODNAME);
                return -1;
        }

        if (memcmp(digest_password, old_digest, SHA256_DIGEST_SIZE) != 0)
        {
                printk("%s: invalid password.\n", MODNAME);
                return -1;
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

int init_module(void)
{

        int i;
        int ret;

        if (the_syscall_table == 0x0)
        {
                printk("%s: cannot manage sys_call_table address set to 0x0\n", MODNAME);
                return -1;
        }

        // check password length
        if (strlen(password) > PASSWORD_MAX_LEN || strlen(password) <= 0)
        {
                printk("%s: invalid password length.\n", MODNAME);
                return -1;
        }

        // hash password
        ret = hash_password(password, strlen(password), digest_password);
        if (ret)
        {
                printk("%s: failed to hash password: %d\n", MODNAME, ret);
                return -1;
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
}
