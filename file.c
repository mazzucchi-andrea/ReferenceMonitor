#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/timekeeping.h>
#include <linux/time.h>
#include <linux/buffer_head.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/minmax.h>

#include "logfilefs.h"
#include "reference_monitor.h"

int logfilefs_open(struct inode *inode, struct file *filp)
{
    loff_t file_size = inode->i_size;

    filp->f_pos = 0;

    printk("%s: open operation called (the current file size is %lld)", MODNAME, file_size);

    return 0;
}

ssize_t logfilefs_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{

    struct buffer_head *bh = NULL;
    struct inode *the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read; // index of the block to be read from device

    printk("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)", MODNAME, len, *off, file_size);

    // this operation is not synchronized
    //*off can be changed concurrently
    // add synchronization if you need it for any reason

    // check that *off is within boundaries
    if (*off >= file_size)
        return 0;
    else if (*off + len > file_size)
        len = file_size - *off;

    // determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE;
    // just read stuff in a single block - residuals will be managed at the applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE)
        len = DEFAULT_BLOCK_SIZE - offset;

    // compute the actual index of the the block to be read from device
    block_to_read = *off / DEFAULT_BLOCK_SIZE + 2; // the value 2 accounts for superblock and file-inode on device

    printk("%s: read operation must access block %d of the device", MODNAME, block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_read);
    if (!bh)
    {
        return -EIO;
    }
    ret = copy_to_user(buf, bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    return len - ret;
}

ssize_t logfilefs_write(struct file *filp, const char __user *buf, size_t len, loff_t *off)
{
    struct buffer_head *bh = NULL;
    struct inode *the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    loff_t maxbytes = the_inode->i_sb->s_maxbytes;
    ssize_t bytes_written = 0;
    loff_t offset = file_size; // with this offset every write is an append operation
    int block_to_write;

    printk("%s: write operation called with len %ld", MODNAME, len);

    if (file_size == maxbytes) 
        return -ENOSPC; // fs full

    if (file_size + len > maxbytes)
        len = maxbytes - file_size; // can't write all the bytes

    while (bytes_written < len)
    {
        int bytes_to_write = min(len - bytes_written, (size_t)(DEFAULT_BLOCK_SIZE - (offset % DEFAULT_BLOCK_SIZE)));
        block_to_write = offset / DEFAULT_BLOCK_SIZE + 2;

        bh = sb_bread(filp->f_path.dentry->d_inode->i_sb, block_to_write);
        if (!bh)
        {
            return -EIO;
        }

        // Copy data from user space buffer to block buffer
        if (copy_from_user(bh->b_data + (offset % DEFAULT_BLOCK_SIZE), buf + bytes_written, bytes_to_write))
        {
            brelse(bh);
            return -EFAULT;
        }

        mark_buffer_dirty(bh);
        brelse(bh);

        bytes_written += bytes_to_write;
        offset += bytes_to_write;
    }

    return bytes_written;
}

struct dentry *logfilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{

    struct logfilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s", MODNAME, child_dentry->d_name.name);

    if (!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME))
    {

        // get a locked inode from the cache
        the_inode = iget_locked(sb, 1);
        if (!the_inode)
            return ERR_PTR(-ENOMEM);

        // already cached inode - simply return successfully
        if (!(the_inode->i_state & I_NEW))
        {
            return child_dentry;
        }

        // this work is done if the inode was not already cached
        inode_init_owner(sb->s_user_ns, the_inode, NULL, S_IFREG);
        the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR | S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &logfilefs_file_operations;
        the_inode->i_op = &logfilefs_inode_ops;

        // just one link for this file
        set_nlink(the_inode, 1);

        // now we retrieve the file size via the FS specific inode, putting it into the generic inode
        bh = (struct buffer_head *)sb_bread(sb, LOGFILEFS_INODES_BLOCK_NUMBER);
        if (!bh)
        {
            iput(the_inode);
            return ERR_PTR(-EIO);
        }
        FS_specific_inode = (struct logfilefs_inode *)bh->b_data;
        the_inode->i_size = FS_specific_inode->file_size;
        brelse(bh);

        d_add(child_dentry, the_inode);
        dget(child_dentry);

        // unlock the inode to make it usable
        unlock_new_inode(the_inode);

        return child_dentry;
    }

    return NULL;
}

// look up goes in the inode operations
const struct inode_operations logfilefs_inode_ops = {
    .lookup = logfilefs_lookup,
};

const struct file_operations logfilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = logfilefs_read,
    .write = logfilefs_write};
