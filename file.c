#include "logfilefs.h"
#include "reference_monitor.h"

ssize_t logfilefs_read(struct file *filp, char __user *buf, size_t len, loff_t *off)
{
    struct buffer_head *bh = NULL;
    struct inode *the_inode = filp->f_inode;
    uint64_t file_size = the_inode->i_size;
    int ret;
    loff_t offset;
    int block_to_read; // index of the block to be read from device

    pr_info("%s: read operation called with len %ld - and offset %lld (the current file size is %lld)", MODNAME, len, *off, file_size);

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

    pr_info("%s: read operation must access block %d of the device", MODNAME, block_to_read);

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

struct dentry *logfilefs_lookup(struct inode *parent_inode, struct dentry *child_dentry, unsigned int flags)
{
    logfilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    pr_info("%s: running the lookup inode-function for name %s", MODNAME, child_dentry->d_name.name);

    if (!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME))
    {
        // get a locked inode from the cache
        the_inode = iget_locked(sb, LOGFILEFS_FILE_INODE_NUMBER);
        if (!the_inode)
            return ERR_PTR(-ENOMEM);

        // already cached inode - simply return successfully
        if (!(the_inode->i_state & I_NEW))
        {
            if (hlist_empty(&the_inode->i_dentry)){
                d_add(child_dentry, the_inode);
                dget(child_dentry);
            }
            inode_unlock(the_inode);
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
        FS_specific_inode = (logfilefs_inode *)bh->b_data;
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
};
