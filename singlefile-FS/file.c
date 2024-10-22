#include <linux/buffer_head.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/uio.h>
#include <linux/version.h>

#include "singlefilefs.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
struct mnt_idmap {
    struct user_namespace *owner;
    refcount_t count;
};
#endif

struct mutex file_op_lock;

static ssize_t onefilefs_write_iter(struct kiocb *iocb, struct iov_iter *from) {
    struct buffer_head *bh = NULL;
    struct file *file = iocb->ki_filp;     // file
    struct inode *inode = file->f_inode;   // inode
    struct super_block *sb = inode->i_sb;  // Super block
    size_t len = from->kvec->iov_len;      // data to write lenght
    size_t free_bytes_in_block = len;      // Free space inside the chosen block

    loff_t block_offset;  // offset inside the chosen block
    int block_to_write;   // index to the block to be written
    size_t copiedBytes;

    loff_t file_size;

    mutex_lock(&file_op_lock);

    file_size = i_size_read(inode);

    // compute the actual index of the the block to be write from device
    block_to_write =
        file_size / DEFAULT_BLOCK_SIZE +
        2;  // the value 2 accounts for superblock and file-inode on device
    block_offset = file_size % DEFAULT_BLOCK_SIZE;

    // just write stuff in a single block - residuals will be managed at the
    // applicatin level
    if (block_offset + len > DEFAULT_BLOCK_SIZE)
        free_bytes_in_block = DEFAULT_BLOCK_SIZE - block_offset;

    bh = sb_bread(sb, block_to_write);
    if (!bh) {
        mutex_unlock(&file_op_lock);
        return -EIO;
    }

    // Copy data from iov_iter to the block buffer. Notice the change here from
    // copy_from_user.
    copiedBytes =
        copy_from_iter(bh->b_data + block_offset, free_bytes_in_block, from);
    if (copiedBytes != free_bytes_in_block) {
        mutex_unlock(&file_op_lock);
        brelse(bh);  // Release the buffer head.
        return -EFAULT;
    }

    mark_buffer_dirty(bh);  // Mark the buffer as dirty, so it will be written
                            // back to the disk
    sync_dirty_buffer(bh);
    brelse(bh);

    // Update file size in the inode
    i_size_write(inode, file_size + len);
    inode->i_size += copiedBytes;
    mark_inode_dirty(inode);  // Mark the inode as dirty, so it will be written
                              // back to the disk
    iocb->ki_pos += copiedBytes;  // Even if we're appending, it's good practice
                                  // to update ki_pos.

    mutex_unlock(&file_op_lock);

    return copiedBytes;
}

static ssize_t onefilefs_read(struct file *filp, char __user *buf, size_t len,
                              loff_t *off) {
    struct buffer_head *bh = NULL;
    struct inode *the_inode = filp->f_inode;
    uint64_t file_size;
    int ret;
    loff_t offset;
    int block_to_read;  // index of the block to be read from device

    file_size = i_size_read(the_inode);

    printk(
        "%s: read operation called with len %ld - and offset %lld (the current "
        "file size is %lld)",
        MOD_NAME, len, *off, file_size);

    // this operation is not synchronized
    //*off can be changed concurrently
    // add synchronization if you need it for any reason

    mutex_lock(&file_op_lock);

    // check that *off is within boundaries
    if (*off >= file_size) {
        mutex_unlock(&file_op_lock);
        return 0;
    } else if (*off + len > file_size)
        len = file_size - *off;

    // determine the block level offset for the operation
    offset = *off % DEFAULT_BLOCK_SIZE;
    // just read stuff in a single block - residuals will be managed at the
    // applicatin level
    if (offset + len > DEFAULT_BLOCK_SIZE) len = DEFAULT_BLOCK_SIZE - offset;

    // compute the actual index of the the block to be read from device
    block_to_read =
        *off / DEFAULT_BLOCK_SIZE +
        2;  // the value 2 accounts for superblock and file-inode on device

    printk("%s: read operation must access block %d of the device", MOD_NAME,
           block_to_read);

    bh = (struct buffer_head *)sb_bread(filp->f_path.dentry->d_inode->i_sb,
                                        block_to_read);
    if (!bh) {
        mutex_unlock(&file_op_lock);
        return -EIO;
    }
    ret = copy_to_user(buf, bh->b_data + offset, len);
    *off += (len - ret);
    brelse(bh);

    mutex_unlock(&file_op_lock);

    return len - ret;
}

static struct dentry *onefilefs_lookup(struct inode *parent_inode,
                                       struct dentry *child_dentry,
                                       unsigned int flags) {
    struct onefilefs_inode *FS_specific_inode;
    struct super_block *sb = parent_inode->i_sb;
    struct buffer_head *bh = NULL;
    struct inode *the_inode = NULL;

    printk("%s: running the lookup inode-function for name %s", MOD_NAME,
           child_dentry->d_name.name);

    if (!strcmp(child_dentry->d_name.name, UNIQUE_FILE_NAME)) {
        // get a locked inode from the cache
        the_inode = iget_locked(sb, 1);
        if (!the_inode) return ERR_PTR(-ENOMEM);

        // already cached inode - simply return successfully
        if (!(the_inode->i_state & I_NEW)) {
            return child_dentry;
        }

// this work is done if the inode was not already cached
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
        inode_init_owner(&nop_mnt_idmap, the_inode, NULL,
                         S_IFREG);  // set the root user as owner of the FS root
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        inode_init_owner(current->cred->user_ns, the_inode, NULL,
                         S_IFREG);  // set the root user as owner of the FS root
#else
        inode_init_owner(the_inode, NULL,
                         S_IFREG);  // set the root user as owner of the FS root
#endif
        the_inode->i_mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH | S_IWUSR |
                            S_IWGRP | S_IXUSR | S_IXGRP | S_IXOTH;
        the_inode->i_fop = &onefilefs_file_operations;
        the_inode->i_op = &onefilefs_inode_ops;

        // just one link for this file
        set_nlink(the_inode, 1);

        // now we retrieve the file size via the FS specific inode, putting it
        // into the generic inode
        bh = (struct buffer_head *)sb_bread(sb,
                                            SINGLEFILEFS_INODES_BLOCK_NUMBER);
        if (!bh) {
            iput(the_inode);
            return ERR_PTR(-EIO);
        }
        FS_specific_inode = (struct onefilefs_inode *)bh->b_data;
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

// static int onefilefs_open(struct inode *inode, struct file *file) {
//     // Opening the file with O_TRUNC flag can overwrite the log
//     if (file->f_flags & (O_TRUNC)) {
//         printk(
//             "%s: Attempt to open the single file with flags O_CREAT and/or "
//             "O_TRUNC. Open blocked. \n",
//             MOD_NAME);
//         return -EINVAL;
//     }

//     return 0;
// }

// look up goes in the inode operations
const struct inode_operations onefilefs_inode_ops = {
    .lookup = onefilefs_lookup,
};

const struct file_operations onefilefs_file_operations = {
    .owner = THIS_MODULE,
    .read = onefilefs_read,
    .write_iter = onefilefs_write_iter,  // Kernel uses write_iter
};
