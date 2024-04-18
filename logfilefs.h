#ifndef _LOGFILEFS_H
#define _LOGFILEFS_H

#include <linux/types.h>
#include <linux/fs.h>

#define MAGIC 0x42424242
#define DEFAULT_BLOCK_SIZE 4096
#define SB_BLOCK_NUMBER 0
#define DEFAULT_FILE_INODE_BLOCK 1

#define FILENAME_MAXLEN 255

#define LOGFILEFS_ROOT_INODE_NUMBER 10
#define LOGFILEFS_FILE_INODE_NUMBER 1

#define LOGFILEFS_INODES_BLOCK_NUMBER 1

#define UNIQUE_FILE_NAME "the-log"

// inode definition
typedef struct _logfilefs_inode
{
	mode_t mode; // not exploited
	uint64_t inode_no;
	uint64_t data_block_number; // not exploited

	union
	{
		uint64_t file_size;
		uint64_t dir_children_count;
	};
} logfilefs_inode;

// dir definition (how the dir datablock is organized)
struct logfilefs_dir_record
{
	char filename[FILENAME_MAXLEN];
	uint64_t inode_no;
};

// superblock definition
struct logfilefs_sb_info
{
	uint64_t version;
	uint64_t magic;
	uint64_t block_size;
	uint64_t inodes_count; // not exploited
	uint64_t free_blocks;  // not exploited

	// padding to fit into a single block
	char padding[(4 * 1024) - (5 * sizeof(uint64_t))];
};

// file.c
extern const struct inode_operations logfilefs_inode_ops;
extern const struct file_operations logfilefs_file_operations;

// dir.c
extern const struct file_operations logfilefs_dir_operations;

#endif
