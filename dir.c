#include "logfilefs.h"
#include "reference_monitor.h"

// this iterate function just returns 3 entries: . and .. and then the name of the unique file of the file system
static int logfilefs_iterate(struct file *file, struct dir_context *ctx)
{
	// printk("%s: we are inside readdir with ctx->pos set to %lld", MODNAME, ctx->pos);
	if (ctx->pos >= (2 + 1))
		return 0; // we cannot return more than . and .. and the unique file entry

	if (ctx->pos == 0)
	{
		// printk("%s: we are inside readdir with ctx->pos set to %lld", MODNAME, ctx->pos);
		if (!dir_emit(ctx, ".", FILENAME_MAXLEN, LOGFILEFS_ROOT_INODE_NUMBER, DT_UNKNOWN))
		{
			return 0;
		}
		else
		{
			ctx->pos++;
		}
	}

	if (ctx->pos == 1)
	{
		// printk("%s: we are inside readdir with ctx->pos set to %lld", MODNAME, ctx->pos);
		//  here the inode number does not care
		if (!dir_emit(ctx, "..", FILENAME_MAXLEN, 1, DT_UNKNOWN))
		{
			return 0;
		}
		else
		{
			ctx->pos++;
		}
	}
	if (ctx->pos == 2)
	{
		// printk("%s: we are inside readdir with ctx->pos set to %lld", MODNAME, ctx->pos);
		if (!dir_emit(ctx, UNIQUE_FILE_NAME, FILENAME_MAXLEN, LOGFILEFS_FILE_INODE_NUMBER, DT_UNKNOWN))
		{
			return 0;
		}
		else
		{
			ctx->pos++;
		}
	}

	return 0;
}

// add the iterate function in the dir operations
const struct file_operations logfilefs_dir_operations = {
	.owner = THIS_MODULE,
	.iterate = logfilefs_iterate,
};
