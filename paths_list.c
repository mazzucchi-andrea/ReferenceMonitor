#include <linux/list.h>
#include <linux/gfp.h>

#include "reference_monitor.h"

LIST_HEAD(paths);

struct path_entry
{
    struct list_head list;
    struct path *path;
};

bool is_parent_dir(const struct path *parent, const struct path *child)
{
    if (!parent || !child)
        return false;

    // Check if the inodes match
    if (parent->dentry->d_inode != child->dentry->d_parent->d_inode)
        return false;

    // Check if the parent dentry is the parent directory of the child dentry
    if (parent->dentry != child->dentry->d_parent)
        return false;

    // If both checks pass, the parent is the parent directory of the child
    return true;
}

int check_path(const struct path *path)
{
    struct path_entry *entry;

    list_for_each_entry(entry, &paths, list)
    {
        if (path_equal(entry->path, path))
            return 0;
    }
    return -1;
}

int check_parent_dir(const struct path *path)
{
    struct path_entry *entry;
   
    list_for_each_entry(entry, &paths, list)
    {
        if (is_parent_dir(entry->path, path))
            return 0;
    }
    return -1;
}

int check_path_or_parent_dir(const struct path *path)
{
    struct path_entry *entry;
   
    list_for_each_entry(entry, &paths, list)
    {
        if (path_equal(entry->path, path) || is_parent_dir(entry->path, path))
            return 0;
    }
    return -1;
}

int add_path(const struct path *new_path)
{
    struct path_entry *new_path_entry;

    if (check_path(new_path) == 0)
    {
        pr_notice("%s: path already present\n", MODNAME);
        return 0;
    }

    new_path_entry = (struct path_entry *)kmalloc(sizeof(struct path_entry), GFP_KERNEL);
    if (new_path_entry == NULL)
    {
        pr_err("%s: Memory allocation failed\n", MODNAME);
        return -1;
    }

    new_path_entry->path = (struct path *)kmalloc(sizeof(struct path), GFP_KERNEL);
    memcpy(new_path_entry->path, new_path, sizeof(struct path));

    INIT_LIST_HEAD(&new_path_entry->list);

    list_add_tail(&new_path_entry->list, &paths);
    return 0;
}

int remove_path(const struct path *path_to_remove)
{
    struct path_entry *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &paths, list)
    {
        if (path_equal(entry->path, path_to_remove))
        {
            list_del(&entry->list);
            path_put(entry->path);
            kfree(entry->path);
            kfree(entry);
            return 0;
        }
    }
    pr_notice("%s: Path not found in the list.\n", MODNAME);
    return -1;
}

void print_paths(void)
{
    struct path_entry *entry;
    char *buf, *pathname;

    buf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf)
        return;

    pr_info("%s: Paths:\n", MODNAME);

    // Iterate over each entry in the list
    list_for_each_entry(entry, &paths, list)
    {
        pathname = d_path(entry->path, buf, PATH_MAX);
        if (!IS_ERR(pathname))
            pr_info("%s: %s\n", MODNAME, pathname);
    }

    kfree(buf);
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
