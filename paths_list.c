#include <linux/list.h>
#include <linux/gfp.h>

#include "reference_monitor.h"

LIST_HEAD(paths);

struct path_entry
{
    struct list_head list;
    char *path;
};

int check_path(const char *path)
{
    struct path_entry *entry;
    list_for_each_entry(entry, &paths, list)
    {
        if (strcmp(entry->path, path) == 0)
            return 0;
    }
    return -1;
}

int check_path_and_dir(const char *path)
{
    struct path_entry *entry;
    list_for_each_entry(entry, &paths, list)
    {
        if (strcmp(entry->path, path) == 0 || strncmp(entry->path, path, strlen(entry->path)) == 0)
            return 0;
    }
    return -1;
}

int add_path(const char *new_path)
{
    struct path_entry *new_path_entry;

    if (check_path(new_path) == 0)
    {
        pr_notice("%s: path already present\n", MODNAME);
        return 0;
    }

    new_path_entry = kmalloc(sizeof(struct path_entry), GFP_KERNEL);
    if (new_path_entry == NULL)
    {
        pr_err("%s: Memory allocation failed\n", MODNAME);
        return -1;
    }

    new_path_entry->path = kmalloc(strlen(new_path), GFP_KERNEL);
    if (new_path_entry->path == NULL)
    {
        pr_err("%s: Memory allocation failed\n", MODNAME);
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
            pr_info("%s: Path '%s' removed.\n", MODNAME, path_to_remove);
            return 0;
        }
    }
    pr_notice("%s: Path '%s' not found in the list.\n", MODNAME, path_to_remove);
    return -1;
}

void print_paths(void)
{
    struct path_entry *entry;

    pr_info("%s: Paths:\n", MODNAME);

    // Iterate over each entry in the list
    list_for_each_entry(entry, &paths, list)
    {
        pr_info("%s: %s\n", MODNAME, entry->path);
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
