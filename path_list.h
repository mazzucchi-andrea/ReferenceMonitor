#ifndef PATH_H
#define PATH_H

struct path_entry;

int add_path(const struct path *);
int remove_path(const struct path *);
int check_path(const struct path *);
int check_path_or_parent_dir(const struct path *);
void print_paths(void);
void refresh_list(void);
void cleanup_list(void);

#endif