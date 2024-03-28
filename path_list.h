#ifndef PATH_H
#define PATH_H

struct path_entry;

int add_path(const char *);
int remove_path(const char *);
int check_path(char *);
void print_paths(void);
void cleanup_list(void);

#endif