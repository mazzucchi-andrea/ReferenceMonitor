#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <limits.h>
#include <pthread.h>

#define NUM_THREADS 1000

int failed = 0;

int dirfd;

char *parent_dir_path = "./parent_dir";

// test file
char *test_file_relative_path = "./parent_dir/test.txt";
char *test_file_absolute_path;
char *test_file_relative_path_rename = "./parent_dir/test_rename.txt";
char *test_file_name = "test.txt";

// test dir
char *test_dir_relative_path = "./parent_dir/test_dir";
char *test_dir_absolute_path;
char *test_dir_relative_path_rename = "./parent_dir/test_rename_dir";
char *test_dir_name = "test_dir";

// test mkdir
char *mkdir_relative_path = "./parent_dir/mkdir_test";
char *mkdir_name = "mkdir_test";

char *test_creat_relative_path = "./parent_dir/test_creat.txt";

// unlink

void *unlink_test_file_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlink, test_file_relative_path))
    {
        printf("Test unlink test_file_relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *unlink_test_file_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlink, test_file_absolute_path))
    {
        printf("Test unlink test_file_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// unlinkat

void *unlinkat_AT_FDCWD_test_file_absolute_path_0(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlinkat, AT_FDCWD, test_file_absolute_path, 0))
    {
        printf("Test unlinkat AT_FDCWD test_file_absolute_path 0 failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *unlinkat_AT_FDCWD_test_dir_absolute_path_AT_REMOVEDIR(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlinkat, AT_FDCWD, test_dir_absolute_path, AT_REMOVEDIR))
    {
        printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *unlinkat_dirfd_test_filename_0(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlinkat, dirfd, test_file_name, 0))
    {
        printf("Test unlinkat dirfd test_filename 0 failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *unlinkat_dirfd_test_dir_name_AT_REMOVEDIR(void *arg)
{
    arg = arg;
    if (!syscall(SYS_unlinkat, dirfd, test_dir_name, AT_REMOVEDIR))
    {
        printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// rename

void *rename_test_file_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rename, test_file_absolute_path, test_file_relative_path_rename))
    {
        printf("Test rename test_file_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *rename_test_file_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rename, test_file_relative_path, test_file_relative_path_rename))
    {
        printf("Test rename test_file_relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *rename_test_dir_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rename, test_dir_absolute_path, test_dir_relative_path_rename))
    {
        printf("Test rename test_dir_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *rename_test_dir_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rename, test_dir_relative_path, test_dir_relative_path_rename))
    {
        printf("Test rename test_dir_relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// renameat

void *renameat_AT_FDCWD_test_file_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat, AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_relative_path_rename))
    {
        printf("Test renameat AT_FDCWD test_file_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat_AT_FDCWD_test_dir_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat, AT_FDCWD, test_dir_relative_path, AT_FDCWD, test_dir_relative_path_rename))
    {
        printf("Test renameat AT_FDCWD test_dir_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat_dirfd_test_filename(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat, dirfd, test_file_name, AT_FDCWD, test_file_relative_path_rename))
    {
        printf("Test renameat dirfd test_filename failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat_dirfd_test_dir_name(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat, dirfd, test_dir_name, AT_FDCWD, test_dir_relative_path_rename))
    {
        printf("Test renameat dirfd test_dir_name failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// renameat2

void *renameat2_AT_FDCWD_test_file_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat2, AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_relative_path_rename, 0))
    {
        printf("Test renameat2 AT_FDCWD test_file_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat2_AT_FDCWD_test_dir_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat2, AT_FDCWD, test_dir_relative_path, AT_FDCWD, test_dir_relative_path_rename, 0))
    {
        printf("Test renameat2 AT_FDCWD test_dir_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat2_dirfd_test_filename(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat2, dirfd, test_file_name, AT_FDCWD, test_file_relative_path_rename, 0))
    {
        printf("Test renameat2 dirfd test_filename failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *renameat2_dirfd_test_dir_name(void *arg)
{
    arg = arg;
    if (!syscall(SYS_renameat2, dirfd, test_dir_name, AT_FDCWD, test_dir_relative_path_rename, 0))
    {
        printf("Test renameat2 dirfd test_dir_name failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// rmdir

void *rmdir_test_dir_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rmdir, test_dir_relative_path))
    {
        printf("Test rmdir test_dir_relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *rmdir_test_dir_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_rmdir, test_dir_absolute_path))
    {
        printf("Test rmdir test_dir_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// creat

void *creat_test_creat_relative_path_0777(void *arg)
{
    arg = arg;
    if (syscall(SYS_creat, test_creat_relative_path, 0777) > 0)
    {
        printf("Test creat test_creat_relative_path 0777 failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *open_test_creat_relative_path_O_RDONLY_O_CREAT(void *arg)
{
    arg = arg;
    if (syscall(SYS_open, test_creat_relative_path, O_RDONLY | O_CREAT, 0777) > 0)
    {
        printf("Test open test_creat_relative_path O_RDONLY | O_CREAT failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// mkdir

void *mkdir_test_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdir, mkdir_relative_path, 0777))
    {
        printf("Test mkdir relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// mkdirat

void *mkdirat_dirfd_mkdir_name(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdirat, dirfd, test_dir_name, 0777))
    {
        printf("Test mkdirat dirfd mkdir_name failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// open

void *open_test_file_absolute_path_O_WRONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_open, test_file_absolute_path, O_WRONLY) < 0)
    {
        printf("Test open test_file_absolute_path O_WRONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *open_test_file_relative_path_O_WRONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_open, test_file_relative_path, O_WRONLY) < 0)
    {
        printf("Test open test_file_relative_path O_WRONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *open_test_file_absolute_path_O_RDONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_open, test_file_absolute_path, O_RDONLY) < 0)
    {
        printf("Test open test_file_absolute_path O_RDONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *open_test_file_relative_path_O_RDONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_open, test_file_relative_path, O_RDONLY) < 0)
    {
        printf("Test open test_file_relative_path O_RDONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// openat

void *openat_vscode(void *arg)
{
    arg = arg;
    if (openat(AT_FDCWD, test_file_absolute_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666) < 0)
    {
        printf("Test openat vscode failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_AT_FDCWD_test_file_absolute_path_O_WRONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, AT_FDCWD, test_file_absolute_path, O_WRONLY) < 0)
    {
        printf("Test openat AT_FDCWD test_file_absolute_path O_WRONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_AT_FDCWD_test_file_relative_path_O_WRONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, AT_FDCWD, test_file_relative_path, O_WRONLY) < 0)
    {
        printf("Test openat AT_FDCWD test_file_relative_path O_WRONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_dirfd_test_file_name_O_WRONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, dirfd, test_file_name, O_WRONLY) < 0)
    {
        printf("Test openat dirfd test_file_name O_WRONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_dirfd_test_file_name_O_RDONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, dirfd, test_file_name, O_RDONLY) < 0)
    {
        printf("Test openat dirfd test_file_name O_RDONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_AT_FDCWD_test_dir_absolute_path_O_RDONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, AT_FDCWD, test_dir_absolute_path, O_RDONLY) < 0)
    {
        printf("Test openat AT_FDCWD test_dir_absolute_path O_RDONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *openat_dirfd_test_dir_name_O_RDONLY(void *arg)
{
    arg = arg;
    if (syscall(SYS_openat, dirfd, test_dir_name, O_RDONLY) < 0)
    {
        printf("Test openat dirfd test_dir_name O_RDONLY failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// mkdir

void *mkdir_test_dir_relative_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdir, test_dir_relative_path))
    {
        printf("Test mkdir test_dir_relative_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *mkdir_test_dir_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdir, test_dir_absolute_path))
    {
        printf("Test mkdir test_dir_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

// mkdirat

void *mkdirat_AT_FDCWD_test_dir_absolute_path(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdirat, AT_FDCWD, test_dir_absolute_path))
    {
        printf("Test mkdirat AT_FDCWD test_dir_absolute_path failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *mkdirat_dirfd_test_dir_name(void *arg)
{
    arg = arg;
    if (!syscall(SYS_mkdirat, dirfd, test_dir_name))
    {
        printf("Test mkdirat dirfd test_dir_name failed\n");
        __sync_fetch_and_add(&failed, 1);
    }
    return NULL;
}

void *(*test_functions[])(void *arg) = {
    unlink_test_file_relative_path,
    unlink_test_file_absolute_path,
    unlinkat_AT_FDCWD_test_file_absolute_path_0,
    unlinkat_AT_FDCWD_test_dir_absolute_path_AT_REMOVEDIR,
    unlinkat_dirfd_test_filename_0,
    unlinkat_dirfd_test_dir_name_AT_REMOVEDIR,
    rename_test_file_absolute_path,
    rename_test_file_relative_path,
    rename_test_dir_absolute_path,
    rename_test_dir_relative_path,
    renameat_AT_FDCWD_test_file_absolute_path,
    renameat_AT_FDCWD_test_dir_path,
    renameat_dirfd_test_filename,
    renameat_dirfd_test_dir_name,
    renameat2_AT_FDCWD_test_file_absolute_path,
    renameat2_AT_FDCWD_test_dir_path,
    renameat2_dirfd_test_filename,
    renameat2_dirfd_test_dir_name,
    rmdir_test_dir_relative_path,
    rmdir_test_dir_absolute_path,
    creat_test_creat_relative_path_0777,
    open_test_creat_relative_path_O_RDONLY_O_CREAT,
    mkdir_test_relative_path,
    mkdirat_dirfd_mkdir_name,
    open_test_file_absolute_path_O_WRONLY,
    open_test_file_relative_path_O_WRONLY,
    open_test_file_absolute_path_O_RDONLY,
    open_test_file_relative_path_O_RDONLY,
    openat_vscode,
    openat_AT_FDCWD_test_file_absolute_path_O_WRONLY,
    openat_AT_FDCWD_test_file_relative_path_O_WRONLY,
    openat_dirfd_test_file_name_O_WRONLY,
    openat_dirfd_test_file_name_O_RDONLY,
    openat_AT_FDCWD_test_dir_absolute_path_O_RDONLY,
    openat_dirfd_test_dir_name_O_RDONLY,
    mkdir_test_dir_relative_path,
    mkdir_test_dir_absolute_path,
    mkdirat_AT_FDCWD_test_dir_absolute_path,
    mkdirat_dirfd_test_dir_name};


int main(void)
{
    test_file_absolute_path = malloc(PATH_MAX);
    if (!test_file_absolute_path)
    {
        perror("Failed memory allocation for test_file_absolute_path");
        exit(EXIT_FAILURE);
    }
    if (!realpath(test_file_relative_path, test_file_absolute_path))
    {
        perror("Failed relative path resolution");
        exit(EXIT_FAILURE);
    }
    printf("test_file_absolute_path %s\n", test_file_absolute_path);

    test_dir_absolute_path = malloc(PATH_MAX);
    if (!test_dir_absolute_path)
    {
        perror("Failed memory allocation for test_file_absolute_path");
        exit(EXIT_FAILURE);
    }
    if (!realpath(test_dir_relative_path, test_dir_absolute_path))
    {
        perror("Failed relative path resolution");
        exit(EXIT_FAILURE);
    }
    printf("test_dir_absolute_path %s\n", test_dir_absolute_path);

    dirfd = open(parent_dir_path, O_RDONLY);
    if (dirfd < 0)
    {
        perror("Failing open parent_dir_path");
        return dirfd;
    }

    pthread_t threads[NUM_THREADS];

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        if (pthread_create(&threads[i], NULL, test_functions[i % 33], NULL) != 0)
        {
            perror("Failed to create thread");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_THREADS; ++i)
    {
        if (pthread_join(threads[i], NULL) != 0)
        {
            perror("Failed to join thread");
            exit(EXIT_FAILURE);
        }
    }

    free(test_file_absolute_path);
    free(test_dir_absolute_path);

    printf("Tests failed: %d\n", failed);

    return 0;
}