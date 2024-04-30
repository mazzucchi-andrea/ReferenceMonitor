#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/openat2.h>

char *saved_password = "the_password";
char *test_file_path = "./test.txt";
char *test_file_path_rename = "/home/zyler/ReferenceMonitor/user/parent_dir/test_rename.txt";
char *test_dir_path = "/home/zyler/ReferenceMonitor/user/parent_dir/test_dir";
char *test_dir_path_rename = "/home/zyler/ReferenceMonitor/user/parent_dir/test_rename_dir";
char *test_filename = "test.txt";
char *test_dir_name = "test_dir";
char *parent_dir_path = "/home/zyler/ReferenceMonitor/user/parent_dir";

int main(void)
{
    int dirfd, ret;
    //mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    struct open_how how;

    dirfd = open(parent_dir_path, O_RDONLY);
    if (dirfd < 0)
    {
        printf("Failing open parent_dir_path %d\n", dirfd);
        return dirfd;
    }

    printf("Test test_file_path test_dir_path\n");

    // unlink test_file_path
    if (unlink(test_file_path) == 0)
    {
        perror("Test unlink test_file_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_path passed\n");

    // unlinkat AT_FDCWD test_file_path 0
    if (unlinkat(AT_FDCWD, test_file_path, 0) == 0)
    {
        perror("Test unlinkat AT_FDCWD test_file_path 0 failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_file_path 0 passed\n");

    // unlinkat AT_FDCWD test_dir_path AT_REMOVEDIR
    if (unlinkat(AT_FDCWD, test_dir_path, AT_REMOVEDIR) == 0)
    {
        perror("Test unlinkat AT_FDCWD test_dir_path AT_REMOVEDIR failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_path AT_REMOVEDIR passed\n");

    // unlinkat dirfd test_filename 0
    if (unlinkat(dirfd, test_filename, 0) == 0)
{
        perror("Test unlinkat dirfd test_filename 0 failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_filename 0 passed\n");

    // unlinkat dirfd test_dir_name AT_REMOVEDIR
    if (unlinkat(dirfd, test_dir_name, AT_REMOVEDIR) == 0)
    {
        perror("Test unlinkat dirfd test_dir_name AT_REMOVEDIR failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR passed\n");

    // rename test_file_path
    if (rename(test_file_path, test_file_path_rename) == 0)
    {
        perror("Test rename test_file_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_path passed\n");

    // rename test_dir_path
    if (rename(test_dir_path, test_dir_path_rename) == 0)
    {
        perror("Test rename test_dir_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_path passed\n");

    // renameat AT_FDCWD test_file_path AT_FDCWD
    ret = renameat(AT_FDCWD, test_file_path, AT_FDCWD, "/home/zyler/parent_dir/test_rename.txt");
    printf("renameat AT_FDCWD test_file_path returns %d\n", ret);

    // renameat AT_FDCWD test_dir_path
    ret = renameat(AT_FDCWD, test_dir_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename");
    printf("renameat AT_FDCWD test_dir_path returns %d\n", ret);

    // renameat dirfd test_filename AT_FDCWD
    ret = renameat(dirfd, test_filename, AT_FDCWD, "/home/zyler/parent_dir/test_rename.txt");
    printf("renameat dirfd test_filename AT_FDCWD returns %d\n", ret);

    // renameat dirfd test_dir_path
    ret = renameat(dirfd, test_dir_name, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename");
    printf("renameat AT_FDCWD test_file_path returns %d\n", ret);

    // open test_file_path O_RDONLY
    ret = syscall(SYS_open, test_file_path, O_RDONLY);
    printf("open test_file_path O_RDONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // open test_file_path O_WRONLY
    ret = syscall(SYS_open, test_file_path, O_WRONLY);
    printf("open test_file_path O_WRONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat AT_FDCWD test_file_path O_RDONLY
    ret = openat(AT_FDCWD, test_file_path, O_RDONLY);
    printf("openat AT_FDCWD test_file_path O_RDONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat AT_FDCWD test_file_path O_WRONLY
    ret = openat(AT_FDCWD, test_file_path, O_WRONLY);
    printf("openat AT_FDCWD test_file_path O_WRONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat AT_FDCWD test_dir_path O_RDONLY
    ret = openat(AT_FDCWD, test_dir_path, O_RDONLY);
    printf("openat AT_FDCWD test_dir_path O_RDONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat AT_FDCWD test_dir_path O_WRONLY
    ret = openat(AT_FDCWD, test_dir_path, O_WRONLY);
    printf("openat AT_FDCWD test_dir_path O_WRONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat dirfd test_filename O_RDONLY
    ret = openat(dirfd, test_filename, O_RDONLY);
    printf("openat dirfd test_filename O_RDONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat dirfd test_filename O_WRONLY
    ret = openat(dirfd, test_filename, O_WRONLY);
    printf("openat dirfd test_filename O_WRONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat dirfd test_dir_name O_RDONLY
    ret = openat(dirfd, test_dir_name, O_RDONLY);
    printf("openat dirfd test_dir_name O_RDONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    // openat dirfd test_dir_name O_WRONLY
    ret = openat(dirfd, test_dir_name, O_WRONLY);
    printf("openat dirfd test_dir_name O_WRONLY returns %d\n", ret);
    if (ret > 0)
        close(ret);

    how.flags = O_RDONLY;

    ret = syscall(SYS_openat2, AT_FDCWD, test_file_path, how);
    printf("openat2 with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_openat2, dirfd, test_filename, how);
    printf("openat2 with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    how.flags = O_WRONLY;

    ret = syscall(SYS_openat2, AT_FDCWD, test_file_path, how);
    printf("openat2 with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_openat2, dirfd, test_filename, how);
    printf("openat2 with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = rmdir(test_dir_path);
    printf("rmdir test_dir_path returns %d\n", ret);

    return 0;
}