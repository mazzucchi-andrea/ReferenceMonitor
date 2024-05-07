#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/openat2.h>

char *parent_dir_path = "/home/zyler/ReferenceMonitor/user/parent_dir";

// test file
char *test_file_relative_path = "./parent_dir/test.txt";
char *test_file_absolute_path = "/home/zyler/ReferenceMonitor/user/parent_dir/test.txt";
char *test_file_relative_path_rename = "./parent_dir/test_rename.txt";
char *test_file_absolute_path_rename = "/home/zyler/ReferenceMonitor/user/parent_dir/test_rename.txt";
char *test_file_name = "test.txt";

// test dir
char *test_dir_relative_path = "./parent_dir/test_dir";
char *test_dir_absolute_path = "/home/zyler/ReferenceMonitor/user/parent_dir/test_dir";
char *test_dir_relative_path_rename = "./parent_dir/test_rename_dir";
char *test_dir_absolute_path_rename = "/home/zyler/ReferenceMonitor/user/parent_dir/test_rename_dir";
char *test_dir_name = "test_dir";

int main(void)
{
    int dirfd, ret;

    dirfd = open(parent_dir_path, O_RDONLY);
    if (dirfd < 0)
    {
        printf("Failing open parent_dir_path %d\n", dirfd);
        return dirfd;
    }

    // unlink

    // unlink test_file_relative_path
    ret = unlink(test_file_relative_path);
    if (!ret)
    {
        perror("Test unlink test_file_relative_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_relative_path passed: ret %d, errno %d\n", ret, errno);

    // unlink test_file_absolute_path
    ret = unlink(test_file_absolute_path);
    if (!ret)
    {
        perror("Test unlink test_file_absolute_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // unlinkat

    // unlinkat AT_FDCWD test_file_absolute_path 0
    if (!unlinkat(AT_FDCWD, test_file_absolute_path, 0))
    {
        perror("Test unlinkat AT_FDCWD test_file_absolute_path 0 failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_absolute_path 0 passed\n");

    // unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR
    if (!unlinkat(AT_FDCWD, test_dir_absolute_path, AT_REMOVEDIR))
    {
        perror("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR passed\n");

    // unlinkat dirfd test_filename 0
    if (!unlinkat(dirfd, test_file_name, 0))
    {
        perror("Test unlinkat dirfd test_filename 0 failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_filename 0 passed\n");

    // unlinkat dirfd test_dir_name AT_REMOVEDIR
    if (!unlinkat(dirfd, test_dir_name, AT_REMOVEDIR))
    {
        perror("Test unlinkat dirfd test_dir_name AT_REMOVEDIR failed");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR passed\n");

    // rename

    // rename test_file_absolute_path
    if (!rename(test_file_absolute_path, test_file_absolute_path_rename))
    {
        perror("Test rename test_file_absolute_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_absolute_path passed\n");

    // rename test_file_relative_path
    if (!rename(test_file_relative_path, test_file_relative_path_rename))
    {
        perror("Test rename test_file_relative_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_relative_path passed\n");

    // rename test_dir_absolute_path
    if (!rename(test_dir_absolute_path, test_dir_absolute_path_rename))
    {
        perror("Test rename test_dir_absolute_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_absolute_path passed\n");

    // rename test_dir_relative_path
    if (!rename(test_dir_relative_path, test_dir_relative_path_rename))
    {
        perror("Test rename test_dir_relative_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_relative_path passed\n");

    // renemeat

    // renameat AT_FDCWD test_file_absolute_path
    ret = renameat(AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_absolute_path_rename);
    if (!ret)
    {
        perror("Test renameat AT_FDCWD test_file_absolute_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_file_absolute_path passed\n");

    // renameat AT_FDCWD test_dir_path
    ret = renameat(AT_FDCWD, test_dir_relative_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename");
    if (!ret)
    {
        perror("Test renameat AT_FDCWD test_dir_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_dir_path passed\n");

    // renameat dirfd test_filename
    ret = renameat(dirfd, test_file_name, AT_FDCWD, test_file_absolute_path_rename);
    if (!ret)
    {
        perror("Test renameat dirfd test_filename failed");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_filename passed\n");

    // renameat dirfd test_dir_name
    ret = renameat(dirfd, test_dir_name, AT_FDCWD, test_dir_absolute_path_rename);
    if (!ret)
    {
        perror("Test renameat dirfd test_dir_name failed");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_dir_name passed\n");

    // rmdir

    // rmdir test_dir_relative_path
    ret = rmdir(test_dir_relative_path);
    if (!ret)
    {
        perror("Test rmdir test_dir_relative_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_relative_path passed\n");

    // rmdir test_dir_absolute_path
    ret = rmdir(test_dir_absolute_path);
    if (!ret)
    {
        perror("Test rmdir test_dir_absolute_path failed");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_absolute_path passed\n");
    
    return 0;
}