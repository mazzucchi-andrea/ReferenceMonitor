#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <limits.h>

int main(void)
{
    int dirfd, ret;

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

    struct open_how how_read, how_write;
    how_read.flags = O_RDONLY;
    how_write.flags = O_WRONLY;

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
        printf("Failing open parent_dir_path %d\n", dirfd);
        return dirfd;
    }

    // unlink

    // unlink test_file_relative_path
    ret = syscall(SYS_unlink, test_file_relative_path);
    if (!ret)
    {
        printf("Test unlink test_file_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_relative_path passed: ret %d, errno %d\n", ret, errno);

    // unlink test_file_absolute_path
    ret = syscall(SYS_unlink, test_file_absolute_path);
    if (!ret)
    {
        printf("Test unlink test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // unlinkat

    // unlinkat AT_FDCWD test_file_absolute_path 0
    ret = syscall(SYS_unlinkat, AT_FDCWD, test_file_absolute_path, 0);
    if (!ret)
    {
        printf("Test unlinkat AT_FDCWD test_file_absolute_path 0 failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_file_absolute_path 0 passed: ret %d, errno %d\n", ret, errno);

    // unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR
    ret = syscall(SYS_unlinkat, AT_FDCWD, test_dir_absolute_path, AT_REMOVEDIR);
    if (!ret)
    {
        printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR passed: ret %d, errno %d\n", ret, errno);

    // unlinkat dirfd test_filename 0
    ret = syscall(SYS_unlinkat, dirfd, test_file_name, 0);
    if (!ret)
    {
        printf("Test unlinkat dirfd test_filename 0 failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_filename 0 passed: ret %d, errno %d\n", ret, errno);

    // unlinkat dirfd test_dir_name AT_REMOVEDIR
    ret = syscall(SYS_unlinkat, dirfd, test_dir_name, AT_REMOVEDIR);
    if (!ret)
    {
        printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR passed: ret %d, errno %d\n", ret, errno);

    // rename

    // rename test_file_absolute_path
    ret = syscall(SYS_rename, test_file_absolute_path, test_file_relative_path_rename);
    if (!ret)
    {
        printf("Test rename test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_file_relative_path
    ret = syscall(SYS_rename, test_file_relative_path, test_file_relative_path_rename);
    if (!ret)
    {
        printf("Test rename test_file_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_relative_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_dir_absolute_path
    ret = syscall(SYS_rename, test_dir_absolute_path, test_dir_relative_path_rename);
    if (!ret)
    {
        printf("Test rename test_dir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_dir_relative_path
    ret = syscall(SYS_rename, test_dir_relative_path, test_dir_relative_path_rename);
    if (!ret)
    {
        printf("Test rename test_dir_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_relative_path passed: ret %d, errno %d\n", ret, errno);

    // renemeat

    // renameat AT_FDCWD test_file_absolute_path
    ret = syscall(SYS_renameat, AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_relative_path_rename);
    if (!ret)
    {
        printf("Test renameat AT_FDCWD test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // renameat AT_FDCWD test_dir_path
    ret = syscall(SYS_renameat, AT_FDCWD, test_dir_relative_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename");
    if (!ret)
    {
        printf("Test renameat AT_FDCWD test_dir_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_dir_path passed: ret %d, errno %d\n", ret, errno);

    // renameat dirfd test_filename
    ret = syscall(SYS_renameat, dirfd, test_file_name, AT_FDCWD, test_file_relative_path_rename);
    if (!ret)
    {
        printf("Test renameat dirfd test_filename failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_filename passed: ret %d, errno %d\n", ret, errno);

    // renameat dirfd test_dir_name
    ret = syscall(SYS_renameat, dirfd, test_dir_name, AT_FDCWD, test_dir_relative_path_rename);
    if (!ret)
    {
        printf("Test renameat dirfd test_dir_name failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_dir_name passed: ret %d, errno %d\n", ret, errno);

    // renemeat2

    // renemeat2 AT_FDCWD test_file_absolute_path
    ret = syscall(SYS_renameat2, AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_relative_path_rename, 0);
    if (!ret)
    {
        printf("Test renemeat2 AT_FDCWD test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renemeat2 AT_FDCWD test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // renemeat2 AT_FDCWD test_dir_path
    ret = syscall(SYS_renameat2, AT_FDCWD, test_dir_relative_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename", 0);
    if (!ret)
    {
        printf("Test renemeat2 AT_FDCWD test_dir_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renemeat2 AT_FDCWD test_dir_path passed: ret %d, errno %d\n", ret, errno);

    // renemeat2 dirfd test_filename
    ret = syscall(SYS_renameat2, dirfd, test_file_name, AT_FDCWD, test_file_relative_path_rename, 0);
    if (!ret)
    {
        printf("Test renemeat2 dirfd test_filename failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renemeat2 dirfd test_filename passed: ret %d, errno %d\n", ret, errno);

    // renameat2 dirfd test_dir_name
    ret = syscall(SYS_renameat2, dirfd, test_dir_name, AT_FDCWD, test_dir_relative_path_rename, 0);
    if (!ret)
    {
        printf("Test renameat2 dirfd test_dir_name failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat2 dirfd test_dir_name passed: ret %d, errno %d\n", ret, errno);

    // rmdir

    // rmdir test_dir_relative_path
    ret = syscall(SYS_rmdir, test_dir_relative_path);
    if (!ret)
    {
        printf("Test rmdir test_dir_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_relative_path passed: ret %d, errno %d\n", ret, errno);

    // rmdir test_dir_absolute_path
    ret = syscall(SYS_rmdir, test_dir_absolute_path);
    if (!ret)
    {
        printf("Test rmdir test_dir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // open

    // open test_file_absolute_path O_WRONLY
    ret = syscall(SYS_open, test_file_absolute_path, O_WRONLY);
    if (ret > 0)
    {
        printf("Test open test_file_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // open test_file_relative_path O_WRONLY
    ret = syscall(SYS_open, test_file_relative_path, O_WRONLY);
    if (ret > 0)
    {
        printf("Test open test_file_relative_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_relative_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // open test_file_absolute_path O_RDWR
    ret = syscall(SYS_open, test_file_absolute_path, O_RDWR);
    if (ret > 0)
    {
        printf("Test open test_file_absolute_path O_RDWR failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_absolute_path O_RDWR passed: ret %d, errno %d\n", ret, errno);

    // open test_file_absolute_path O_RDONLY
    ret = syscall(SYS_open, test_file_absolute_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test open test_file_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_absolute_path O_RDONLY passed\n");
    close(ret);

    // open test_file_relative_path O_RDONLY
    ret = syscall(SYS_open, test_file_relative_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test open test_file_relative_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_relative_path O_RDONLY passed\n");
    close(ret);

    // openat

    // openat AT_FDCWD test_file_absolute_path O_WRONLY
    ret = syscall(SYS_openat, AT_FDCWD, test_file_absolute_path, O_WRONLY);
    if (ret > 0)
    {
        printf("Test openat AT_FDCWD test_file_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_file_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat dirfd test_file_name O_WRONLY
    ret = syscall(SYS_openat, dirfd, test_file_name, O_WRONLY);
    if (ret > 0)
    {
        printf("Test openat dirfd test_file_name O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_file_name O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat AT_FDCWD test_file_absolute_path O_RDONLY
    ret = syscall(SYS_openat, AT_FDCWD, test_file_absolute_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat AT_FDCWD test_file_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_file_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat AT_FDCWD test_dir_absolute_path O_RDONLY
    ret = syscall(SYS_openat, AT_FDCWD, test_dir_absolute_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat AT_FDCWD test_dir_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_dir_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat dirfd test_file_name O_RDONLY
    ret = syscall(SYS_openat, dirfd, test_file_name, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat dirfd test_file_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_file_name O_RDONLY passed\n");
    close(ret);

    // openat dirfd test_dir_name O_RDONLY
    ret = syscall(SYS_openat, dirfd, test_dir_name, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat dirfd test_dir_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_dir_name O_RDONLY passed\n");
    close(ret);

    // openat2

    // openat2 AT_FDCWD test_file_absolute_path O_WRONLY
    ret = syscall(SYS_openat2, AT_FDCWD, test_file_absolute_path, &how_write, sizeof(how_write));
    if (ret > 0)
    {
        printf("Test openat2 AT_FDCWD test_file_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 AT_FDCWD test_file_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat2 AT_FDCWD test_dir_absolute_path O_WRONLY
    ret = syscall(SYS_openat2, AT_FDCWD, test_dir_absolute_path, &how_write, sizeof(how_write));
    if (ret > 0)
    {
        printf("Test openat2 AT_FDCWD test_dir_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 AT_FDCWD test_dir_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat2 dirfd test_file_name O_WRONLY
    ret = syscall(SYS_openat2, dirfd, test_file_name, &how_write, sizeof(how_write));
    if (ret > 0)
    {
        printf("Test openat2 dirfd test_file_name O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 dirfd test_file_name O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat2 dirfd test_dir_name O_WRONLY
    ret = syscall(SYS_openat2, dirfd, test_dir_name, &how_write, sizeof(how_write));
    if (ret > 0)
    {
        printf("Test openat2 dirfd test_dir_name O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 dirfd test_dir_name O_WRONLY passed: ret %d, errno %d\n", ret, errno);

    // openat2 AT_FDCWD test_file_absolute_path O_RDONLY
    ret = syscall(SYS_openat2, AT_FDCWD, test_file_absolute_path, &how_read, sizeof(how_read));
    if (ret < 0)
    {
        perror("Test openat2 AT_FDCWD test_file_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 AT_FDCWD test_file_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat2 AT_FDCWD test_dir_absolute_path O_RDONLY
    ret = syscall(SYS_openat2, AT_FDCWD, test_dir_absolute_path, &how_read, sizeof(how_read));
    if (ret < 0)
    {
        printf("Test openat2 AT_FDCWD test_dir_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 AT_FDCWD test_dir_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat2 dirfd test_file_name O_RDONLY
    ret = syscall(SYS_openat2, dirfd, test_file_name, &how_read, sizeof(how_read));
    if (ret < 0)
    {
        printf("Test openat2 dirfd test_file_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 dirfd test_file_name O_RDONLY passed\n");
    close(ret);

    // openat2 dirfd test_dir_name O_RDONLY
    ret = syscall(SYS_openat2, dirfd, test_dir_name, &how_read, sizeof(how_read));
    if (ret < 0)
    {
        printf("Test openat2 dirfd test_dir_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat2 dirfd test_dir_name O_RDONLY passed\n");
    close(ret);

    return 0;
}