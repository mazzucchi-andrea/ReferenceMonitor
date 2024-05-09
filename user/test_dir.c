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

// test mkdir
char *mkdir_absolute_path = "/home/zyler/ReferenceMonitor/user/parent_dir/mkdir_test";
char *mkdir_relative_path = "./parent_dir/mkdir_test";
char *mkdir_name = "mkdir_test";

int main(void)
{
    int dirfd, ret;
    // struct open_how how_read, how_write;
    // how_read.flags = O_RDONLY;
    // how_write.flags = O_WRONLY;

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
        printf("Test unlink test_file_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_relative_path passed: ret %d, errno %d\n", ret, errno);

    // unlink test_file_absolute_path
    ret = unlink(test_file_absolute_path);
    if (!ret)
    {
        printf("Test unlink test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlink test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // unlinkat

    // unlinkat AT_FDCWD test_file_absolute_path 0
    if (!unlinkat(AT_FDCWD, test_file_absolute_path, 0))
    {
        printf("Test unlinkat AT_FDCWD test_file_absolute_path 0 failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_absolute_path 0 passed: ret %d, errno %d\n", ret, errno);

    // unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR
    if (!unlinkat(AT_FDCWD, test_dir_absolute_path, AT_REMOVEDIR))
    {
        printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat AT_FDCWD test_dir_absolute_path AT_REMOVEDIR passed: ret %d, errno %d\n", ret, errno);

    // unlinkat dirfd test_filename 0
    if (!unlinkat(dirfd, test_file_name, 0))
    {
        printf("Test unlinkat dirfd test_filename 0 failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_filename 0 passed: ret %d, errno %d\n", ret, errno);

    // unlinkat dirfd test_dir_name AT_REMOVEDIR
    if (!unlinkat(dirfd, test_dir_name, AT_REMOVEDIR))
    {
        printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test unlinkat dirfd test_dir_name AT_REMOVEDIR passed: ret %d, errno %d\n", ret, errno);

    // rename

    // rename test_file_absolute_path
    if (!rename(test_file_absolute_path, test_file_absolute_path_rename))
    {
        printf("Test rename test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_file_relative_path
    if (!rename(test_file_relative_path, test_file_relative_path_rename))
    {
        printf("Test rename test_file_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_file_relative_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_dir_absolute_path
    if (!rename(test_dir_absolute_path, test_dir_absolute_path_rename))
    {
        printf("Test rename test_dir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // rename test_dir_relative_path
    if (!rename(test_dir_relative_path, test_dir_relative_path_rename))
    {
        printf("Test rename test_dir_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rename test_dir_relative_path passed: ret %d, errno %d\n", ret, errno);

    // renemeat

    // renameat AT_FDCWD test_file_absolute_path
    ret = renameat(AT_FDCWD, test_file_absolute_path, AT_FDCWD, test_file_absolute_path_rename);
    if (!ret)
    {
        printf("Test renameat AT_FDCWD test_file_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_file_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // renameat AT_FDCWD test_dir_path
    ret = renameat(AT_FDCWD, test_dir_relative_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename");
    if (!ret)
    {
        printf("Test renameat AT_FDCWD test_dir_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat AT_FDCWD test_dir_path passed: ret %d, errno %d\n", ret, errno);

    // renameat dirfd test_filename
    ret = renameat(dirfd, test_file_name, AT_FDCWD, test_file_absolute_path_rename);
    if (!ret)
    {
        printf("Test renameat dirfd test_filename failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_filename passed: ret %d, errno %d\n", ret, errno);

    // renameat dirfd test_dir_name
    ret = renameat(dirfd, test_dir_name, AT_FDCWD, test_dir_absolute_path_rename);
    if (!ret)
    {
        printf("Test renameat dirfd test_dir_name failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test renameat dirfd test_dir_name passed: ret %d, errno %d\n", ret, errno);

    // rmdir

    // rmdir test_dir_relative_path
    ret = rmdir(test_dir_relative_path);
    if (!ret)
    {
        printf("Test rmdir test_dir_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_relative_path passed: ret %d, errno %d\n", ret, errno);

    // rmdir test_dir_absolute_path
    ret = rmdir(test_dir_absolute_path);
    if (!ret)
    {
        printf("Test rmdir test_dir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test rmdir test_dir_absolute_path passed: ret %d, errno %d\n", ret, errno);

    // open

    // open test_file_absolute_path O_WRONLY
    ret = syscall(SYS_open, test_file_absolute_path, O_WRONLY);
    if (ret < 0)
    {
        printf("Test open test_file_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_absolute_path O_WRONLY passed: ret %d\n", ret);
    close(ret);

    // open test_file_relative_path O_WRONLY
    ret = syscall(SYS_open, test_file_relative_path, O_WRONLY);
    if (ret < 0)
    {
        printf("Test open test_file_relative_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test open test_file_relative_path O_WRONLY passed: ret %d\n", ret);
    close(ret);

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
    ret = openat(AT_FDCWD, test_file_absolute_path, O_WRONLY);
    if (ret < 0)
    {
        printf("Test openat AT_FDCWD test_file_absolute_path O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_file_absolute_path O_WRONLY passed: ret %d\n", ret);
    close(ret);

    // openat dirfd test_file_name O_WRONLY
    ret = openat(dirfd, test_file_name, O_WRONLY);
    if (ret < 0)
    {
        printf("Test openat dirfd test_file_name O_WRONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_file_name O_WRONLY passed: ret %d\n", ret);
    close(ret);

    // openat AT_FDCWD test_file_absolute_path O_RDONLY
    ret = openat(AT_FDCWD, test_file_absolute_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat AT_FDCWD test_file_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_file_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat AT_FDCWD test_dir_absolute_path O_RDONLY
    ret = openat(AT_FDCWD, test_dir_absolute_path, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat AT_FDCWD test_dir_absolute_path O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat AT_FDCWD test_dir_absolute_path O_RDONLY passed\n");
    close(ret);

    // openat dirfd test_file_name O_RDONLY
    ret = openat(dirfd, test_file_name, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat dirfd test_file_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_file_name O_RDONLY passed\n");
    close(ret);

    // openat dirfd test_dir_name O_RDONLY
    ret = openat(dirfd, test_dir_name, O_RDONLY);
    if (ret < 0)
    {
        printf("Test openat dirfd test_dir_name O_RDONLY failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test openat dirfd test_dir_name O_RDONLY passed\n");
    close(ret);

    /*
        // openat2

        // openat2 AT_FDCWD test_file_absolute_path O_WRONLY
        ret = syscall(SYS_openat2, AT_FDCWD, test_file_absolute_path, &how_write, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 AT_FDCWD test_file_absolute_path O_WRONLY failed: ret %d, errno %d\n", ret, errno);
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 AT_FDCWD test_file_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);
        close(ret);

        // openat2 AT_FDCWD test_dir_absolute_path O_WRONLY
        ret = syscall(SYS_openat2, AT_FDCWD, test_dir_absolute_path, &how_write, sizeof(struct open_how));
        if (ret > 0)
        {
            printf("Test openat2 AT_FDCWD test_dir_absolute_path O_WRONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 AT_FDCWD test_dir_absolute_path O_WRONLY passed: ret %d, errno %d\n", ret, errno);
        close(ret);

        // openat2 dirfd test_file_name O_WRONLY
        ret = syscall(SYS_openat2, dirfd, test_file_name, &how_write, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 dirfd test_file_name O_WRONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 dirfd test_file_name O_WRONLY passed: ret %d, errno %d\n", ret, errno);
        close(ret);

        // openat2 dirfd test_dir_name O_WRONLY
        ret = syscall(SYS_openat2, dirfd, test_dir_name, &how_write, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 dirfd test_dir_name O_WRONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 dirfd test_dir_name O_WRONLY passed: ret %d, errno %d\n", ret, errno);
        close(ret);

        // openat2 AT_FDCWD test_file_absolute_path O_RDONLY
        ret = syscall(SYS_openat2, AT_FDCWD, test_file_absolute_path, &how_read, sizeof(struct open_how));
        if (ret < 0)
        {
            perror("Test openat2 AT_FDCWD test_file_absolute_path O_RDONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 AT_FDCWD test_file_absolute_path O_RDONLY passed: ret %d\n", ret);
        close(ret);

        // openat2 AT_FDCWD test_dir_absolute_path O_RDONLY
        ret = syscall(SYS_openat2, AT_FDCWD, test_dir_absolute_path, &how_read, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 AT_FDCWD test_dir_absolute_path O_RDONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 AT_FDCWD test_dir_absolute_path O_RDONLY passed: ret %d\n", ret);
        close(ret);

        // openat2 dirfd test_file_name O_RDONLY
        ret = syscall(SYS_openat2, dirfd, test_file_name, &how_read, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 dirfd test_file_name O_RDONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 dirfd test_file_name O_RDONLY passed: ret %d\n", ret);
        close(ret);

        // openat2 dirfd test_dir_name O_RDONLY
        ret = syscall(SYS_openat2, dirfd, test_dir_name, &how_read, sizeof(struct open_how));
        if (ret < 0)
        {
            printf("Test openat2 dirfd test_dir_name O_RDONLY failed\n");
            exit(EXIT_FAILURE);
        }
        printf("Test openat2 dirfd test_dir_name O_RDONLY passed: ret %d\n", ret);
        close(ret);
     */
    // mkdir

    // mkdir mkdir_absolute_path
    ret = mkdir(mkdir_absolute_path, 0777);
    if (!ret)
    {
        printf("Test mkdir mkdir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test mkdir mkdir_absolute_path passed\n");

    // mkdir mkdir_absolute_path
    ret = mkdir(mkdir_relative_path, 0777);
    if (!ret)
    {
        printf("Test mkdir mkdir_relative_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test mkdir mkdir_relative_path passed\n");

    // mkdirat

    // mkdirat AT_FDCWD mkdir_absolute_path
    ret = mkdirat(AT_FDCWD, mkdir_absolute_path, 0777);
    if (!ret)
    {
        printf("Test mkdirat AT_FDCWD mkdir_absolute_path failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test mkdirat AT_FDCWD mkdir_absolute_path passed\n");

    // mkdirat dirfd mkdir_name
    ret = mkdirat(dirfd, mkdir_name, 0777);
    if (!ret)
    {
        printf("Test mkdirat dirfd mkdir_name failed\n");
        exit(EXIT_FAILURE);
    }
    printf("Test mkdirat dirfd mkdir_name passed\n");

    return 0;
}