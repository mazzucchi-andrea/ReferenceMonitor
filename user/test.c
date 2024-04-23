#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>       /* Definition of O_* and S_* constants */
#include <sys/syscall.h> /* Definition of SYS_* constants */
#include <linux/openat2.h>

char *saved_password = "the_password";
char *test_file_path = "/home/zyler/parent_dir/test.txt";
char *test_file_name = "test.txt";
char *parent_dir_path = "/home/zyler/parent_dir";
char *test_dir_name = "test_dir";
char *test_dir_path = "/home/zyler/parent_dir/test_dir";
char *test_creat_path = "/home/zyler/parent_dir/creat.txt";

int main(void)
{
    int ret, dirfd;
    mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    struct open_how how;

    dirfd = open(parent_dir_path, O_RDONLY);
    if (dirfd < 0)
    {
        printf("Failing open parent_dir_path %d\n", dirfd);
        return dirfd;
    }

    printf("Test Direct Path\n");

    ret = syscall(174, saved_password, test_file_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    ret = syscall(174, saved_password, test_dir_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    ret = unlink(test_file_path);
    printf("Unlink test_file_path return %d\n", ret);

    ret = unlink(test_dir_path);
    printf("Unlink test_dir_path return %d\n", ret);

    ret = unlinkat(AT_FDCWD, test_file_path, 0);
    printf("Unlinkat test_file_path return %d\n", ret);

    // test unlinkat remove dir AT_FDCWD
    ret = unlinkat(AT_FDCWD, test_dir_path, 0);
    printf("Unlinkat test_dir_path return %d\n", ret);

    // test unlinkat relative dir dir
    ret = unlinkat(dirfd, test_dir_name, AT_REMOVEDIR);
    printf("Unlinkat test_dir_name return %d\n", ret);

    // test unlinkat relative dir file
    ret = unlinkat(dirfd, test_file_name, 0);
    printf("Unlinkat test_dir_name return %d\n", ret);

    ret = syscall(SYS_open, test_file_path, O_RDONLY);
    printf("Open with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_open, test_file_path, O_WRONLY);
    printf("Open with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = rename(test_file_path, "/home/zyler/test_rename.txt");
    printf("Rename return %d\n", ret);

    ret = openat(AT_FDCWD, test_file_path, O_RDONLY);
    printf("openat O_RDONLY test_file_path return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(AT_FDCWD, test_file_path, O_WRONLY);
    printf("openat O_WRONLY test_file_path return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(AT_FDCWD, test_dir_path, O_RDONLY);
    printf("openat O_RDONLY test_dir_path return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(AT_FDCWD, test_dir_path, O_WRONLY);
    printf("openat O_WRONLY test_dir_path return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(dirfd, test_file_name, O_RDONLY);
    printf("openat O_RDONLY test_file_name return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(dirfd, test_file_name, O_WRONLY);
    printf("openat O_WRONLY test_file_name return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(dirfd, test_dir_name, O_RDONLY);
    printf("openat O_RDONLY test_dir_name return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = openat(dirfd, test_dir_name, O_WRONLY);
    printf("openat O_WRONLY test_dir_name return %d\n", ret);
    if (ret > 0)
        close(ret);

    how.flags = O_RDONLY;

    ret = syscall(SYS_openat2, AT_FDCWD, test_file_path, how);
    printf("openat2 with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_openat2, dirfd, test_file_name, how);
    printf("openat2 with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    how.flags = O_WRONLY;

    ret = syscall(SYS_openat2, AT_FDCWD, test_file_path, how);
    printf("openat2 with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_openat2, dirfd, test_file_name, how);
    printf("openat2 with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    // remove paths

    ret = syscall(174, saved_password, test_file_path, 1);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    ret = syscall(174, saved_password, test_dir_path, 1);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    // Test with parent dir protected

    printf("Test Parent Dir\n");

    ret = syscall(174, saved_password, parent_dir_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    ret = unlink(test_file_path);
    printf("Unlink test_file_path return %d\n", ret);

    ret = unlink(test_dir_path);
    printf("Unlink test_file_path return %d\n", ret);

    ret = unlinkat(AT_FDCWD, test_file_path, 0);
    printf("Unlinkat test_file_path return %d\n", ret);

    // test unlinkat remove dir AT_FDCWD
    ret = unlinkat(AT_FDCWD, test_dir_path, 0);
    printf("Unlinkat test_dir_path return %d\n", ret);

    // test unlinkat relative dir dir
    ret = unlinkat(dirfd, test_dir_name, AT_REMOVEDIR);
    printf("Unlinkat test_dir_name return %d\n", ret);

    // test unlinkat relative dir file
    ret = unlinkat(dirfd, test_file_name, 0);
    printf("Unlinkat test_dir_name return %d\n", ret);

    ret = syscall(SYS_open, test_file_path, O_RDONLY);
    printf("Open with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(SYS_open, test_file_path, O_WRONLY);
    printf("Open with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = rename(test_file_path, "/home/zyler/test_rename.txt");
    printf("Rename return %d\n", ret);

    ret = creat(test_creat_path, mode);
    printf("creat return %d\n", ret);

    return ret;
}