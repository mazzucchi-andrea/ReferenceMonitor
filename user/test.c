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
char *test_filename = "test.txt";
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

    printf("Test test_file_path test_dir_path\n");

    // add test_file_path to protected paths
    ret = syscall(174, saved_password, test_file_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    // add test_dir_path to protected paths
    ret = syscall(174, saved_password, test_dir_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }

    // unlink test_file_path
    ret = unlink(test_file_path);
    printf("unlink test_file_path returns %d\n", ret);

    // unlinkat test_file_path AT_FDCWD
    ret = unlinkat(AT_FDCWD, test_file_path, 0);
    printf("unlinkat test_file_path AT_FDCWD returns %d\n", ret);

    // unlinkat test_dir_path AT_FDCWD AT_REMOVEDIR
    ret = unlinkat(AT_FDCWD, test_dir_path, AT_REMOVEDIR);
    printf("unlinkat test_dir_path AT_FDCWD AT_REMOVEDIR returns %d\n", ret);

    // unlinkat test_dir_path dirfd AT_REMOVEDIR
    ret = unlinkat(dirfd, test_dir_name, AT_REMOVEDIR);
    printf("unlinkat test_dir_path dirfd AT_REMOVEDIR returns %d\n", ret);

    // unlinkat test_file_path dirfd
    ret = unlinkat(dirfd, test_filename, 0);
    printf("unlinkat test_file_path dirfd returns %d\n", ret);

    // rename test_file_path
    ret = rename(test_file_path, "/home/zyler/parent_dir/test_rename.txt");
    printf("rename test_file_path returns %d\n", ret);

    // rename test_dir_path
    ret = rename(test_dir_path, "/home/zyler/tparent_dir/est_dir_rename.txt");
    printf("rename test_file_path returns %d\n", ret);

    // renameat AT_FDCWD test_file_path AT_FDCWD
    ret = renameat(AT_FDCWD, test_file_path, AT_FDCWD, "/home/zyler/parent_dir/test_rename.txt");
    printf("renameat AT_FDCWD test_file_path returns %d\n", ret);

    // renameat AT_FDCWD test_dir_path AT_FDCWD
    ret = renameat(AT_FDCWD, test_dir_path, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename.txt");
    printf("renameat AT_FDCWD test_file_path returns %d\n", ret);

    // renameat dirfd test_filename AT_FDCWD
    ret = renameat(dirfd, test_filename, AT_FDCWD, "/home/zyler/parent_dir/test_rename.txt");
    printf("renameat dirfd test_filename AT_FDCWD returns %d\n", ret);

    // renameat dirfd test_dir_path
    ret = renameat(dirfd, test_dir_name, AT_FDCWD, "/home/zyler/parent_dir/test_dir_rename.txt");
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
    ret = unlinkat(dirfd, test_filename, 0);
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

    ret = rmdir(parent_dir_path);
    printf("rmdir parent_dir_path returns %d\n", ret);

    return ret;
}