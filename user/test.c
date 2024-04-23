#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

char *saved_password = "the_password";
char *test_file_path = "/home/zyler/parent_dir/test.txt";
char *test_file_name = "test.txt";
char *parent_dir_path = "/home/zyler/parent_dir";
char *test_dir_name = "test_dir";
char *test_dir_path = "/home/zyler/parent_dir/test_dir";

int main(void)
{
    int ret, dirfd;

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
    printf("Unlink test_file_path return %d\n", ret);

    ret = unlinkat(AT_FDCWD, test_file_path, 0);
    printf("Unlinkat test_file_path return %d\n", ret);

    // test unlinkat remove dir AT_FDCWD
    ret = unlinkat(AT_FDCWD, test_dir_path, 0);
    printf("Unlinkat test_dir_path return %d\n", ret);

    dirfd = open(parent_dir_path, O_RDONLY);
    if (dirfd < 0)
    {
        printf("Failing open parent_dir_path %d\n", dirfd);
        return dirfd;
    }

    // test unlinkat relative dir dir
    ret = unlinkat(dirfd, test_dir_name, AT_REMOVEDIR);
    printf("Unlinkat test_dir_name return %d\n", ret);

    // test unlinkat relative dir file
    ret = unlinkat(dirfd, test_file_name, 0);
    printf("Unlinkat test_dir_name return %d\n", ret);

    ret = syscall(2, test_file_path, O_RDONLY);
    printf("Open with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(2, test_file_path, O_WRONLY);
    printf("Open with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = rename(test_file_path, "/home/zyler/test_rename.txt");
    printf("Rename return %d\n", ret);

    return ret;
}