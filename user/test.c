#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

char *saved_password = "the_password";
char *test_file_path = "/home/zyler/test.txt";

int main(void)
{
    int ret;

    ret = syscall(174, saved_password, test_file_path, 0);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", errno);
        return ret;
    }
    ret = unlink(test_file_path);
    printf("Unlink return %d\n", ret);

    ret = unlinkat(AT_FDCWD, test_file_path, 0);
    printf("Unlinkat return %d\n", ret);

    ret = syscall(2, test_file_path, O_RDONLY);
    printf("Open with O_RDONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    ret = syscall(2, test_file_path, O_WRONLY);
    printf("Open with O_WRONLY return %d\n", ret);
    if (ret > 0)
        close(ret);

    return ret;
}