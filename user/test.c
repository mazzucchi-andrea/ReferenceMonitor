#include <stdio.h>
#include <unistd.h>
#include <errno.h>

char *saved_password = "the_password";
char *test_file_path = "/home/zyler/test";

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
    return ret;
}