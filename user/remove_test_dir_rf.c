#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

const char *saved_password = "the_password";
char *test_dir = "./parent_dir";

int main(void)
{
    // Check if the effective user ID is 0 (root)
    if (geteuid())
    {
        printf("You must run this program as root.\n");
        exit(EXIT_FAILURE);
    }

    // remove test_dir_path to protected paths
    if (syscall(156, saved_password, test_dir, 1))
    {
        printf("edit_paths failed with error %d\n", errno);
        return -errno;
    }
    printf("%s removed from Reference Monitor\n", test_dir);

    return 0;
}