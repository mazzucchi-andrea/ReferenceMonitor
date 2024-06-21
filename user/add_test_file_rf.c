#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

const char *saved_password = "the_password";
const char *test_file_path = "./parent_dir/test.txt";
const char *test_dir_relative_path = "./parent_dir/test_dir";


int main() {
    // Check if the effective user ID is 0 (root)
    if (geteuid() != 0) {
        printf("You must run this program as root.\n");
        exit(EXIT_FAILURE);
    }

    // add test_file_path to protected paths
    if (syscall(156, saved_password, test_file_path, 0) == -1)
    {
        printf("edit_paths failed with error %d\n", errno);
        return -errno;
    }
    printf("%s added to Reference Monitor\n", test_file_path);

    // add test_dir_path to protected paths
    if (syscall(156, saved_password, test_dir_relative_path, 0) == -1)
    {
        printf("edit_paths failed with error %d\n", errno);
        return -errno;
    }
    printf("%s added to Reference Monitor\n", test_dir_relative_path);

    return 0;
}