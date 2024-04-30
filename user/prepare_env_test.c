#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int main() {
    const char *parent_dir = "parent_dir";
    const char *test_dir = "parent_dir/test_dir";
    const char *test_file = "parent_dir/test.txt";

    // Create parent directory
    if (mkdir(parent_dir, 0777) == -1 && errno != EEXIST) {
        perror("mkdir parent_dir failed");
        exit(EXIT_FAILURE);
    }

    // Create test directory
    if (mkdir(test_dir, 0777) == -1 && errno != EEXIST) {
        perror("mkdir test_dir failed");
        exit(EXIT_FAILURE);
    }

    // Create test file
    FILE *fp = fopen(test_file, "w");
    if (fp == NULL) {
        perror("fopen test.txt failed");
        exit(EXIT_FAILURE);
    }
    fclose(fp);

    printf("Directory structure created successfully.\n");

    return 0;
}
