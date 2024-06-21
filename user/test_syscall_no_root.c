#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

#define ADD 0
#define REMOVE 1

char *saved_password = "the_password";
char *new_password = "new_password";
char *test_file_path = "/home/zyler/test";

int main(void)
{
    int ret;
    FILE *file;

    printf("Test Change State No Root\n");

    ret = syscall(134, saved_password, OFF);
    if (ret == -EPERM)
        printf("Test Change State No Root OFF Passed\n");
    else
        printf("Test Change State No Root OFF Failed %d\n", ret);

    ret = syscall(134, saved_password, ON);
    if (ret == -EPERM)
        printf("Test Change State No Root ON Passed\n");
    else
        printf("Test Change State No Root ON Failed %d\n", ret);

    ret = syscall(134, saved_password, REC_ON);
    if (ret == -EPERM)
        printf("Test Change State No Root REC_ON Passed\n");
    else
        printf("Test Change State No Root REC_ON Failed %d\n", ret);

    ret = syscall(134, saved_password, REC_OFF);
    if (ret == -EPERM)
        printf("Test Change State No Root REC_OFF Passed\n");
    else
        printf("Test Change State No Root REC_OFF Failed %d\n", ret);

    // create the test file
    file = fopen(test_file_path, "a");
    fclose(file);

    printf("Test Edit Paths No Root\n");

    ret = syscall(156, saved_password, test_file_path, ADD);
    if (ret == -EPERM)
        printf("Test Edit Paths No Root ADD Passed\n");
    else
        printf("Test Edit Paths No Root ADD Failed %d\n", ret);

    ret = syscall(156, saved_password, test_file_path, REMOVE);
    if (ret == -EPERM)
        printf("Test Edit Paths No Root REMOVE Passed \n");
    else
        printf("Test Edit Paths No Root REMOVE Failed %d\n", ret);

    printf("Test Change Password No Root\n");

    ret = syscall(174, saved_password, new_password);
    if (ret == -EPERM)
        printf("Test Change Password No Root Passed \n");
    else
        printf("Test Change Password No Root Failed %d\n", ret);
}