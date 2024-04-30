#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PASSWORD_MAX_LEN 64
#define PATH_MAX_LEN 4096

#define ON 0
#define OFF 1
#define REC_ON 2
#define REC_OFF 3

#define ADD 0
#define REMOVE 1

char *saved_password = "the_password";

void change_state()
{
    int state, ret;

    printf("Select one of the folliwing states:\n");
    printf("ON: %d\n", ON);
    printf("OFF: %d\n", OFF);
    printf("REC_ON: %d\n", REC_ON);
    printf("REC_OFF: %d\n", REC_OFF);

    printf("Enter the state: ");
    scanf("%d", &state);

    if (state < 0 || state > 3)
    {
        printf("Invalid state code\n");
        return;
    }

    ret = syscall(156, saved_password, state);
    if (ret < 0)
    {
        printf("change_state failed with error %d\n", ret);
        return;
    }

    printf("State Changed\n");
}

void edit_path()
{
    int mode, ret;
    char path[PATH_MAX_LEN];

    printf("Select one of the folliwing modes:\n");
    printf("ADD: %d\n", ADD);
    printf("REMOVE: %d\n", REMOVE);

    printf("Enter the mode: ");
    scanf("%d", &mode);

    if (mode != 0 && mode != 1)
    {
        printf("Invalid mode code %d\n", mode);
        return;
    }

    printf("Enter the path (up to %d characters): ", PATH_MAX_LEN - 1);
    scanf("%4095s", path);

    ret = syscall(174, saved_password, path, mode);
    if (ret < 0)
    {
        printf("edit_path failed with error %d\n", ret);
        return;
    }

    printf("Path Edited\n");
}

void change_password()
{
    int ret;
    char new_password[PASSWORD_MAX_LEN + 1];

    printf("Enter the new password (up to %d characters): ", PASSWORD_MAX_LEN);
    scanf("%64s", new_password);

    ret = syscall(177, saved_password, new_password);
    if (ret < 0)
    {
        printf("change_password failed with error %d\n", ret);
        return;
    }

    saved_password = new_password;

    printf("Password Changed\n");
}

int main()
{

    while (1)
    {
        printf("Options:\n");
        printf("1. Invoke syscall change_state\n");
        printf("2. Invoke syscall edit_path\n");
        printf("3. Invoke syscall change_password\n");
        printf("0. Exit\n");

        int choice;
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice)
        {
        case 1:
        {
            change_state();
            break;
        }

        case 2:
        {
            edit_path();
            break;
        }

        case 3:
        {
            change_password();
            break;
        }

        case 0:
        {
            printf("Exiting program.\n");
            exit(0);
        }

        default:
            printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}
