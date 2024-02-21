#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (syscall(134, "the_password", atoi(argv[1])) < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}