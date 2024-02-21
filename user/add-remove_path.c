#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    if (syscall(156, "the_password", argv[1], atoi(argv[2])) < 0)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}