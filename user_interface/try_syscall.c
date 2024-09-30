#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int syscall_, param;

    if (argc < 3) {
        printf("usage: syscall-num param\n");
        return EXIT_FAILURE;
    }

    syscall_ = strtol(argv[1], NULL, 10);
    param = strtol(argv[2], NULL, 10);

    int ret = syscall(syscall_, param);
    if (ret != 0) {
        printf("Syscall failed = %d.\n", ret);
        return 1;
    }

    printf("Syscall %d executed with param %d\n", syscall_, param);

    return 0;
}
