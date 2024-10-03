#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int syscall_, param, param2;

    // if (argc < 3) {
    //     printf("usage: syscall-num param\n");
    //     return EXIT_FAILURE;
    // }

    // syscall_ = strtol(argv[1], NULL, 10);
    // param = strtol(argv[2], NULL, 10);
    // param2 = strtol(argv[3], NULL, 10);

    int ret = syscall(134, 50, 0);
    if (ret != 0) {
        printf("Syscall failed = %d. errno=%d\n", ret, errno);
        return 1;
    }

    printf("Syscall %d executed with param %d\n", syscall_, param);

    return 0;
}
