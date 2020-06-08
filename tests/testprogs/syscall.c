#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>

#define FILE_NAME_LENGTH 50
#define TEMP_FILE_NAME "RUNTIME_TEST_SYSCALL_GEN_TEMP"

void usage() {
    printf("Usage:\n");
    printf("\t./syscall <syscall name> [<arguments>]\n");
    printf("Supported Syscalls:\n");
    printf("\t nanosleep [$N] (default args: 100ns)\n");
    printf("\t open\n");
    printf("\t openat\n");
    printf("\t read\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage();
        exit(0);
    }
    const char *syscall_name = argv[1];
    int r;

    if (strcmp("nanosleep", syscall_name) == 0) {
        struct timespec req;
        const char * arg = argv[2];
        req.tv_sec = 0;
        req.tv_nsec = 100;
        if (argc > 2) {
            long long n = atoll(arg);
            if (n == 0 && arg[strspn(arg, "0")] != '\0') {
                printf("Cannot convert argument '%s' to a number.\n", arg);
                exit(0);
            }

            if (n < 0) {
                printf("Invalid argument '%s', argument should not be negative", arg);
                exit(0);
            }

            req.tv_sec = n / 1000000000;
            req.tv_nsec = n % 1000000000;
        }
        r = syscall(SYS_nanosleep, &req, NULL);
        if (r)
            printf("Error in syscall %s: %d\n", syscall_name, errno);
    }

    else if (strcmp("open", syscall_name) == 0 || strcmp("openat", syscall_name) == 0) {
        //char *file_name = tempnam("./", TEMP_FILE_NAME);
        const char *file_name = TEMP_FILE_NAME;
        if (file_name == NULL) {
            printf("Error when getting file name: %d\n", errno);
            exit(0);
        }
        int fd = strcmp("open", syscall_name) ? syscall(SYS_openat, AT_FDCWD, file_name, O_CREAT) : syscall(SYS_open, file_name, O_CREAT);
        if (fd < 0) {
            printf("Error in syscall %s: %d\n", syscall_name, errno);
            exit(0);
        }
        close(fd);
        remove(file_name);
    }

    else if (strcmp("read", syscall_name) == 0) {
        char file_name[FILE_NAME_LENGTH];
        strncpy(file_name, "TEMP_FILE_SYS_READ_XXXXXX", FILE_NAME_LENGTH - 1);
        int fd = mkstemp(file_name);
        if (fd < 0) {
            printf("Error in syscall %s when creating temp file: %d\n", syscall_name, errno);
            exit(0);
        }
        char buf[10];
        int r = syscall(SYS_read, fd, (void *)buf, 0);
        close(fd);
        remove(file_name);
    }

    return 0;
}