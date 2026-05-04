#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void log_info(const char *msg) {
    printf("[INFO] %s\n", msg);
}

int read_full(int fd, void *buf, size_t len) {
    size_t total = 0;
    char *p = buf;

    while (total < len) {
        int n = read(fd, p + total, len - total);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

int write_full(int fd, const void *buf, size_t len) {
    size_t total = 0;
    const char *p = buf;

    while (total < len) {
        int n = write(fd, p + total, len - total);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}
