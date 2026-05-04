#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

void die(const char *msg);
void log_info(const char *msg);

int read_full(int fd, void *buf, size_t len);
int write_full(int fd, const void *buf, size_t len);

#endif
