#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <net/if.h>

#include "tun.h"
#include "utils.h"

#define PORT 5555

int main() {
    int sockfd;
    struct sockaddr_in server;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket");

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sockfd, (struct sockaddr*)&server, sizeof(server)) < 0)
        die("connect");

    char tun_name[IFNAMSIZ];
    tun_name[0] = '\0';

    int tun_fd = tun_create(tun_name);
    if (tun_fd < 0)
        die("tun_create failed");

    printf("[INFO] Client TUN: %s\n", tun_name);

    char buffer[2000];

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        FD_SET(tun_fd, &fds);

        int maxfd = (sockfd > tun_fd ? sockfd : tun_fd) + 1;

        if (select(maxfd, &fds, NULL, NULL, NULL) < 0)
            die("select");

        if (FD_ISSET(sockfd, &fds)) {
            int len = read(sockfd, buffer, sizeof(buffer));
            if (len <= 0) break;
            write_full(tun_fd, buffer, len);
        }

        if (FD_ISSET(tun_fd, &fds)) {
            int len = read(tun_fd, buffer, sizeof(buffer));
            if (len <= 0) break;
            write_full(sockfd, buffer, len);
        }
    }

    close(sockfd);
    close(tun_fd);

    return 0;
}
