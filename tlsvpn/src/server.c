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
    int sockfd, client;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) die("socket");

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        die("bind");

    if (listen(sockfd, 1) < 0)
        die("listen");

    log_info("Server listening...");

    client = accept(sockfd, NULL, NULL);
    if (client < 0)
        die("accept");

    // IMPORTANT FIX: let kernel choose interface name
    char tun_name[IFNAMSIZ];
    tun_name[0] = '\0';

    int tun_fd = tun_create(tun_name);
    if (tun_fd < 0)
        die("tun_create failed");

    printf("[INFO] TUN created: %s\n", tun_name);

    char buffer[2000];

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(client, &fds);
        FD_SET(tun_fd, &fds);

        int maxfd = (client > tun_fd ? client : tun_fd) + 1;

        if (select(maxfd, &fds, NULL, NULL, NULL) < 0)
            die("select");

        // client -> tun
        if (FD_ISSET(client, &fds)) {
            int len = read(client, buffer, sizeof(buffer));
            if (len <= 0) break;
            write_full(tun_fd, buffer, len);
        }

        // tun -> client
        if (FD_ISSET(tun_fd, &fds)) {
            int len = read(tun_fd, buffer, sizeof(buffer));
            if (len <= 0) break;
            write_full(client, buffer, len);
        }
    }

    close(client);
    close(sockfd);
    close(tun_fd);

    return 0;
}
