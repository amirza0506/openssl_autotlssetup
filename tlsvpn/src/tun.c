#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <errno.h>

#include "tun.h"
#include "utils.h"

int tun_create(char *dev)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
        die("open /dev/net/tun");

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    // IMPORTANT FIX:
    // allow kernel to assign tun0/tun1/etc
    if (dev && dev[0] != '\0')
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0)
        die("ioctl(TUNSETIFF)");

    // return actual interface name
    strcpy(dev, ifr.ifr_name);

    return fd;
}
