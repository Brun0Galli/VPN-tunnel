// tun.c
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "tun.h"

int tun_create(const char *devname) {
    struct ifreq ifr;
    int fd, err;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("open /dev/net/tun");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (devname && *devname) {
        strncpy(ifr.ifr_name, devname, IFNAMSIZ);
    }

    err = ioctl(fd, TUNSETIFF, (void *)&ifr);
    if (err < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return -1;
    }

    printf("TUN creado: %s\n", ifr.ifr_name);
    return fd;
}