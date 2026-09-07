#define _GNU_SOURCE

#include "pn_endian.h"
#include "pn_types.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "사용법: %s <iface>\n", argv[0]);
        return 1;
    }
    const char *iface = argv[1];

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        perror("socket");
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        return 1;
    }
    int ifindex = ifr.ifr_ifindex;
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        return 1;
    }
    uint8_t srcmac[6];
    memcpy(srcmac, ifr.ifr_hwaddr.sa_data, 6);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, 0xA1B2C3D4);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);

    uint8_t frame[64];
    memcpy(frame, k_dcp_mc, 6);
    memcpy(frame + 6, srcmac, 6);
    pn_wr_be16(frame + 12, PN_ETHTYPE_PN);
    memcpy(frame + 14, pay, 16);

    sll.sll_halen = 6;
    memcpy(sll.sll_addr, k_dcp_mc, 6);
    if (sendto(fd, frame, 30, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        return 1;
    }
    fprintf(stderr, "DCP Identify sent on %s\n", iface);

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    for (int i = 0; i < 50; i++) {
        uint8_t rx[1518];
        ssize_t n = recv(fd, rx, sizeof(rx), 0);
        if (n < 14) {
            usleep(20000);
            continue;
        }
        uint16_t et = (uint16_t)((rx[12] << 8) | rx[13]);
        if (et != PN_ETHTYPE_PN || n < 16) {
            continue;
        }
        uint16_t fid = (uint16_t)((rx[14] << 8) | rx[15]);
        if (fid != PN_FRAMEID_DCP_ID_RES) {
            continue;
        }
        fwrite(rx, 1, (size_t)n, stdout);
        fprintf(stderr, "got Identify.Res %zd bytes", n);
        if (n >= 20) {
            for (ssize_t k = 0; k + 12 < n; k++) {
                if (memcmp(rx + k, "sensor-line1", 12) == 0) {
                    fprintf(stderr, " NameOfStation=sensor-line1");
                    fprintf(stderr, "\n");
                    return 0;
                }
            }
        }
        fprintf(stderr, "\n");
        return 2;
    }
    fprintf(stderr, "timeout: no DCP Identify.Res\n");
    return 1;
}
