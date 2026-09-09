#include "pn_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static size_t ber_len(uint8_t *p, size_t n)
{
    if (n < 128) {
        p[0] = (uint8_t)n;
        return 1;
    }
    p[0] = 0x81;
    p[1] = (uint8_t)n;
    return 2;
}

static size_t ber_tlv(uint8_t *p, uint8_t tag, const uint8_t *v, size_t n)
{
    size_t i = 0;
    p[i++] = tag;
    i += ber_len(p + i, n);
    if (n && v) {
        memcpy(p + i, v, n);
    }
    return i + n;
}

static size_t ber_int(uint8_t *p, int v)
{
    uint8_t b[4];
    b[0] = (uint8_t)((v >> 24) & 0xff);
    b[1] = (uint8_t)((v >> 16) & 0xff);
    b[2] = (uint8_t)((v >> 8) & 0xff);
    b[3] = (uint8_t)(v & 0xff);
    int s = 0;
    while (s < 3 && b[s] == 0) {
        s++;
    }
    return ber_tlv(p, 0x02, b + s, (size_t)(4 - s));
}

static size_t ber_oid_sysname(uint8_t *p)
{
    static const uint8_t oid[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
                                  0x00};
    return ber_tlv(p, 0x06, oid, sizeof(oid));
}

int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t len, uint8_t *resp,
                   size_t cap, size_t *out_len)
{
    (void)req;
    (void)len;
    if (!s || !resp || !out_len) {
        return -EINVAL;
    }

    uint8_t inner[256];
    size_t i = 0;
    inner[i++] = 0x30;
    size_t vb_len_at = i++;
    i += ber_oid_sysname(inner + i);
    const char *name = s->cfg.station_name;
    i += ber_tlv(inner + i, 0x04, (const uint8_t *)name, strlen(name));
    inner[vb_len_at] = (uint8_t)(i - vb_len_at - 1);

    uint8_t vbl[300];
    size_t v = 0;
    vbl[v++] = 0x30;
    size_t vbl_len_at = v++;
    memcpy(vbl + v, inner, i);
    v += i;
    vbl[vbl_len_at] = (uint8_t)(v - vbl_len_at - 1);

    uint8_t pdu[400];
    size_t p = 0;
    pdu[p++] = 0xA2;
    size_t pdu_len_at = p++;
    p += ber_int(pdu + p, 1);
    p += ber_int(pdu + p, 0);
    p += ber_int(pdu + p, 0);
    memcpy(pdu + p, vbl, v);
    p += v;
    pdu[pdu_len_at] = (uint8_t)(p - pdu_len_at - 1);

    uint8_t msg[500];
    size_t m = 0;
    msg[m++] = 0x30;
    size_t msg_len_at = m++;
    m += ber_int(msg + m, 0);
    m += ber_tlv(msg + m, 0x04, (const uint8_t *)"public", 6);
    memcpy(msg + m, pdu, p);
    m += p;
    msg[msg_len_at] = (uint8_t)(m - msg_len_at - 1);

    if (m > cap) {
        return -ENOSPC;
    }
    memcpy(resp, msg, m);
    *out_len = m;
    return 0;
}

void pn_snmp_poll(pn_stack_t *s)
{
    if (s->fd_snmp < 0) {
        return;
    }
    uint8_t buf[1500];
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);
    ssize_t n = recvfrom(s->fd_snmp, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&src, &sl);
    if (n <= 0) {
        return;
    }
    uint8_t msg[500];
    size_t m = 0;
    if (pn_snmp_handle(s, buf, (size_t)n, msg, sizeof(msg), &m) == 0 && m > 0) {
        sendto(s->fd_snmp, msg, m, 0, (struct sockaddr *)&src, sl);
    }
    (void)errno;
}
