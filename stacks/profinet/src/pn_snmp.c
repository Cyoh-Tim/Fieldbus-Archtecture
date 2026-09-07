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

/* Walk a BER INTEGER; returns value and bytes consumed, or 0 on fail. */
static int ber_parse_int(const uint8_t *p, size_t n, int *out, size_t *used)
{
    if (n < 2 || p[0] != 0x02) {
        return -1;
    }
    size_t ln = p[1];
    size_t hdr = 2;
    if (ln & 0x80) {
        return -1;
    }
    if (hdr + ln > n || ln == 0 || ln > 4) {
        return -1;
    }
    int v = 0;
    for (size_t i = 0; i < ln; i++) {
        v = (v << 8) | p[hdr + i];
    }
    *out = v;
    *used = hdr + ln;
    return 0;
}

static int snmp_request_id(const uint8_t *buf, size_t n)
{
    /* SEQUENCE { version INTEGER, community OCTET STRING, PDU } */
    if (n < 2 || buf[0] != 0x30) {
        return 1;
    }
    size_t off = 2;
    if (buf[1] & 0x80) {
        off += (size_t)(buf[1] & 0x7f);
    }
    if (off >= n) {
        return 1;
    }
    int ver = 0;
    size_t used = 0;
    if (ber_parse_int(buf + off, n - off, &ver, &used) != 0) {
        return 1;
    }
    off += used;
    if (off >= n || buf[off] != 0x04) {
        return 1;
    }
    size_t clen = buf[off + 1];
    off += 2 + clen;
    if (off >= n) {
        return 1;
    }
    /* PDU: GetRequest 0xA0 / GetNext 0xA1 / Set 0xA3 */
    if ((buf[off] & 0xF0) != 0xA0) {
        return 1;
    }
    off += 2;
    if (buf[off - 1] & 0x80) {
        off += (size_t)(buf[off - 1] & 0x7f) - 1;
    }
    int rid = 1;
    if (off < n && ber_parse_int(buf + off, n - off, &rid, &used) == 0) {
        return rid;
    }
    return 1;
}

static int snmp_find_oid(const uint8_t *buf, size_t n, const uint8_t **oid,
                         size_t *olen)
{
    for (size_t i = 0; i + 2 < n; i++) {
        if (buf[i] == 0x06 && buf[i + 1] < 128 && i + 2 + buf[i + 1] <= n) {
            *oid = buf + i + 2;
            *olen = buf[i + 1];
            return 0;
        }
    }
    return -1;
}

static int oid_eq(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an == bn && memcmp(a, b, an) == 0;
}

static int oid_prefix(const uint8_t *a, size_t an, const uint8_t *b, size_t bn)
{
    return an >= bn && memcmp(a, b, bn) == 0;
}

static size_t ber_oid(uint8_t *p, const uint8_t *oid, size_t n)
{
    return ber_tlv(p, 0x06, oid, n);
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
    int req_id = snmp_request_id(buf, (size_t)n);

    static const uint8_t k_sysname[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                        0x05, 0x00};
    static const uint8_t k_sysdescr[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                         0x01, 0x00};
    /* 1.0.8802.1.1.2.1.3.3[.0] lldpLocSysName */
    static const uint8_t k_lldp_loc[] = {0x28, 0xc4, 0x6a, 0x01, 0x01, 0x02,
                                         0x01, 0x03, 0x03};
    /* 1.0.8802.1.1.2.1.4.1.1.9 lldpRemSysName */
    static const uint8_t k_lldp_rem[] = {0x28, 0xc4, 0x6a, 0x01, 0x01, 0x02,
                                         0x01, 0x04, 0x01, 0x01, 0x09};

    const uint8_t *req_oid = k_sysname;
    size_t req_olen = sizeof(k_sysname);
    const uint8_t *found = NULL;
    size_t found_n = 0;
    if (snmp_find_oid(buf, (size_t)n, &found, &found_n) == 0) {
        req_oid = found;
        req_olen = found_n;
    }

    const char *val = s->cfg.station_name;
    if (oid_prefix(req_oid, req_olen, k_sysdescr, sizeof(k_sysdescr) - 1) ||
        oid_eq(req_oid, req_olen, k_sysdescr, sizeof(k_sysdescr))) {
        val = s->cfg.device_type[0] ? s->cfg.device_type : "FB-ARCH PN Device";
    } else if (oid_prefix(req_oid, req_olen, k_lldp_loc, sizeof(k_lldp_loc))) {
        val = s->cfg.station_name;
    } else if (oid_prefix(req_oid, req_olen, k_lldp_rem, sizeof(k_lldp_rem))) {
        val = s->lldp_rem_set ? s->lldp_rem_name : "";
    }

    uint8_t inner[256];
    size_t i = 0;
    inner[i++] = 0x30;
    size_t vb_len_at = i++;
    i += ber_oid(inner + i, req_oid, req_olen);
    i += ber_tlv(inner + i, 0x04, (const uint8_t *)val, strlen(val));
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
    p += ber_int(pdu + p, req_id);
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

    sendto(s->fd_snmp, msg, m, 0, (struct sockaddr *)&src, sl);
    (void)errno;
}
