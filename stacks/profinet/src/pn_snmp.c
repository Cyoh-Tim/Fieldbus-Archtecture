#include "pn_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define ASN_INT   0x02u
#define ASN_OCT   0x04u
#define ASN_NULL  0x05u
#define ASN_OID   0x06u
#define ASN_GAUGE 0x42u
#define ASN_TICKS 0x43u

#define SNMP_ERR_NOSUCHNAME 2

#define OID_MAX 16
#define LEAF_VAL_MAX 64

static uint32_t ticks_from(const pn_stack_t *s, uint64_t ns)
{
    if (ns < s->start_ns) {
        return 0;
    }
    return (uint32_t)((ns - s->start_ns) / 10000000ull);
}

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

static size_t ber_uint(uint8_t *p, uint8_t tag, uint32_t v)
{
    uint8_t b[5] = {0};
    b[1] = (uint8_t)((v >> 24) & 0xff);
    b[2] = (uint8_t)((v >> 16) & 0xff);
    b[3] = (uint8_t)((v >> 8) & 0xff);
    b[4] = (uint8_t)(v & 0xff);
    int s = 1;
    while (s < 4 && b[s] == 0) {
        s++;
    }
    if (b[s] & 0x80) {
        s--;
    }
    return ber_tlv(p, tag, b + s, (size_t)(5 - s));
}

static size_t ber_int(uint8_t *p, int v)
{
    return ber_uint(p, ASN_INT, (uint32_t)v);
}

static int ber_parse_int(const uint8_t *p, size_t n, int *out, size_t *used)
{
    if (n < 2 || p[0] != ASN_INT) {
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

static int oid_decode(const uint8_t *p, size_t n, uint32_t *oid, uint8_t *out_n)
{
    if (!p || n == 0 || n > 64) {
        return -1;
    }
    oid[0] = (uint32_t)(p[0] / 40);
    oid[1] = (uint32_t)(p[0] % 40);
    uint8_t k = 2;
    uint32_t v = 0;
    int pending = 0;
    for (size_t i = 1; i < n; i++) {
        v = (v << 7) | (uint32_t)(p[i] & 0x7f);
        pending = 1;
        if (!(p[i] & 0x80)) {
            if (k >= OID_MAX) {
                return -1;
            }
            oid[k++] = v;
            v = 0;
            pending = 0;
        }
    }
    if (pending) {
        return -1;
    }
    /* Legacy pretest encoded 8802 as 0xC46A (8810). Accept both. */
    if (k >= 3 && oid[0] == 1 && oid[1] == 0 && oid[2] == 8810) {
        oid[2] = 8802;
    }
    *out_n = k;
    return 0;
}

static size_t oid_encode(const uint32_t *oid, uint8_t n, uint8_t *out)
{
    if (n < 2) {
        return 0;
    }
    size_t i = 0;
    out[i++] = (uint8_t)(40u * oid[0] + oid[1]);
    for (uint8_t k = 2; k < n; k++) {
        uint32_t v = oid[k];
        uint8_t tmp[5];
        int t = 0;
        tmp[t++] = (uint8_t)(v & 0x7f);
        v >>= 7;
        while (v) {
            tmp[t++] = (uint8_t)((v & 0x7f) | 0x80);
            v >>= 7;
        }
        while (t--) {
            out[i++] = tmp[t];
        }
    }
    return i;
}

static int oid_cmp(const uint32_t *a, uint8_t an, const uint32_t *b, uint8_t bn)
{
    uint8_t n = an < bn ? an : bn;
    for (uint8_t i = 0; i < n; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    if (an < bn) {
        return -1;
    }
    if (an > bn) {
        return 1;
    }
    return 0;
}

static int oid_is_prefix(const uint32_t *pre, uint8_t pn, const uint32_t *oid,
                         uint8_t on)
{
    if (pn > on) {
        return 0;
    }
    return oid_cmp(pre, pn, oid, pn) == 0;
}

enum {
    L_LLDP_LASTCHG,
    L_LLDP_LOC_CHASSIS_ST,
    L_LLDP_LOC_CHASSIS,
    L_LLDP_LOC_SYSNAME,
    L_LLDP_LOC_SYSDESC,
    L_LLDP_LOC_PORT_ST,
    L_LLDP_LOC_PORT,
    L_LLDP_REM_CHASSIS_ST,
    L_LLDP_REM_CHASSIS,
    L_LLDP_REM_PORT_ST,
    L_LLDP_REM_PORT,
    L_LLDP_REM_SYSNAME,
    L_SYSDESCR,
    L_SYSOID,
    L_SYSUPTIME,
    L_SYSCONTACT,
    L_SYSNAME,
    L_SYSLOCATION,
    L_SYSSERVICES,
    L_IFNUMBER,
    L_IFINDEX,
    L_IFDESCR,
    L_IFTYPE,
    L_IFMTU,
    L_IFSPEED,
    L_IFPHYS,
    L_IFADMIN,
    L_IFOPER,
    L_COUNT
};

static const uint32_t k_oids[][OID_MAX] = {
    [L_LLDP_LASTCHG] = {1, 0, 8802, 1, 1, 2, 1, 2, 6, 0},
    [L_LLDP_LOC_CHASSIS_ST] = {1, 0, 8802, 1, 1, 2, 1, 3, 1, 0},
    [L_LLDP_LOC_CHASSIS] = {1, 0, 8802, 1, 1, 2, 1, 3, 2, 0},
    [L_LLDP_LOC_SYSNAME] = {1, 0, 8802, 1, 1, 2, 1, 3, 3, 0},
    [L_LLDP_LOC_SYSDESC] = {1, 0, 8802, 1, 1, 2, 1, 3, 4, 0},
    [L_LLDP_LOC_PORT_ST] = {1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 2, 1},
    [L_LLDP_LOC_PORT] = {1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 3, 1},
    [L_LLDP_REM_CHASSIS_ST] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 4, 0, 1, 1},
    [L_LLDP_REM_CHASSIS] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 5, 0, 1, 1},
    [L_LLDP_REM_PORT_ST] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 6, 0, 1, 1},
    [L_LLDP_REM_PORT] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 7, 0, 1, 1},
    [L_LLDP_REM_SYSNAME] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9, 0, 1, 1},
    [L_SYSDESCR] = {1, 3, 6, 1, 2, 1, 1, 1, 0},
    [L_SYSOID] = {1, 3, 6, 1, 2, 1, 1, 2, 0},
    [L_SYSUPTIME] = {1, 3, 6, 1, 2, 1, 1, 3, 0},
    [L_SYSCONTACT] = {1, 3, 6, 1, 2, 1, 1, 4, 0},
    [L_SYSNAME] = {1, 3, 6, 1, 2, 1, 1, 5, 0},
    [L_SYSLOCATION] = {1, 3, 6, 1, 2, 1, 1, 6, 0},
    [L_SYSSERVICES] = {1, 3, 6, 1, 2, 1, 1, 7, 0},
    [L_IFNUMBER] = {1, 3, 6, 1, 2, 1, 2, 1, 0},
    [L_IFINDEX] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 1},
    [L_IFDESCR] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 2, 1},
    [L_IFTYPE] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 3, 1},
    [L_IFMTU] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 4, 1},
    [L_IFSPEED] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 5, 1},
    [L_IFPHYS] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1},
    [L_IFADMIN] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 1},
    [L_IFOPER] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 1},
};

static const uint8_t k_oidn[L_COUNT] = {
    [L_LLDP_LASTCHG] = 10,
    [L_LLDP_LOC_CHASSIS_ST] = 10,
    [L_LLDP_LOC_CHASSIS] = 10,
    [L_LLDP_LOC_SYSNAME] = 10,
    [L_LLDP_LOC_SYSDESC] = 10,
    [L_LLDP_LOC_PORT_ST] = 12,
    [L_LLDP_LOC_PORT] = 12,
    [L_LLDP_REM_CHASSIS_ST] = 14,
    [L_LLDP_REM_CHASSIS] = 14,
    [L_LLDP_REM_PORT_ST] = 14,
    [L_LLDP_REM_PORT] = 14,
    [L_LLDP_REM_SYSNAME] = 14,
    [L_SYSDESCR] = 9,
    [L_SYSOID] = 9,
    [L_SYSUPTIME] = 9,
    [L_SYSCONTACT] = 9,
    [L_SYSNAME] = 9,
    [L_SYSLOCATION] = 9,
    [L_SYSSERVICES] = 9,
    [L_IFNUMBER] = 9,
    [L_IFINDEX] = 11,
    [L_IFDESCR] = 11,
    [L_IFTYPE] = 11,
    [L_IFMTU] = 11,
    [L_IFSPEED] = 11,
    [L_IFPHYS] = 11,
    [L_IFADMIN] = 11,
    [L_IFOPER] = 11,
};

static int leaf_needs_rem(int id)
{
    return id == L_LLDP_REM_CHASSIS_ST || id == L_LLDP_REM_CHASSIS ||
           id == L_LLDP_REM_PORT_ST || id == L_LLDP_REM_PORT ||
           id == L_LLDP_REM_SYSNAME;
}

static int leaf_present(const pn_stack_t *s, int id)
{
    if (leaf_needs_rem(id) && !s->lldp_rem_set) {
        return 0;
    }
    return 1;
}

static size_t put_str(uint8_t *val, const char *s)
{
    size_t n = strlen(s);
    if (n > LEAF_VAL_MAX) {
        n = LEAF_VAL_MAX;
    }
    memcpy(val, s, n);
    return n;
}

static int leaf_value(pn_stack_t *s, int id, uint8_t *asn, uint8_t *val,
                      size_t *vlen)
{
    static const uint32_t sysoid[] = {1, 3, 6, 1, 4, 1, 99999, 1};
    const char *descr =
        s->cfg.device_type[0] ? s->cfg.device_type : "Fieldbus PN Device";
    const char *port = "port-001";
    uint64_t now = pn_now_ns();

    switch (id) {
    case L_LLDP_LASTCHG:
        *asn = ASN_TICKS;
        *vlen = ber_uint(val, ASN_TICKS,
                         ticks_from(s, s->lldp_last_change_ns
                                           ? s->lldp_last_change_ns
                                           : s->start_ns));
        return 0;
    case L_LLDP_LOC_CHASSIS_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, 4); /* macAddress */
        return 0;
    case L_LLDP_LOC_CHASSIS:
        *asn = ASN_OCT;
        memcpy(val, s->cfg.mac, 6);
        *vlen = 6;
        return 0;
    case L_LLDP_LOC_SYSNAME:
        *asn = ASN_OCT;
        *vlen = put_str(val, s->cfg.station_name);
        return 0;
    case L_LLDP_LOC_SYSDESC:
        *asn = ASN_OCT;
        *vlen = put_str(val, descr);
        return 0;
    case L_LLDP_LOC_PORT_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, 7); /* local */
        return 0;
    case L_LLDP_LOC_PORT:
        *asn = ASN_OCT;
        *vlen = put_str(val, port);
        return 0;
    case L_LLDP_REM_CHASSIS_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, s->lldp_rem_chassis_subtype
                                 ? s->lldp_rem_chassis_subtype
                                 : 4);
        return 0;
    case L_LLDP_REM_CHASSIS:
        *asn = ASN_OCT;
        if (s->lldp_rem_chassis_len) {
            size_t n = s->lldp_rem_chassis_len;
            if (n > LEAF_VAL_MAX) {
                n = LEAF_VAL_MAX;
            }
            memcpy(val, s->lldp_rem_chassis, n);
            *vlen = n;
        } else {
            memcpy(val, s->lldp_rem_mac, 6);
            *vlen = 6;
        }
        return 0;
    case L_LLDP_REM_PORT_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, s->lldp_rem_port_subtype
                                 ? s->lldp_rem_port_subtype
                                 : 3);
        return 0;
    case L_LLDP_REM_PORT:
        *asn = ASN_OCT;
        if (s->lldp_rem_port[0]) {
            *vlen = put_str(val, s->lldp_rem_port);
        } else {
            memcpy(val, s->lldp_rem_mac, 6);
            *vlen = 6;
        }
        return 0;
    case L_LLDP_REM_SYSNAME:
        *asn = ASN_OCT;
        *vlen = put_str(val, s->lldp_rem_name);
        return 0;
    case L_SYSDESCR:
        *asn = ASN_OCT;
        *vlen = put_str(val, descr);
        return 0;
    case L_SYSOID:
        *asn = ASN_OID;
        *vlen = oid_encode(sysoid, 8, val);
        return 0;
    case L_SYSUPTIME:
        *asn = ASN_TICKS;
        *vlen = ber_uint(val, ASN_TICKS, ticks_from(s, now));
        return 0;
    case L_SYSCONTACT:
    case L_SYSLOCATION:
        *asn = ASN_OCT;
        *vlen = 0;
        return 0;
    case L_SYSNAME:
        *asn = ASN_OCT;
        *vlen = put_str(val, s->cfg.station_name);
        return 0;
    case L_SYSSERVICES:
        *asn = ASN_INT;
        *vlen = ber_int(val, 72);
        return 0;
    case L_IFNUMBER:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFINDEX:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFDESCR:
        *asn = ASN_OCT;
        *vlen = put_str(val, port);
        return 0;
    case L_IFTYPE:
        *asn = ASN_INT;
        *vlen = ber_int(val, 6); /* ethernetCsmacd */
        return 0;
    case L_IFMTU:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1500);
        return 0;
    case L_IFSPEED:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, 100000000u);
        return 0;
    case L_IFPHYS:
        *asn = ASN_OCT;
        memcpy(val, s->cfg.mac, 6);
        *vlen = 6;
        return 0;
    case L_IFADMIN:
    case L_IFOPER:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1); /* up, matches PDPort Link UP */
        return 0;
    default:
        return -1;
    }
}

static int match_get(pn_stack_t *s, const uint32_t *req, uint8_t rn)
{
    int prefix = -1;
    for (int i = 0; i < L_COUNT; i++) {
        if (!leaf_present(s, i)) {
            continue;
        }
        uint8_t ln = k_oidn[i];
        if (oid_cmp(req, rn, k_oids[i], ln) == 0) {
            return i;
        }
        /* Scalar .0 omitted, or table prefix that uniquely identifies a leaf. */
        if (oid_is_prefix(req, rn, k_oids[i], ln) && rn < ln) {
            if (prefix < 0) {
                prefix = i;
            } else {
                prefix = -2;
            }
        }
    }
    return prefix >= 0 ? prefix : -1;
}

static int match_next(pn_stack_t *s, const uint32_t *req, uint8_t rn)
{
    for (int i = 0; i < L_COUNT; i++) {
        if (!leaf_present(s, i)) {
            continue;
        }
        if (oid_cmp(req, rn, k_oids[i], k_oidn[i]) < 0) {
            return i;
        }
    }
    return -1;
}

static int snmp_parse(const uint8_t *buf, size_t n, int *rid, int *pdu_type,
                      uint32_t *oid, uint8_t *oid_n)
{
    if (n < 2 || buf[0] != 0x30) {
        return -1;
    }
    size_t off = 2;
    if (buf[1] & 0x80) {
        off += (size_t)(buf[1] & 0x7f);
    }
    if (off >= n) {
        return -1;
    }
    int ver = 0;
    size_t used = 0;
    if (ber_parse_int(buf + off, n - off, &ver, &used) != 0) {
        return -1;
    }
    (void)ver;
    off += used;
    if (off >= n || buf[off] != ASN_OCT) {
        return -1;
    }
    size_t clen = buf[off + 1];
    off += 2 + clen;
    if (off >= n) {
        return -1;
    }
    int pt = buf[off];
    if ((pt & 0xF0) != 0xA0) {
        return -1;
    }
    *pdu_type = pt;
    off += 2;
    if (buf[off - 1] & 0x80) {
        off += (size_t)(buf[off - 1] & 0x7f) - 1;
    }
    *rid = 1;
    if (off < n && ber_parse_int(buf + off, n - off, rid, &used) == 0) {
        off += used;
    }
    const uint8_t *found = NULL;
    size_t found_n = 0;
    for (size_t i = off; i + 2 < n; i++) {
        if (buf[i] == ASN_OID && buf[i + 1] < 128 &&
            i + 2 + buf[i + 1] <= n) {
            found = buf + i + 2;
            found_n = buf[i + 1];
            break;
        }
    }
    if (!found || oid_decode(found, found_n, oid, oid_n) != 0) {
        *oid_n = 0;
    }
    return 0;
}

static size_t wrap_seq(uint8_t *out, const uint8_t *inner, size_t n)
{
    size_t i = 0;
    out[i++] = 0x30;
    i += ber_len(out + i, n);
    memcpy(out + i, inner, n);
    return i + n;
}

int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t n, uint8_t *resp,
                   size_t cap, size_t *out_len)
{
    int rid = 1, pdu_type = 0xA0;
    uint32_t req_oid[OID_MAX];
    uint8_t req_n = 0;
    if (snmp_parse(req, n, &rid, &pdu_type, req_oid, &req_n) != 0) {
        return -EINVAL;
    }

    int is_next = (pdu_type == 0xA1);
    int leaf = is_next ? match_next(s, req_oid, req_n)
                       : match_get(s, req_oid, req_n);

    uint8_t vb_inner[192];
    size_t vi = 0;
    int err = 0;
    uint32_t out_oid[OID_MAX];
    uint8_t out_n = req_n;
    memcpy(out_oid, req_oid, sizeof(uint32_t) * req_n);

    uint8_t asn = ASN_NULL;
    uint8_t val[LEAF_VAL_MAX + 8];
    size_t vlen = 0;

    if (leaf >= 0 && leaf_value(s, leaf, &asn, val, &vlen) == 0) {
        memcpy(out_oid, k_oids[leaf], sizeof(uint32_t) * k_oidn[leaf]);
        out_n = k_oidn[leaf];
    } else {
        err = SNMP_ERR_NOSUCHNAME;
        asn = ASN_NULL;
        vlen = 0;
        if (is_next) {
            /* SNMPv1 GetNext past end: noSuchName, echo request OID. */
            memcpy(out_oid, req_oid, sizeof(uint32_t) * req_n);
            out_n = req_n;
        }
    }

    uint8_t oidber[48];
    size_t olen = oid_encode(out_oid, out_n, oidber);
    vi += ber_tlv(vb_inner + vi, ASN_OID, oidber, olen);
    if (err) {
        vi += ber_tlv(vb_inner + vi, ASN_NULL, NULL, 0);
    } else if (asn == ASN_OCT) {
        vi += ber_tlv(vb_inner + vi, ASN_OCT, val, vlen);
    } else if (asn == ASN_OID) {
        vi += ber_tlv(vb_inner + vi, ASN_OID, val, vlen);
    } else {
        /* INTEGER / TimeTicks / Gauge already encoded as TLV in val. */
        memcpy(vb_inner + vi, val, vlen);
        vi += vlen;
    }

    uint8_t vb[208];
    size_t vb_n = wrap_seq(vb, vb_inner, vi);
    uint8_t vbl[220];
    size_t vbl_n = wrap_seq(vbl, vb, vb_n);

    uint8_t pdu_inner[280];
    size_t p = 0;
    p += ber_int(pdu_inner + p, rid);
    p += ber_int(pdu_inner + p, err);
    p += ber_int(pdu_inner + p, err ? 1 : 0);
    memcpy(pdu_inner + p, vbl, vbl_n);
    p += vbl_n;

    uint8_t pdu[300];
    size_t pn = 0;
    pdu[pn++] = 0xA2;
    pn += ber_len(pdu + pn, p);
    memcpy(pdu + pn, pdu_inner, p);
    pn += p;

    uint8_t msg_inner[320];
    size_t m = 0;
    m += ber_int(msg_inner + m, 0);
    m += ber_tlv(msg_inner + m, ASN_OCT, (const uint8_t *)"public", 6);
    memcpy(msg_inner + m, pdu, pn);
    m += pn;

    size_t total = wrap_seq(resp, msg_inner, m);
    if (total > cap) {
        return -ENOSPC;
    }
    *out_len = total;
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
    size_t mlen = 0;
    if (pn_snmp_handle(s, buf, (size_t)n, msg, sizeof(msg), &mlen) != 0) {
        return;
    }
    sendto(s->fd_snmp, msg, mlen, 0, (struct sockaddr *)&src, sl);
    (void)errno;
}
