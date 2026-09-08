#include "pn_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#define ASN_INT        0x02u
#define ASN_OCT        0x04u
#define ASN_NULL       0x05u
#define ASN_OID        0x06u
#define ASN_COUNTER    0x41u
#define ASN_GAUGE      0x42u
#define ASN_TICKS      0x43u
#define ASN_COUNTER64  0x46u

#define SNMP_ERR_NOSUCHNAME 2
#define SNMP_ERR_READONLY   4

#define OID_MAX 18
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
    if (n < 256) {
        p[0] = 0x81;
        p[1] = (uint8_t)n;
        return 2;
    }
    p[0] = 0x82;
    p[1] = (uint8_t)(n >> 8);
    p[2] = (uint8_t)n;
    return 3;
}

static size_t ber_len_size(size_t n)
{
    if (n < 128) {
        return 1;
    }
    if (n < 256) {
        return 2;
    }
    return 3;
}

static int ber_read_len(const uint8_t *p, size_t n, size_t *len, size_t *used)
{
    if (n < 1) {
        return -1;
    }
    if (!(p[0] & 0x80)) {
        *len = p[0];
        *used = 1;
        return 0;
    }
    size_t nbytes = (size_t)(p[0] & 0x7f);
    if (nbytes == 0 || nbytes > 2 || 1 + nbytes > n) {
        return -1;
    }
    size_t v = 0;
    for (size_t i = 0; i < nbytes; i++) {
        v = (v << 8) | p[1 + i];
    }
    *len = v;
    *used = 1 + nbytes;
    return 0;
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
    L_LLDP_TX_INT,
    L_LLDP_TX_HOLD,
    L_LLDP_STATS_INS,
    L_LLDP_STATS_DEL,
    L_LLDP_STATS_DROP,
    L_LLDP_STATS_AGE,
    L_LLDP_LASTCHG,
    L_LLDP_LOC_CHASSIS_ST,
    L_LLDP_LOC_CHASSIS,
    L_LLDP_LOC_SYSNAME,
    L_LLDP_LOC_SYSDESC,
    L_LLDP_LOC_CAP_SUP,
    L_LLDP_LOC_CAP_EN,
    L_LLDP_LOC_PORT_ST,
    L_LLDP_LOC_PORT,
    L_LLDP_LOC_PORT_DESC,
    L_LLDP_REM_CHASSIS_ST,
    L_LLDP_REM_CHASSIS,
    L_LLDP_REM_PORT_ST,
    L_LLDP_REM_PORT,
    L_LLDP_REM_SYSNAME,
    L_LLDP_REM_SYSDESC,
    L_LLDP_REM_CAP_SUP,
    L_LLDP_REM_CAP_EN,
    L_LLDP_XPNO_TXD,
    L_LLDP_XPNO_RXD,
    L_LLDP_XPNO_REM_TXD,
    L_LLDP_XPNO_REM_RXD,
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
    L_IFLASTCHG,
    L_IFINOCT,
    L_IFINUCAST,
    L_IFINNUCAST,
    L_IFINDISC,
    L_IFINERR,
    L_IFINUNK,
    L_IFOUTOCT,
    L_IFOUTUCAST,
    L_IFOUTNUCAST,
    L_IFOUTDISC,
    L_IFOUTERR,
    L_IFOUTQLEN,
    L_IFSPEC,
    L_IPFWD,
    L_IPTTL,
    L_IP_ADENT_ADDR,
    L_IP_ADENT_IF,
    L_IP_ADENT_MASK,
    L_IP_ADENT_BCAST,
    L_ICMP_IN,
    L_ICMP_INERR,
    L_ICMP_INECHO,
    L_ICMP_INECHOREP,
    L_ICMP_OUT,
    L_ICMP_OUTECHO,
    L_UDP_IN,
    L_UDP_NOPORT,
    L_UDP_INERR,
    L_UDP_OUT,
    L_UDP_LADDR,
    L_UDP_LPORT,
    L_SNMP_IN,
    L_SNMP_OUT,
    L_SNMP_INGET,
    L_SNMP_INNEXT,
    L_SNMP_INSET,
    L_SNMP_OUTRESP,
    L_SNMP_AUTHTRAP,
    L_IFX_NAME,
    L_IFX_INMCAST,
    L_IFX_INBCAST,
    L_IFX_OUTMCAST,
    L_IFX_OUTBCAST,
    L_IFX_HCIN,
    L_IFX_HCOUT,
    L_IFX_TRAP,
    L_IFX_HSPEED,
    L_IFX_PROM,
    L_IFX_CONN,
    L_IFX_ALIAS,
    L_IFX_DISC,
    L_AT_IF,
    L_AT_PHYS,
    L_AT_NET,
    L_IP_NTM_IF,
    L_IP_NTM_PHYS,
    L_IP_NTM_NET,
    L_IP_NTM_TYPE,
    L_ICMP_INDST,
    L_ICMP_INTIME,
    L_ICMP_INPARM,
    L_ICMP_INQUENCH,
    L_ICMP_INREDIR,
    L_ICMP_INTS,
    L_ICMP_INTSREP,
    L_ICMP_INMASK,
    L_ICMP_INMASKREP,
    L_ICMP_OUTERR,
    L_ICMP_OUTDST,
    L_ICMP_OUTTIME,
    L_ICMP_OUTPARM,
    L_ICMP_OUTQUENCH,
    L_ICMP_OUTREDIR,
    L_ICMP_OUTECHOREP,
    L_ICMP_OUTTS,
    L_ICMP_OUTTSREP,
    L_ICMP_OUTMASK,
    L_ICMP_OUTMASKREP,
    L_TCP_RTOALG,
    L_TCP_RTOMIN,
    L_TCP_RTOMAX,
    L_TCP_MAXCONN,
    L_TCP_ACTIVE,
    L_TCP_PASSIVE,
    L_TCP_ATTEMPT,
    L_TCP_ESTABRST,
    L_TCP_CURRESTAB,
    L_TCP_INSEG,
    L_TCP_OUTSEG,
    L_TCP_RETRANS,
    L_TCP_INERR,
    L_TCP_OUTRST,
    L_COUNT
};

static uint32_t k_oids[][OID_MAX] = {
    [L_LLDP_TX_INT] = {1, 0, 8802, 1, 1, 2, 1, 1, 1, 0},
    [L_LLDP_TX_HOLD] = {1, 0, 8802, 1, 1, 2, 1, 1, 2, 0},
    [L_LLDP_STATS_INS] = {1, 0, 8802, 1, 1, 2, 1, 2, 2, 0},
    [L_LLDP_STATS_DEL] = {1, 0, 8802, 1, 1, 2, 1, 2, 3, 0},
    [L_LLDP_STATS_DROP] = {1, 0, 8802, 1, 1, 2, 1, 2, 4, 0},
    [L_LLDP_STATS_AGE] = {1, 0, 8802, 1, 1, 2, 1, 2, 5, 0},
    [L_LLDP_LASTCHG] = {1, 0, 8802, 1, 1, 2, 1, 2, 6, 0},
    [L_LLDP_LOC_CHASSIS_ST] = {1, 0, 8802, 1, 1, 2, 1, 3, 1, 0},
    [L_LLDP_LOC_CHASSIS] = {1, 0, 8802, 1, 1, 2, 1, 3, 2, 0},
    [L_LLDP_LOC_SYSNAME] = {1, 0, 8802, 1, 1, 2, 1, 3, 3, 0},
    [L_LLDP_LOC_SYSDESC] = {1, 0, 8802, 1, 1, 2, 1, 3, 4, 0},
    [L_LLDP_LOC_CAP_SUP] = {1, 0, 8802, 1, 1, 2, 1, 3, 5, 0},
    [L_LLDP_LOC_CAP_EN] = {1, 0, 8802, 1, 1, 2, 1, 3, 6, 0},
    [L_LLDP_LOC_PORT_ST] = {1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 2, 1},
    [L_LLDP_LOC_PORT] = {1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 3, 1},
    [L_LLDP_LOC_PORT_DESC] = {1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 4, 1},
    [L_LLDP_REM_CHASSIS_ST] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 4, 0, 1, 1},
    [L_LLDP_REM_CHASSIS] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 5, 0, 1, 1},
    [L_LLDP_REM_PORT_ST] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 6, 0, 1, 1},
    [L_LLDP_REM_PORT] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 7, 0, 1, 1},
    [L_LLDP_REM_SYSNAME] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 9, 0, 1, 1},
    [L_LLDP_REM_SYSDESC] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 10, 0, 1, 1},
    [L_LLDP_REM_CAP_SUP] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 11, 0, 1, 1},
    [L_LLDP_REM_CAP_EN] = {1, 0, 8802, 1, 1, 2, 1, 4, 1, 1, 12, 0, 1, 1},
    [L_LLDP_XPNO_TXD] = {1, 0, 8802, 1, 1, 2, 1, 5, 3791, 1, 2, 3, 1, 1, 1},
    [L_LLDP_XPNO_RXD] = {1, 0, 8802, 1, 1, 2, 1, 5, 3791, 1, 2, 4, 1, 1, 1},
    [L_LLDP_XPNO_REM_TXD] = {1, 0, 8802, 1, 1, 2, 1, 5, 3791, 1, 3, 3, 1, 1, 0, 1, 1},
    [L_LLDP_XPNO_REM_RXD] = {1, 0, 8802, 1, 1, 2, 1, 5, 3791, 1, 3, 4, 1, 1, 0, 1, 1},
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
    [L_IFLASTCHG] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 9, 1},
    [L_IFINOCT] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1},
    [L_IFINUCAST] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 11, 1},
    [L_IFINNUCAST] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 12, 1},
    [L_IFINDISC] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 13, 1},
    [L_IFINERR] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 14, 1},
    [L_IFINUNK] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 15, 1},
    [L_IFOUTOCT] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 16, 1},
    [L_IFOUTUCAST] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 17, 1},
    [L_IFOUTNUCAST] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 18, 1},
    [L_IFOUTDISC] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 19, 1},
    [L_IFOUTERR] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 20, 1},
    [L_IFOUTQLEN] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 21, 1},
    [L_IFSPEC] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 22, 1},
    [L_IPFWD] = {1, 3, 6, 1, 2, 1, 4, 1, 0},
    [L_IPTTL] = {1, 3, 6, 1, 2, 1, 4, 2, 0},
    [L_IP_ADENT_ADDR] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 0, 0, 0, 0},
    [L_IP_ADENT_IF] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 2, 0, 0, 0, 0},
    [L_IP_ADENT_MASK] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 3, 0, 0, 0, 0},
    [L_IP_ADENT_BCAST] = {1, 3, 6, 1, 2, 1, 4, 20, 1, 4, 0, 0, 0, 0},
    [L_ICMP_IN] = {1, 3, 6, 1, 2, 1, 5, 1, 0},
    [L_ICMP_INERR] = {1, 3, 6, 1, 2, 1, 5, 2, 0},
    [L_ICMP_INECHO] = {1, 3, 6, 1, 2, 1, 5, 8, 0},
    [L_ICMP_INECHOREP] = {1, 3, 6, 1, 2, 1, 5, 9, 0},
    [L_ICMP_OUT] = {1, 3, 6, 1, 2, 1, 5, 14, 0},
    [L_ICMP_OUTECHO] = {1, 3, 6, 1, 2, 1, 5, 21, 0},
    [L_UDP_IN] = {1, 3, 6, 1, 2, 1, 7, 1, 0},
    [L_UDP_NOPORT] = {1, 3, 6, 1, 2, 1, 7, 2, 0},
    [L_UDP_INERR] = {1, 3, 6, 1, 2, 1, 7, 3, 0},
    [L_UDP_OUT] = {1, 3, 6, 1, 2, 1, 7, 4, 0},
    [L_UDP_LADDR] = {1, 3, 6, 1, 2, 1, 7, 5, 1, 1, 0, 0, 0, 0, 161},
    [L_UDP_LPORT] = {1, 3, 6, 1, 2, 1, 7, 5, 1, 2, 0, 0, 0, 0, 161},
    [L_SNMP_IN] = {1, 3, 6, 1, 2, 1, 11, 1, 0},
    [L_SNMP_OUT] = {1, 3, 6, 1, 2, 1, 11, 2, 0},
    [L_SNMP_INGET] = {1, 3, 6, 1, 2, 1, 11, 15, 0},
    [L_SNMP_INNEXT] = {1, 3, 6, 1, 2, 1, 11, 16, 0},
    [L_SNMP_INSET] = {1, 3, 6, 1, 2, 1, 11, 17, 0},
    [L_SNMP_OUTRESP] = {1, 3, 6, 1, 2, 1, 11, 28, 0},
    [L_SNMP_AUTHTRAP] = {1, 3, 6, 1, 2, 1, 11, 30, 0},
    [L_IFX_NAME] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 1},
    [L_IFX_INMCAST] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 2, 1},
    [L_IFX_INBCAST] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 3, 1},
    [L_IFX_OUTMCAST] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 4, 1},
    [L_IFX_OUTBCAST] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 5, 1},
    [L_IFX_HCIN] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1},
    [L_IFX_HCOUT] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, 1},
    [L_IFX_TRAP] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 14, 1},
    [L_IFX_HSPEED] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 15, 1},
    [L_IFX_PROM] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 16, 1},
    [L_IFX_CONN] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 17, 1},
    [L_IFX_ALIAS] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18, 1},
    [L_IFX_DISC] = {1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 19, 1},
    [L_AT_IF] = {1, 3, 6, 1, 2, 1, 3, 1, 1, 1, 1, 0, 0, 0, 0},
    [L_AT_PHYS] = {1, 3, 6, 1, 2, 1, 3, 1, 1, 2, 1, 0, 0, 0, 0},
    [L_AT_NET] = {1, 3, 6, 1, 2, 1, 3, 1, 1, 3, 1, 0, 0, 0, 0},
    [L_IP_NTM_IF] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 1, 1, 0, 0, 0, 0},
    [L_IP_NTM_PHYS] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 2, 1, 0, 0, 0, 0},
    [L_IP_NTM_NET] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 3, 1, 0, 0, 0, 0},
    [L_IP_NTM_TYPE] = {1, 3, 6, 1, 2, 1, 4, 22, 1, 4, 1, 0, 0, 0, 0},
    [L_ICMP_INDST] = {1, 3, 6, 1, 2, 1, 5, 3, 0},
    [L_ICMP_INTIME] = {1, 3, 6, 1, 2, 1, 5, 4, 0},
    [L_ICMP_INPARM] = {1, 3, 6, 1, 2, 1, 5, 5, 0},
    [L_ICMP_INQUENCH] = {1, 3, 6, 1, 2, 1, 5, 6, 0},
    [L_ICMP_INREDIR] = {1, 3, 6, 1, 2, 1, 5, 7, 0},
    [L_ICMP_INTS] = {1, 3, 6, 1, 2, 1, 5, 10, 0},
    [L_ICMP_INTSREP] = {1, 3, 6, 1, 2, 1, 5, 11, 0},
    [L_ICMP_INMASK] = {1, 3, 6, 1, 2, 1, 5, 12, 0},
    [L_ICMP_INMASKREP] = {1, 3, 6, 1, 2, 1, 5, 13, 0},
    [L_ICMP_OUTERR] = {1, 3, 6, 1, 2, 1, 5, 15, 0},
    [L_ICMP_OUTDST] = {1, 3, 6, 1, 2, 1, 5, 16, 0},
    [L_ICMP_OUTTIME] = {1, 3, 6, 1, 2, 1, 5, 17, 0},
    [L_ICMP_OUTPARM] = {1, 3, 6, 1, 2, 1, 5, 18, 0},
    [L_ICMP_OUTQUENCH] = {1, 3, 6, 1, 2, 1, 5, 19, 0},
    [L_ICMP_OUTREDIR] = {1, 3, 6, 1, 2, 1, 5, 20, 0},
    [L_ICMP_OUTECHOREP] = {1, 3, 6, 1, 2, 1, 5, 22, 0},
    [L_ICMP_OUTTS] = {1, 3, 6, 1, 2, 1, 5, 23, 0},
    [L_ICMP_OUTTSREP] = {1, 3, 6, 1, 2, 1, 5, 24, 0},
    [L_ICMP_OUTMASK] = {1, 3, 6, 1, 2, 1, 5, 25, 0},
    [L_ICMP_OUTMASKREP] = {1, 3, 6, 1, 2, 1, 5, 26, 0},
    [L_TCP_RTOALG] = {1, 3, 6, 1, 2, 1, 6, 1, 0},
    [L_TCP_RTOMIN] = {1, 3, 6, 1, 2, 1, 6, 2, 0},
    [L_TCP_RTOMAX] = {1, 3, 6, 1, 2, 1, 6, 3, 0},
    [L_TCP_MAXCONN] = {1, 3, 6, 1, 2, 1, 6, 4, 0},
    [L_TCP_ACTIVE] = {1, 3, 6, 1, 2, 1, 6, 5, 0},
    [L_TCP_PASSIVE] = {1, 3, 6, 1, 2, 1, 6, 6, 0},
    [L_TCP_ATTEMPT] = {1, 3, 6, 1, 2, 1, 6, 7, 0},
    [L_TCP_ESTABRST] = {1, 3, 6, 1, 2, 1, 6, 8, 0},
    [L_TCP_CURRESTAB] = {1, 3, 6, 1, 2, 1, 6, 9, 0},
    [L_TCP_INSEG] = {1, 3, 6, 1, 2, 1, 6, 10, 0},
    [L_TCP_OUTSEG] = {1, 3, 6, 1, 2, 1, 6, 11, 0},
    [L_TCP_RETRANS] = {1, 3, 6, 1, 2, 1, 6, 12, 0},
    [L_TCP_INERR] = {1, 3, 6, 1, 2, 1, 6, 14, 0},
    [L_TCP_OUTRST] = {1, 3, 6, 1, 2, 1, 6, 15, 0},
};

static const uint8_t k_oidn[L_COUNT] = {
    [L_LLDP_TX_INT] = 10, [L_LLDP_TX_HOLD] = 10,
    [L_LLDP_STATS_INS] = 10, [L_LLDP_STATS_DEL] = 10,
    [L_LLDP_STATS_DROP] = 10, [L_LLDP_STATS_AGE] = 10, [L_LLDP_LASTCHG] = 10,
    [L_LLDP_LOC_CHASSIS_ST] = 10, [L_LLDP_LOC_CHASSIS] = 10,
    [L_LLDP_LOC_SYSNAME] = 10, [L_LLDP_LOC_SYSDESC] = 10,
    [L_LLDP_LOC_CAP_SUP] = 10, [L_LLDP_LOC_CAP_EN] = 10,
    [L_LLDP_LOC_PORT_ST] = 12, [L_LLDP_LOC_PORT] = 12, [L_LLDP_LOC_PORT_DESC] = 12,
    [L_LLDP_REM_CHASSIS_ST] = 14, [L_LLDP_REM_CHASSIS] = 14,
    [L_LLDP_REM_PORT_ST] = 14, [L_LLDP_REM_PORT] = 14,
    [L_LLDP_REM_SYSNAME] = 14, [L_LLDP_REM_SYSDESC] = 14,
    [L_LLDP_REM_CAP_SUP] = 14, [L_LLDP_REM_CAP_EN] = 14,
    [L_LLDP_XPNO_TXD] = 15, [L_LLDP_XPNO_RXD] = 15,
    [L_LLDP_XPNO_REM_TXD] = 17, [L_LLDP_XPNO_REM_RXD] = 17,
    [L_SYSDESCR] = 9, [L_SYSOID] = 9, [L_SYSUPTIME] = 9, [L_SYSCONTACT] = 9,
    [L_SYSNAME] = 9, [L_SYSLOCATION] = 9, [L_SYSSERVICES] = 9,
    [L_IFNUMBER] = 9,
    [L_IFINDEX] = 11, [L_IFDESCR] = 11, [L_IFTYPE] = 11, [L_IFMTU] = 11,
    [L_IFSPEED] = 11, [L_IFPHYS] = 11, [L_IFADMIN] = 11, [L_IFOPER] = 11,
    [L_IFLASTCHG] = 11, [L_IFINOCT] = 11, [L_IFINUCAST] = 11, [L_IFINNUCAST] = 11,
    [L_IFINDISC] = 11, [L_IFINERR] = 11, [L_IFINUNK] = 11, [L_IFOUTOCT] = 11,
    [L_IFOUTUCAST] = 11, [L_IFOUTNUCAST] = 11, [L_IFOUTDISC] = 11, [L_IFOUTERR] = 11,
    [L_IFOUTQLEN] = 11, [L_IFSPEC] = 11,
    [L_IPFWD] = 9, [L_IPTTL] = 9,
    [L_IP_ADENT_ADDR] = 14, [L_IP_ADENT_IF] = 14, [L_IP_ADENT_MASK] = 14,
    [L_IP_ADENT_BCAST] = 14,
    [L_ICMP_IN] = 9, [L_ICMP_INERR] = 9, [L_ICMP_INECHO] = 9,
    [L_ICMP_INECHOREP] = 9, [L_ICMP_OUT] = 9, [L_ICMP_OUTECHO] = 9,
    [L_UDP_IN] = 9, [L_UDP_NOPORT] = 9, [L_UDP_INERR] = 9, [L_UDP_OUT] = 9,
    [L_UDP_LADDR] = 15, [L_UDP_LPORT] = 15,
    [L_SNMP_IN] = 9, [L_SNMP_OUT] = 9, [L_SNMP_INGET] = 9, [L_SNMP_INNEXT] = 9,
    [L_SNMP_INSET] = 9, [L_SNMP_OUTRESP] = 9, [L_SNMP_AUTHTRAP] = 9,
    [L_IFX_NAME] = 12, [L_IFX_INMCAST] = 12, [L_IFX_INBCAST] = 12,
    [L_IFX_OUTMCAST] = 12, [L_IFX_OUTBCAST] = 12, [L_IFX_HCIN] = 12,
    [L_IFX_HCOUT] = 12, [L_IFX_TRAP] = 12, [L_IFX_HSPEED] = 12, [L_IFX_PROM] = 12,
    [L_IFX_CONN] = 12, [L_IFX_ALIAS] = 12, [L_IFX_DISC] = 12,
    [L_AT_IF] = 15, [L_AT_PHYS] = 15, [L_AT_NET] = 15,
    [L_IP_NTM_IF] = 15, [L_IP_NTM_PHYS] = 15, [L_IP_NTM_NET] = 15,
    [L_IP_NTM_TYPE] = 15,
    [L_ICMP_INDST] = 9, [L_ICMP_INTIME] = 9, [L_ICMP_INPARM] = 9,
    [L_ICMP_INQUENCH] = 9, [L_ICMP_INREDIR] = 9, [L_ICMP_INTS] = 9,
    [L_ICMP_INTSREP] = 9, [L_ICMP_INMASK] = 9, [L_ICMP_INMASKREP] = 9,
    [L_ICMP_OUTERR] = 9, [L_ICMP_OUTDST] = 9, [L_ICMP_OUTTIME] = 9,
    [L_ICMP_OUTPARM] = 9, [L_ICMP_OUTQUENCH] = 9, [L_ICMP_OUTREDIR] = 9,
    [L_ICMP_OUTECHOREP] = 9, [L_ICMP_OUTTS] = 9, [L_ICMP_OUTTSREP] = 9,
    [L_ICMP_OUTMASK] = 9, [L_ICMP_OUTMASKREP] = 9,
    [L_TCP_RTOALG] = 9, [L_TCP_RTOMIN] = 9, [L_TCP_RTOMAX] = 9,
    [L_TCP_MAXCONN] = 9, [L_TCP_ACTIVE] = 9, [L_TCP_PASSIVE] = 9,
    [L_TCP_ATTEMPT] = 9, [L_TCP_ESTABRST] = 9, [L_TCP_CURRESTAB] = 9,
    [L_TCP_INSEG] = 9, [L_TCP_OUTSEG] = 9, [L_TCP_RETRANS] = 9,
    [L_TCP_INERR] = 9, [L_TCP_OUTRST] = 9,
};

static int leaf_needs_rem(int id)
{
    return id == L_LLDP_REM_CHASSIS_ST || id == L_LLDP_REM_CHASSIS ||
           id == L_LLDP_REM_PORT_ST || id == L_LLDP_REM_PORT ||
           id == L_LLDP_REM_SYSNAME || id == L_LLDP_REM_SYSDESC ||
           id == L_LLDP_REM_CAP_SUP || id == L_LLDP_REM_CAP_EN ||
           id == L_LLDP_XPNO_REM_TXD || id == L_LLDP_XPNO_REM_RXD;
}

static void bind_ip_oids(const pn_stack_t *s)
{
    uint32_t ip = s->cfg.ip;
    uint32_t a = (ip >> 24) & 0xffu;
    uint32_t b = (ip >> 16) & 0xffu;
    uint32_t c = (ip >> 8) & 0xffu;
    uint32_t d = ip & 0xffu;
    static const int ids[] = {
        L_IP_ADENT_ADDR, L_IP_ADENT_IF, L_IP_ADENT_MASK, L_IP_ADENT_BCAST,
        L_AT_IF, L_AT_PHYS, L_AT_NET, L_IP_NTM_IF, L_IP_NTM_PHYS, L_IP_NTM_NET,
        L_IP_NTM_TYPE};
    for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
        uint8_t n = k_oidn[ids[i]];
        if (n < 4) {
            continue;
        }
        k_oids[ids[i]][n - 4] = a;
        k_oids[ids[i]][n - 3] = b;
        k_oids[ids[i]][n - 2] = c;
        k_oids[ids[i]][n - 1] = d;
    }
}

static void put_ip_oct(uint8_t *val, uint32_t v)
{
    val[0] = (uint8_t)((v >> 24) & 0xff);
    val[1] = (uint8_t)((v >> 16) & 0xff);
    val[2] = (uint8_t)((v >> 8) & 0xff);
    val[3] = (uint8_t)(v & 0xff);
}

static int leaf_present(const pn_stack_t *s, int id)
{
    if (leaf_needs_rem(id) && !s->lldp_rem_set) {
        return 0;
    }
    return 1;
}

static int leaf_writable(int id)
{
    /* RFC 1213 lists sysContact/sysName/sysLocation as writable.
     * PI SC1 keeps SNMP read-only (Get still served for CC-B topology). */
    (void)id;
    return 0;
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

static size_t ber_u64(uint8_t *p, uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (uint8_t)(v >> (56 - 8 * i));
    }
    return ber_tlv(p, ASN_COUNTER64, b, 8);
}

static const char *sys_name(const pn_stack_t *s)
{
    return s->snmp_sysname[0] ? s->snmp_sysname : s->cfg.station_name;
}

static int leaf_value(pn_stack_t *s, int id, uint8_t *asn, uint8_t *val,
                      size_t *vlen)
{
    static const uint32_t sysoid[] = {1, 3, 6, 1, 4, 1, 99999, 1};
    static const uint32_t zero_dot[] = {0, 0};
    const char *descr =
        s->cfg.device_type[0] ? s->cfg.device_type : "Fieldbus PN Device";
    const char *port = "port-001";
    uint64_t now = pn_now_ns();
    static const uint8_t cap[2] = {0x00, 0x80}; /* station-only */

    switch (id) {
    case L_LLDP_TX_INT:
        *asn = ASN_INT;
        *vlen = ber_int(val, 5);
        return 0;
    case L_LLDP_TX_HOLD:
        *asn = ASN_INT;
        *vlen = ber_int(val, 4);
        return 0;
    case L_LLDP_STATS_INS:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, s->lldp_rem_inserts);
        return 0;
    case L_LLDP_STATS_DEL:
    case L_LLDP_STATS_DROP:
    case L_LLDP_STATS_AGE:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, 0);
        return 0;
    case L_LLDP_LASTCHG:
        *asn = ASN_TICKS;
        *vlen = ber_uint(val, ASN_TICKS,
                         ticks_from(s, s->lldp_last_change_ns
                                           ? s->lldp_last_change_ns
                                           : s->start_ns));
        return 0;
    case L_LLDP_LOC_CHASSIS_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, 4);
        return 0;
    case L_LLDP_LOC_CHASSIS:
        *asn = ASN_OCT;
        memcpy(val, s->cfg.mac, 6);
        *vlen = 6;
        return 0;
    case L_LLDP_LOC_SYSNAME:
        *asn = ASN_OCT;
        *vlen = put_str(val, sys_name(s));
        return 0;
    case L_LLDP_LOC_SYSDESC:
        *asn = ASN_OCT;
        *vlen = put_str(val, descr);
        return 0;
    case L_LLDP_LOC_CAP_SUP:
    case L_LLDP_LOC_CAP_EN:
        *asn = ASN_OCT;
        memcpy(val, cap, 2);
        *vlen = 2;
        return 0;
    case L_LLDP_LOC_PORT_ST:
        *asn = ASN_INT;
        *vlen = ber_int(val, 7);
        return 0;
    case L_LLDP_LOC_PORT:
    case L_LLDP_LOC_PORT_DESC:
    case L_IFDESCR:
    case L_IFX_NAME:
    case L_IFX_ALIAS:
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
    case L_LLDP_REM_SYSDESC:
        *asn = ASN_OCT;
        *vlen = put_str(val, s->lldp_rem_desc[0] ? s->lldp_rem_desc : "controller");
        return 0;
    case L_LLDP_XPNO_TXD:
    case L_LLDP_XPNO_RXD:
    case L_LLDP_XPNO_REM_TXD:
    case L_LLDP_XPNO_REM_RXD:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, 1000);
        return 0;
    case L_LLDP_REM_CAP_SUP:
    case L_LLDP_REM_CAP_EN:
        *asn = ASN_OCT;
        memcpy(val, cap, 2);
        *vlen = 2;
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
        *asn = ASN_OCT;
        *vlen = put_str(val, s->snmp_syscontact);
        return 0;
    case L_SYSLOCATION:
        *asn = ASN_OCT;
        *vlen = put_str(val, s->snmp_syslocation);
        return 0;
    case L_SYSNAME:
        *asn = ASN_OCT;
        *vlen = put_str(val, sys_name(s));
        return 0;
    case L_SYSSERVICES:
        *asn = ASN_INT;
        *vlen = ber_int(val, 72);
        return 0;
    case L_IFNUMBER:
    case L_IFINDEX:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFTYPE:
        *asn = ASN_INT;
        *vlen = ber_int(val, 6);
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
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFLASTCHG:
        *asn = ASN_TICKS;
        *vlen = ber_uint(val, ASN_TICKS, 0);
        return 0;
    case L_IFINOCT:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_in_octets);
        return 0;
    case L_IFINUCAST:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_in_ucast);
        return 0;
    case L_IFOUTOCT:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_out_octets);
        return 0;
    case L_IFOUTUCAST:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_out_ucast);
        return 0;
    case L_IFINNUCAST:
    case L_IFINUNK:
    case L_IFOUTNUCAST:
    case L_IFOUTQLEN:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
        return 0;
    case L_IFINDISC:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_in_discards);
        return 0;
    case L_IFINERR:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_in_errors);
        return 0;
    case L_IFOUTDISC:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_out_discards);
        return 0;
    case L_IFOUTERR:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->if_out_errors);
        return 0;
    case L_IFSPEC:
        *asn = ASN_OID;
        *vlen = oid_encode(zero_dot, 2, val);
        return 0;
    case L_IPFWD:
        *asn = ASN_INT;
        *vlen = ber_int(val, 2);
        return 0;
    case L_IPTTL:
        *asn = ASN_INT;
        *vlen = ber_int(val, 64);
        return 0;
    case L_IP_ADENT_ADDR:
        *asn = ASN_OCT;
        put_ip_oct(val, s->cfg.ip);
        *vlen = 4;
        return 0;
    case L_IP_ADENT_IF:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IP_ADENT_MASK:
        *asn = ASN_OCT;
        put_ip_oct(val, s->cfg.netmask);
        *vlen = 4;
        return 0;
    case L_IP_ADENT_BCAST:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_ICMP_IN:
    case L_ICMP_INERR:
    case L_ICMP_INECHO:
    case L_ICMP_INECHOREP:
    case L_ICMP_OUT:
    case L_ICMP_OUTECHO:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
        return 0;
    case L_UDP_IN:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->udp_in);
        return 0;
    case L_UDP_OUT:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->udp_out);
        return 0;
    case L_UDP_NOPORT:
    case L_UDP_INERR:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
        return 0;
    case L_UDP_LADDR:
        *asn = ASN_OCT;
        memset(val, 0, 4);
        *vlen = 4;
        return 0;
    case L_UDP_LPORT:
        *asn = ASN_INT;
        *vlen = ber_int(val, PN_SNMP_PORT);
        return 0;
    case L_SNMP_IN:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_in_pkts);
        return 0;
    case L_SNMP_OUT:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_out_pkts);
        return 0;
    case L_SNMP_INGET:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_in_get);
        return 0;
    case L_SNMP_INNEXT:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_in_next);
        return 0;
    case L_SNMP_INSET:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_in_set);
        return 0;
    case L_SNMP_OUTRESP:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, s->snmp_out_pkts);
        return 0;
    case L_SNMP_AUTHTRAP:
        *asn = ASN_INT;
        *vlen = ber_int(val, 2);
        return 0;
    case L_IFX_INMCAST:
    case L_IFX_INBCAST:
    case L_IFX_OUTMCAST:
    case L_IFX_OUTBCAST:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
        return 0;
    case L_IFX_HCIN:
        *asn = ASN_COUNTER64;
        *vlen = ber_u64(val, s->if_in_octets);
        return 0;
    case L_IFX_HCOUT:
        *asn = ASN_COUNTER64;
        *vlen = ber_u64(val, s->if_out_octets);
        return 0;
    case L_IFX_TRAP:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFX_HSPEED:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, 100);
        return 0;
    case L_IFX_PROM:
        *asn = ASN_INT;
        *vlen = ber_int(val, 2);
        return 0;
    case L_IFX_CONN:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_IFX_DISC:
        *asn = ASN_TICKS;
        *vlen = ber_uint(val, ASN_TICKS, 0);
        return 0;
    case L_AT_IF:
    case L_IP_NTM_IF:
        *asn = ASN_INT;
        *vlen = ber_int(val, 1);
        return 0;
    case L_AT_PHYS:
    case L_IP_NTM_PHYS:
        *asn = ASN_OCT;
        memcpy(val, s->cfg.mac, 6);
        *vlen = 6;
        return 0;
    case L_AT_NET:
    case L_IP_NTM_NET:
        *asn = ASN_OCT;
        put_ip_oct(val, s->cfg.ip);
        *vlen = 4;
        return 0;
    case L_IP_NTM_TYPE:
        *asn = ASN_INT;
        *vlen = ber_int(val, 3);
        return 0;
    case L_ICMP_INDST:
    case L_ICMP_INTIME:
    case L_ICMP_INPARM:
    case L_ICMP_INQUENCH:
    case L_ICMP_INREDIR:
    case L_ICMP_INTS:
    case L_ICMP_INTSREP:
    case L_ICMP_INMASK:
    case L_ICMP_INMASKREP:
    case L_ICMP_OUTERR:
    case L_ICMP_OUTDST:
    case L_ICMP_OUTTIME:
    case L_ICMP_OUTPARM:
    case L_ICMP_OUTQUENCH:
    case L_ICMP_OUTREDIR:
    case L_ICMP_OUTECHOREP:
    case L_ICMP_OUTTS:
    case L_ICMP_OUTTSREP:
    case L_ICMP_OUTMASK:
    case L_ICMP_OUTMASKREP:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
        return 0;
    case L_TCP_RTOALG:
        *asn = ASN_INT;
        *vlen = ber_int(val, 4);
        return 0;
    case L_TCP_RTOMIN:
        *asn = ASN_INT;
        *vlen = ber_int(val, 200);
        return 0;
    case L_TCP_RTOMAX:
        *asn = ASN_INT;
        *vlen = ber_int(val, 120000);
        return 0;
    case L_TCP_MAXCONN:
        *asn = ASN_INT;
        {
            uint8_t m = 0xff;
            *vlen = ber_tlv(val, ASN_INT, &m, 1);
        }
        return 0;
    case L_TCP_CURRESTAB:
        *asn = ASN_GAUGE;
        *vlen = ber_uint(val, ASN_GAUGE, 0);
        return 0;
    case L_TCP_ACTIVE:
    case L_TCP_PASSIVE:
    case L_TCP_ATTEMPT:
    case L_TCP_ESTABRST:
    case L_TCP_INSEG:
    case L_TCP_OUTSEG:
    case L_TCP_RETRANS:
    case L_TCP_INERR:
    case L_TCP_OUTRST:
        *asn = ASN_COUNTER;
        *vlen = ber_uint(val, ASN_COUNTER, 0);
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
    int best = -1;
    for (int i = 0; i < L_COUNT; i++) {
        if (!leaf_present(s, i)) {
            continue;
        }
        if (oid_cmp(req, rn, k_oids[i], k_oidn[i]) < 0) {
            if (best < 0 ||
                oid_cmp(k_oids[i], k_oidn[i], k_oids[best], k_oidn[best]) <
                    0) {
                best = i;
            }
        }
    }
    return best;
}

#define SNMP_VB_MAX 8

typedef struct {
    uint32_t oid[OID_MAX];
    uint8_t n;
    uint8_t vtag;
    uint8_t vbuf[LEAF_VAL_MAX];
    size_t vlen;
} snmp_vb_t;

static int snmp_parse(const uint8_t *buf, size_t n, int *rid, int *pdu_type,
                      int *ver, snmp_vb_t *vbs, int *nvb, int *nonrep,
                      int *maxrep, char *community, size_t ccap)
{
    if (n < 2 || buf[0] != 0x30) {
        return -1;
    }
    size_t slen = 0, sused = 0;
    if (ber_read_len(buf + 1, n - 1, &slen, &sused) != 0) {
        return -1;
    }
    if (1 + sused + slen > n) {
        return -1;
    }
    n = 1 + sused + slen;
    size_t off = 1 + sused;
    if (off >= n) {
        return -1;
    }
    int version = 0;
    size_t used = 0;
    if (ber_parse_int(buf + off, n - off, &version, &used) != 0) {
        return -1;
    }
    *ver = version;
    off += used;
    if (off >= n || buf[off] != ASN_OCT) {
        return -1;
    }
    size_t clen = 0, cused = 0;
    if (off + 1 >= n ||
        ber_read_len(buf + off + 1, n - off - 1, &clen, &cused) != 0) {
        return -1;
    }
    if (1 + cused + clen > n - off) {
        return -1;
    }
    if (community && ccap > 0) {
        size_t cn = clen < ccap - 1 ? clen : ccap - 1;
        memcpy(community, buf + off + 1 + cused, cn);
        community[cn] = '\0';
    }
    off += 1 + cused + clen;
    if (off >= n) {
        return -1;
    }
    int pt = buf[off];
    if ((pt & 0xF0) != 0xA0) {
        return -1;
    }
    *pdu_type = pt;
    size_t pdulen = 0, pused = 0;
    if (off + 1 >= n ||
        ber_read_len(buf + off + 1, n - off - 1, &pdulen, &pused) != 0) {
        return -1;
    }
    if (1 + pused + pdulen > n - off) {
        return -1;
    }
    n = off + 1 + pused + pdulen;
    off += 1 + pused;
    *rid = 1;
    *nonrep = 0;
    *maxrep = 0;
    if (off < n && ber_parse_int(buf + off, n - off, rid, &used) == 0) {
        off += used;
    }
    int tmp = 0;
    if (off < n && ber_parse_int(buf + off, n - off, &tmp, &used) == 0) {
        *nonrep = tmp;
        off += used;
    }
    if (off < n && ber_parse_int(buf + off, n - off, &tmp, &used) == 0) {
        *maxrep = tmp;
        off += used;
    }
    *nvb = 0;
    if (off < n && buf[off] == 0x30) {
        size_t vblen = 0, vbused = 0;
        if (ber_read_len(buf + off + 1, n - off - 1, &vblen, &vbused) == 0 &&
            1 + vbused + vblen <= n - off) {
            size_t vend = off + 1 + vbused + vblen;
            size_t vo = off + 1 + vbused;
            while (vo < vend && *nvb < SNMP_VB_MAX) {
                if (buf[vo] != 0x30) {
                    break;
                }
                size_t sl = 0, su = 0;
                if (ber_read_len(buf + vo + 1, vend - vo - 1, &sl, &su) != 0) {
                    break;
                }
                size_t so = vo + 1 + su;
                size_t se = so + sl;
                if (se > vend) {
                    break;
                }
                snmp_vb_t *vb = &vbs[*nvb];
                memset(vb, 0, sizeof(*vb));
                vb->vtag = ASN_NULL;
                if (so < se && buf[so] == ASN_OID) {
                    size_t olen = 0, oused = 0;
                    if (ber_read_len(buf + so + 1, se - so - 1, &olen,
                                    &oused) == 0 &&
                        1 + oused + olen <= se - so) {
                        oid_decode(buf + so + 1 + oused, olen, vb->oid,
                                   &vb->n);
                        size_t val_at = so + 1 + oused + olen;
                        if (val_at < se) {
                            vb->vtag = buf[val_at];
                            size_t ln = 0, lused = 0;
                            if (val_at + 1 < se &&
                                ber_read_len(buf + val_at + 1, se - val_at - 1,
                                             &ln, &lused) == 0 &&
                                1 + lused + ln <= se - val_at) {
                                if (ln > LEAF_VAL_MAX) {
                                    ln = LEAF_VAL_MAX;
                                }
                                memcpy(vb->vbuf, buf + val_at + 1 + lused, ln);
                                vb->vlen = ln;
                            }
                        }
                    }
                }
                (*nvb)++;
                vo = se;
            }
        }
    }
    if (*nvb == 0) {
        /* Fallback: first OID anywhere in the PDU (short-form length). */
        const uint8_t *found = NULL;
        size_t found_n = 0;
        size_t found_at = 0;
        for (size_t i = off; i + 2 < n; i++) {
            if (buf[i] == ASN_OID && buf[i + 1] < 128 &&
                i + 2 + buf[i + 1] <= n) {
                found = buf + i + 2;
                found_n = buf[i + 1];
                found_at = i + 2 + found_n;
                break;
            }
        }
        if (found) {
            snmp_vb_t *vb = &vbs[0];
            memset(vb, 0, sizeof(*vb));
            oid_decode(found, found_n, vb->oid, &vb->n);
            vb->vtag = ASN_NULL;
            if (found_at + 2 <= n) {
                vb->vtag = buf[found_at];
                size_t ln = buf[found_at + 1];
                if (!(ln & 0x80) && found_at + 2 + ln <= n) {
                    if (ln > LEAF_VAL_MAX) {
                        ln = LEAF_VAL_MAX;
                    }
                    memcpy(vb->vbuf, buf + found_at + 2, ln);
                    vb->vlen = ln;
                }
            }
            *nvb = 1;
        }
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

static size_t encode_varbind(uint8_t *out, const uint32_t *oid, uint8_t on,
                             int err, uint8_t asn, const uint8_t *val,
                             size_t vlen)
{
    uint8_t inner[192];
    size_t vi = 0;
    uint8_t oidber[48];
    size_t olen = oid_encode(oid, on, oidber);
    vi += ber_tlv(inner + vi, ASN_OID, oidber, olen);
    if (err) {
        vi += ber_tlv(inner + vi, ASN_NULL, NULL, 0);
    } else if (asn == ASN_OCT) {
        vi += ber_tlv(inner + vi, ASN_OCT, val, vlen);
    } else if (asn == ASN_OID) {
        vi += ber_tlv(inner + vi, ASN_OID, val, vlen);
    } else {
        memcpy(inner + vi, val, vlen);
        vi += vlen;
    }
    return wrap_seq(out, inner, vi);
}

static void store_oct(char *dst, size_t cap, const uint8_t *v, size_t n)
{
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, v, n);
    dst[n] = '\0';
}

static int apply_set(pn_stack_t *s, int leaf, uint8_t vtag, const uint8_t *v,
                     size_t n)
{
    if (vtag != ASN_OCT) {
        return -1;
    }
    if (leaf == L_SYSCONTACT) {
        store_oct(s->snmp_syscontact, sizeof(s->snmp_syscontact), v, n);
        return 0;
    }
    if (leaf == L_SYSLOCATION) {
        store_oct(s->snmp_syslocation, sizeof(s->snmp_syslocation), v, n);
        return 0;
    }
    if (leaf == L_SYSNAME) {
        store_oct(s->snmp_sysname, sizeof(s->snmp_sysname), v, n);
        return 0;
    }
    return -1;
}

static int encode_leaf(pn_stack_t *s, const uint32_t *req, uint8_t rn,
                       int is_next, uint8_t *out, size_t cap, size_t *used,
                       uint32_t *walk, uint8_t *wn, int *this_err)
{
    int leaf = is_next ? match_next(s, req, rn) : match_get(s, req, rn);
    uint8_t asn = ASN_NULL;
    uint8_t val[LEAF_VAL_MAX + 16];
    size_t vlen = 0;
    uint32_t out_oid[OID_MAX];
    uint8_t out_n = rn;
    memcpy(out_oid, req, sizeof(uint32_t) * rn);
    *this_err = 0;
    if (leaf >= 0 && leaf_value(s, leaf, &asn, val, &vlen) == 0) {
        memcpy(out_oid, k_oids[leaf], sizeof(uint32_t) * k_oidn[leaf]);
        out_n = k_oidn[leaf];
        if (walk && wn) {
            memcpy(walk, out_oid, sizeof(uint32_t) * out_n);
            *wn = out_n;
        }
    } else {
        *this_err = SNMP_ERR_NOSUCHNAME;
        asn = ASN_NULL;
        vlen = 0;
    }
    size_t n = encode_varbind(out, out_oid, out_n, *this_err, asn, val, vlen);
    if (n > cap) {
        return -ENOSPC;
    }
    *used = n;
    return 0;
}

int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t n, uint8_t *resp,
                   size_t cap, size_t *out_len)
{
    int rid = 1, pdu_type = 0xA0, ver = 0, nonrep = 0, maxrep = 0, nvb = 0;
    snmp_vb_t in_vb[SNMP_VB_MAX];
    char community[64];
    memset(in_vb, 0, sizeof(in_vb));
    community[0] = '\0';
    if (snmp_parse(req, n, &rid, &pdu_type, &ver, in_vb, &nvb, &nonrep,
                   &maxrep, community, sizeof(community)) != 0) {
        return -EINVAL;
    }
    if (community[0] && strcmp(community, "public") != 0) {
        return -EPERM;
    }
    if (nvb < 1) {
        return -EINVAL;
    }
    bind_ip_oids(s);
    s->snmp_in_pkts++;
    int is_bulk = (pdu_type == 0xA5);
    int is_next = (pdu_type == 0xA1 || is_bulk);
    int is_set = (pdu_type == 0xA3);
    if (is_set) {
        s->snmp_in_set++;
    } else if (is_next) {
        s->snmp_in_next++;
    } else {
        s->snmp_in_get++;
    }

    int reps = 1;
    if (is_bulk) {
        reps = maxrep < 1 ? 1 : maxrep;
        if (reps > 8) {
            reps = 8;
        }
        if (nonrep < 0) {
            nonrep = 0;
        }
        if (nonrep > nvb) {
            nonrep = nvb;
        }
    }

    uint8_t vbs[900];
    size_t vbs_n = 0;
    int err = 0;

    if (is_set) {
        int leaf = match_get(s, in_vb[0].oid, in_vb[0].n);
        uint8_t asn = ASN_NULL;
        uint8_t val[LEAF_VAL_MAX + 16];
        size_t vlen = 0;
        uint32_t out_oid[OID_MAX];
        uint8_t out_n = in_vb[0].n;
        memcpy(out_oid, in_vb[0].oid, sizeof(uint32_t) * in_vb[0].n);
        if (leaf >= 0 && leaf_writable(leaf) &&
            apply_set(s, leaf, in_vb[0].vtag, in_vb[0].vbuf, in_vb[0].vlen) ==
                0 &&
            leaf_value(s, leaf, &asn, val, &vlen) == 0) {
            memcpy(out_oid, k_oids[leaf], sizeof(uint32_t) * k_oidn[leaf]);
            out_n = k_oidn[leaf];
        } else if (leaf >= 0) {
            err = SNMP_ERR_READONLY;
            memcpy(out_oid, k_oids[leaf], sizeof(uint32_t) * k_oidn[leaf]);
            out_n = k_oidn[leaf];
            asn = ASN_NULL;
            vlen = 0;
        } else {
            err = SNMP_ERR_NOSUCHNAME;
            asn = ASN_NULL;
            vlen = 0;
        }
        vbs_n += encode_varbind(vbs + vbs_n, out_oid, out_n, err, asn, val,
                                vlen);
    } else if (is_bulk) {
        uint32_t walks[SNMP_VB_MAX][OID_MAX];
        uint8_t wns[SNMP_VB_MAX];
        for (int i = 0; i < nvb; i++) {
            memcpy(walks[i], in_vb[i].oid, sizeof(uint32_t) * in_vb[i].n);
            wns[i] = in_vb[i].n;
        }
        for (int i = 0; i < nonrep; i++) {
            size_t used = 0;
            int this_err = 0;
            if (vbs_n + 208 > sizeof(vbs)) {
                break;
            }
            if (encode_leaf(s, walks[i], wns[i], 1, vbs + vbs_n,
                            sizeof(vbs) - vbs_n, &used, walks[i], &wns[i],
                            &this_err) != 0) {
                break;
            }
            vbs_n += used;
            if (this_err && err == 0) {
                err = this_err;
            }
        }
        int repeating = nvb - nonrep;
        for (int r = 0; r < reps && repeating > 0; r++) {
            int stop = 0;
            for (int i = 0; i < repeating; i++) {
                int idx = nonrep + i;
                size_t used = 0;
                int this_err = 0;
                if (vbs_n + 208 > sizeof(vbs)) {
                    stop = 1;
                    break;
                }
                if (encode_leaf(s, walks[idx], wns[idx], 1, vbs + vbs_n,
                                sizeof(vbs) - vbs_n, &used, walks[idx],
                                &wns[idx], &this_err) != 0) {
                    stop = 1;
                    break;
                }
                vbs_n += used;
                if (this_err) {
                    if (r == 0 && err == 0) {
                        err = this_err;
                    }
                    stop = 1;
                    break;
                }
            }
            if (stop) {
                break;
            }
        }
    } else {
        for (int i = 0; i < nvb; i++) {
            size_t used = 0;
            int this_err = 0;
            if (vbs_n + 208 > sizeof(vbs)) {
                break;
            }
            if (encode_leaf(s, in_vb[i].oid, in_vb[i].n, is_next, vbs + vbs_n,
                            sizeof(vbs) - vbs_n, &used, NULL, NULL,
                            &this_err) != 0) {
                break;
            }
            vbs_n += used;
            if (this_err && err == 0) {
                err = this_err;
            }
        }
    }

    uint8_t vbl[960];
    size_t vbl_n = wrap_seq(vbl, vbs, vbs_n);

    uint8_t pdu_inner[1024];
    size_t p = 0;
    p += ber_int(pdu_inner + p, rid);
    p += ber_int(pdu_inner + p, err);
    p += ber_int(pdu_inner + p, err ? 1 : 0);
    memcpy(pdu_inner + p, vbl, vbl_n);
    p += vbl_n;

    uint8_t pdu[1100];
    size_t pn = 0;
    pdu[pn++] = 0xA2;
    pn += ber_len(pdu + pn, p);
    memcpy(pdu + pn, pdu_inner, p);
    pn += p;

    uint8_t msg_inner[1200];
    size_t m = 0;
    m += ber_int(msg_inner + m, ver);
    m += ber_tlv(msg_inner + m, ASN_OCT, (const uint8_t *)"public", 6);
    memcpy(msg_inner + m, pdu, pn);
    m += pn;

    size_t need = 1 + ber_len_size(m) + m;
    if (need > cap) {
        return -ENOSPC;
    }
    size_t total = wrap_seq(resp, msg_inner, m);
    *out_len = total;
    s->snmp_out_pkts++;
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
    s->udp_in++;
    uint8_t msg[1400];
    size_t mlen = 0;
    if (pn_snmp_handle(s, buf, (size_t)n, msg, sizeof(msg), &mlen) != 0) {
        return;
    }
    sendto(s->fd_snmp, msg, mlen, 0, (struct sockaddr *)&src, sl);
    s->udp_out++;
    (void)errno;
}
