/*
 * SNMPv1 / SNMPv2c agent for the one object this stack already exposes:
 * sysName.0 (1.3.6.1.2.1.1.5.0) = NameOfStation.
 *
 * The configured community is "public". There is no community field on
 * pn_cfg_t; CTT and the oracle both use this string. A different
 * community, a version other than v1 (0) or v2c (1), a malformed BER
 * message, or anything that is not a Get / GetNext / Set is not
 * answered. That includes a non-SNMP UDP payload, which used to be
 * reflected as a GetResponse.
 *
 * Get of an unknown OID is noSuchName (v1) or noSuchObject (v2c).
 * GetNext returns the next implemented OID, or noSuchName / endOfMibView
 * when the request is past the end of this MIB. Set does not change
 * the station name (readOnly / notWritable).
 *
 * MIB-II interfaces and LLDP-MIB are not implemented here. The
 * 2026-11-01 audit left that list to a product-scope decision.
 */
#include "pn_internal.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "logger.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#define SNMP_VB_MAX  32
#define SNMP_OID_MAX 32

#define SNMP_GET     0xA0
#define SNMP_GETNEXT 0xA1
#define SNMP_RESP    0xA2
#define SNMP_SET     0xA3

#define SNMP_NOERROR     0
#define SNMP_TOOBIG      1
#define SNMP_NOSUCHNAME  2
#define SNMP_READONLY    4
#define SNMP_NOACCESS    6
#define SNMP_NOTWRITABLE 17

#define SNMP_NOSUCHOBJECT 0x80
#define SNMP_ENDOFMIBVIEW 0x82

#define VB_RAW     0
#define VB_SYSNAME 1
#define VB_EXCEPT  2

static const uint8_t k_public[] = {'p', 'u', 'b', 'l', 'i', 'c'};
static const uint32_t k_sys_name[] = {1, 3, 6, 1, 2, 1, 1, 5, 0};

static int ber_head(const uint8_t *p, size_t n, uint8_t *tag, const uint8_t **val,
                    size_t *vlen, size_t *total)
{
    if (n < 2) {
        return -1;
    }
    size_t i = 2;
    size_t L;
    if ((p[1] & 0x80) == 0) {
        L = p[1];
    } else {
        size_t nb = (size_t)(p[1] & 0x7f);
        if (nb == 0 || nb > 3 || i + nb > n) {
            return -1;
        }
        L = 0;
        for (size_t k = 0; k < nb; k++) {
            L = (L << 8) | p[i++];
        }
    }
    if (i > n || L > n - i) {
        return -1;
    }
    *tag = p[0];
    *val = p + i;
    *vlen = L;
    *total = i + L;
    return 0;
}

static int parse_i32(const uint8_t *v, size_t n, int32_t *out)
{
    if (n < 1 || n > 4) {
        return -1;
    }
    uint32_t u = 0;
    for (size_t i = 0; i < n; i++) {
        u = (u << 8) | v[i];
    }
    if (n < 4 && (v[0] & 0x80) != 0) {
        static const uint32_t fill[] = {0, 0xffffff00u, 0xffff0000u, 0xff000000u};
        u |= fill[n];
    }
    *out = (int32_t)u;
    return 0;
}

static int parse_oid(const uint8_t *v, size_t n, uint32_t *arcs, size_t cap,
                     size_t *narc)
{
    if (n < 1) {
        return -1;
    }
    size_t na = 0;
    size_t i = 0;
    int first = 1;
    while (i < n) {
        uint32_t sub = 0;
        int guard = 0;
        uint8_t c;
        do {
            if (i >= n || ++guard > 5) {
                return -1;
            }
            c = v[i++];
            if (sub > (0xffffffffu >> 7)) {
                return -1;
            }
            sub = (sub << 7) | (uint32_t)(c & 0x7f);
        } while ((c & 0x80) != 0);
        if (first) {
            first = 0;
            if (na + 2 > cap) {
                return -1;
            }
            if (sub < 40) {
                arcs[na++] = 0;
                arcs[na++] = sub;
            } else if (sub < 80) {
                arcs[na++] = 1;
                arcs[na++] = sub - 40;
            } else {
                arcs[na++] = 2;
                arcs[na++] = sub - 80;
            }
        } else {
            if (na >= cap) {
                return -1;
            }
            arcs[na++] = sub;
        }
    }
    if (na < 2) {
        return -1;
    }
    *narc = na;
    return 0;
}

static int oid_cmp(const uint32_t *a, size_t na, const uint32_t *b, size_t nb)
{
    size_t n = na < nb ? na : nb;
    for (size_t i = 0; i < n; i++) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    if (na < nb) {
        return -1;
    }
    if (na > nb) {
        return 1;
    }
    return 0;
}

static int mib_exact(const uint32_t *arcs, size_t n)
{
    if (oid_cmp(arcs, n, k_sys_name, sizeof(k_sys_name) / sizeof(k_sys_name[0])) ==
        0) {
        return 0;
    }
    return -1;
}

/* Smallest implemented OID strictly greater than the request. */
static int mib_next(const uint32_t *arcs, size_t n)
{
    if (oid_cmp(k_sys_name, sizeof(k_sys_name) / sizeof(k_sys_name[0]), arcs, n) >
        0) {
        return 0;
    }
    return -1;
}

typedef struct {
    uint32_t arcs[SNMP_OID_MAX];
    size_t narc;
    const uint8_t *raw;
    size_t raw_len;
    uint8_t kind;
    uint8_t except_tag;
} vb_out_t;

typedef struct {
    int32_t version;
    int32_t req_id;
    int32_t err;
    int32_t idx;
    const uint8_t *community;
    size_t community_len;
    size_t nvb;
    vb_out_t vb[SNMP_VB_MAX];
} rsp_t;

typedef struct {
    uint8_t *p;
    size_t cap;
    size_t n;
    int err;
} wr_t;

static void wr_bytes(wr_t *w, const uint8_t *b, size_t n)
{
    if (w->err) {
        return;
    }
    if (n > w->cap - w->n) {
        w->err = 1;
        return;
    }
    if (n && b) {
        memcpy(w->p + w->n, b, n);
    }
    w->n += n;
}

static void wr_u8(wr_t *w, uint8_t v)
{
    wr_bytes(w, &v, 1);
}

static size_t put_len(uint8_t *p, size_t n)
{
    if (n < 128) {
        p[0] = (uint8_t)n;
        return 1;
    }
    if (n <= 0xff) {
        p[0] = 0x81;
        p[1] = (uint8_t)n;
        return 2;
    }
    p[0] = 0x82;
    p[1] = (uint8_t)(n >> 8);
    p[2] = (uint8_t)n;
    return 3;
}

static size_t wr_begin(wr_t *w)
{
    size_t at = w->n;
    static const uint8_t hole[4] = {0, 0, 0, 0};
    wr_bytes(w, hole, sizeof(hole));
    return at;
}

static void wr_end(wr_t *w, size_t at, uint8_t tag)
{
    if (w->err || at + 4 > w->n) {
        w->err = 1;
        return;
    }
    size_t body = w->n - (at + 4);
    uint8_t lenb[3];
    size_t ln = put_len(lenb, body);
    size_t hdr = 1 + ln;
    size_t pad = 4 - hdr;
    memmove(w->p + at + hdr, w->p + at + 4, body);
    w->p[at] = tag;
    memcpy(w->p + at + 1, lenb, ln);
    w->n -= pad;
}

static void wr_int(wr_t *w, int32_t v)
{
    uint32_t u = (uint32_t)v;
    uint8_t b[4];
    b[0] = (uint8_t)(u >> 24);
    b[1] = (uint8_t)(u >> 16);
    b[2] = (uint8_t)(u >> 8);
    b[3] = (uint8_t)u;
    int s = 0;
    if (v >= 0) {
        while (s < 3 && b[s] == 0 && (b[s + 1] & 0x80) == 0) {
            s++;
        }
    } else {
        while (s < 3 && b[s] == 0xff && (b[s + 1] & 0x80) != 0) {
            s++;
        }
    }
    size_t at = wr_begin(w);
    wr_bytes(w, b + s, (size_t)(4 - s));
    wr_end(w, at, 0x02);
}

static int put_base128(uint8_t *p, size_t cap, uint32_t v, size_t *n)
{
    uint8_t tmp[5];
    int i = 5;
    tmp[--i] = (uint8_t)(v & 0x7f);
    v >>= 7;
    while (v > 0) {
        if (i == 0) {
            return -1;
        }
        tmp[--i] = (uint8_t)((v & 0x7f) | 0x80);
        v >>= 7;
    }
    size_t len = (size_t)(5 - i);
    if (len > cap) {
        return -1;
    }
    memcpy(p, tmp + i, len);
    *n = len;
    return 0;
}

static void wr_oid(wr_t *w, const uint32_t *arcs, size_t narc)
{
    uint8_t body[128];
    size_t n = 0;
    if (narc < 2 || arcs[0] > 2) {
        w->err = 1;
        return;
    }
    uint64_t first = (uint64_t)arcs[0] * 40u + arcs[1];
    if (first > 0xffffffffu) {
        w->err = 1;
        return;
    }
    size_t piece = 0;
    if (put_base128(body, sizeof(body), (uint32_t)first, &piece) != 0) {
        w->err = 1;
        return;
    }
    n = piece;
    for (size_t i = 2; i < narc; i++) {
        if (put_base128(body + n, sizeof(body) - n, arcs[i], &piece) != 0) {
            w->err = 1;
            return;
        }
        n += piece;
    }
    size_t at = wr_begin(w);
    wr_bytes(w, body, n);
    wr_end(w, at, 0x06);
}

static void wr_sysname(wr_t *w, const pn_stack_t *s)
{
    size_t nlen = strnlen(s->cfg.station_name, PN_STATION_NAME_MAX);
    size_t at = wr_begin(w);
    wr_bytes(w, (const uint8_t *)s->cfg.station_name, nlen);
    wr_end(w, at, 0x04);
}

static void wr_except(wr_t *w, uint8_t tag)
{
    wr_u8(w, tag);
    wr_u8(w, 0);
}

static int encode_rsp(const pn_stack_t *s, const rsp_t *r, uint8_t *dst, size_t cap,
                      size_t *out)
{
    wr_t w = {.p = dst, .cap = cap, .n = 0, .err = 0};
    size_t msg = wr_begin(&w);
    wr_int(&w, r->version);
    size_t comm = wr_begin(&w);
    wr_bytes(&w, r->community, r->community_len);
    wr_end(&w, comm, 0x04);
    size_t pdu = wr_begin(&w);
    wr_int(&w, r->req_id);
    wr_int(&w, r->err);
    wr_int(&w, r->idx);
    size_t list = wr_begin(&w);
    for (size_t i = 0; i < r->nvb; i++) {
        const vb_out_t *vb = &r->vb[i];
        size_t one = wr_begin(&w);
        wr_oid(&w, vb->arcs, vb->narc);
        if (vb->kind == VB_SYSNAME) {
            wr_sysname(&w, s);
        } else if (vb->kind == VB_EXCEPT) {
            wr_except(&w, vb->except_tag);
        } else {
            wr_bytes(&w, vb->raw, vb->raw_len);
        }
        wr_end(&w, one, 0x30);
    }
    wr_end(&w, list, 0x30);
    wr_end(&w, pdu, SNMP_RESP);
    wr_end(&w, msg, 0x30);
    if (w.err) {
        return -1;
    }
    *out = w.n;
    return 0;
}

static void keep_raw(vb_out_t *vb)
{
    vb->kind = VB_RAW;
}

static void use_sysname(vb_out_t *vb)
{
    vb->narc = sizeof(k_sys_name) / sizeof(k_sys_name[0]);
    memcpy(vb->arcs, k_sys_name, sizeof(k_sys_name));
    vb->kind = VB_SYSNAME;
}

static void fill_get(rsp_t *r)
{
    if (r->version == 0) {
        for (size_t i = 0; i < r->nvb; i++) {
            if (mib_exact(r->vb[i].arcs, r->vb[i].narc) < 0) {
                r->err = SNMP_NOSUCHNAME;
                r->idx = (int32_t)i + 1;
                for (size_t j = 0; j < r->nvb; j++) {
                    keep_raw(&r->vb[j]);
                }
                return;
            }
        }
        r->err = SNMP_NOERROR;
        r->idx = 0;
        for (size_t i = 0; i < r->nvb; i++) {
            use_sysname(&r->vb[i]);
        }
        return;
    }
    r->err = SNMP_NOERROR;
    r->idx = 0;
    for (size_t i = 0; i < r->nvb; i++) {
        if (mib_exact(r->vb[i].arcs, r->vb[i].narc) < 0) {
            r->vb[i].kind = VB_EXCEPT;
            r->vb[i].except_tag = SNMP_NOSUCHOBJECT;
        } else {
            use_sysname(&r->vb[i]);
        }
    }
}

static void fill_getnext(rsp_t *r)
{
    if (r->version == 0) {
        for (size_t i = 0; i < r->nvb; i++) {
            if (mib_next(r->vb[i].arcs, r->vb[i].narc) < 0) {
                r->err = SNMP_NOSUCHNAME;
                r->idx = (int32_t)i + 1;
                for (size_t j = 0; j < r->nvb; j++) {
                    keep_raw(&r->vb[j]);
                }
                return;
            }
        }
        r->err = SNMP_NOERROR;
        r->idx = 0;
        for (size_t i = 0; i < r->nvb; i++) {
            use_sysname(&r->vb[i]);
        }
        return;
    }
    r->err = SNMP_NOERROR;
    r->idx = 0;
    for (size_t i = 0; i < r->nvb; i++) {
        if (mib_next(r->vb[i].arcs, r->vb[i].narc) < 0) {
            r->vb[i].kind = VB_EXCEPT;
            r->vb[i].except_tag = SNMP_ENDOFMIBVIEW;
        } else {
            use_sysname(&r->vb[i]);
        }
    }
}

static void fill_set(rsp_t *r)
{
    r->idx = 0;
    r->err = SNMP_NOERROR;
    for (size_t i = 0; i < r->nvb; i++) {
        keep_raw(&r->vb[i]);
        if (mib_exact(r->vb[i].arcs, r->vb[i].narc) < 0) {
            r->err = (r->version == 0) ? SNMP_NOSUCHNAME : SNMP_NOACCESS;
            r->idx = (int32_t)i + 1;
            return;
        }
        r->err = (r->version == 0) ? SNMP_READONLY : SNMP_NOTWRITABLE;
        r->idx = (int32_t)i + 1;
        return;
    }
}

static int take_int(const uint8_t **p, size_t *n, int32_t *out)
{
    uint8_t tag;
    const uint8_t *val;
    size_t vlen, total;
    if (ber_head(*p, *n, &tag, &val, &vlen, &total) != 0 || tag != 0x02) {
        return -1;
    }
    if (parse_i32(val, vlen, out) != 0) {
        return -1;
    }
    *p += total;
    *n -= total;
    return 0;
}

/* 0 = built a response, 1 = well-formed but not answered, -1 = not SNMP. */
static int parse_request(const uint8_t *req, size_t len, rsp_t *r, int *too_many)
{
    memset(r, 0, sizeof(*r));
    *too_many = 0;
    uint8_t tag;
    const uint8_t *val;
    size_t vlen, total;
    if (ber_head(req, len, &tag, &val, &vlen, &total) != 0 || tag != 0x30 ||
        total != len) {
        return -1;
    }
    const uint8_t *p = val;
    size_t left = vlen;
    if (take_int(&p, &left, &r->version) != 0 ||
        (r->version != 0 && r->version != 1)) {
        return -1;
    }
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || tag != 0x04) {
        return -1;
    }
    r->community = val;
    r->community_len = vlen;
    p += total;
    left -= total;
    if (vlen != sizeof(k_public) || memcmp(val, k_public, sizeof(k_public)) != 0) {
        return 1;
    }
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || total != left) {
        return -1;
    }
    if (tag != SNMP_GET && tag != SNMP_GETNEXT && tag != SNMP_SET) {
        return 1;
    }
    uint8_t pdu = tag;
    p = val;
    left = vlen;
    if (take_int(&p, &left, &r->req_id) != 0 ||
        take_int(&p, &left, &r->err) != 0 ||
        take_int(&p, &left, &r->idx) != 0) {
        return -1;
    }
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || tag != 0x30 ||
        total != left) {
        return -1;
    }
    p = val;
    left = vlen;
    while (left > 0) {
        if (r->nvb >= SNMP_VB_MAX) {
            *too_many = 1;
            return 0;
        }
        const uint8_t *body;
        size_t body_len, body_total;
        if (ber_head(p, left, &tag, &body, &body_len, &body_total) != 0 ||
            tag != 0x30) {
            return -1;
        }
        const uint8_t *q = body;
        size_t ql = body_len;
        const uint8_t *oidv;
        size_t oidn, oid_total;
        if (ber_head(q, ql, &tag, &oidv, &oidn, &oid_total) != 0 || tag != 0x06) {
            return -1;
        }
        vb_out_t *vb = &r->vb[r->nvb];
        if (parse_oid(oidv, oidn, vb->arcs, SNMP_OID_MAX, &vb->narc) != 0) {
            return -1;
        }
        q += oid_total;
        ql -= oid_total;
        if (ql < 2) {
            return -1;
        }
        /* Keep the value TLV exactly, for error responses. */
        vb->raw = q;
        vb->raw_len = ql;
        size_t value_total = 0;
        if (ber_head(q, ql, &tag, &oidv, &oidn, &value_total) != 0 ||
            value_total != ql) {
            return -1;
        }
        (void)tag;
        r->nvb++;
        p += body_total;
        left -= body_total;
    }
    if (pdu == SNMP_GET) {
        fill_get(r);
    } else if (pdu == SNMP_GETNEXT) {
        fill_getnext(r);
    } else {
        fill_set(r);
    }
    return 0;
}

static int emit(const pn_stack_t *s, rsp_t *r, uint8_t *resp, size_t cap,
                size_t *out_len)
{
    if (encode_rsp(s, r, resp, cap, out_len) == 0) {
        return 0;
    }
    r->err = SNMP_TOOBIG;
    r->idx = 0;
    r->nvb = 0;
    if (encode_rsp(s, r, resp, cap, out_len) == 0) {
        return 0;
    }
    *out_len = 0;
    LOG_WARN("pn_snmp", "SNMP response does not fit in %zu bytes", cap);
    return -ENOSPC;
}

int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t len, uint8_t *resp,
                   size_t cap, size_t *out_len)
{
    if (!s || !resp || !out_len) {
        return -EINVAL;
    }
    *out_len = 0;
    if (!req || len == 0 || cap == 0) {
        return 0;
    }
    rsp_t rsp;
    int too_many = 0;
    int pr = parse_request(req, len, &rsp, &too_many);
    if (pr != 0) {
        return 0;
    }
    if (too_many) {
        rsp.err = SNMP_TOOBIG;
        rsp.idx = 0;
        rsp.nvb = 0;
    }
    return emit(s, &rsp, resp, cap, out_len);
}

void pn_snmp_poll(pn_stack_t *s)
{
    if (!s || s->fd_snmp < 0) {
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
    uint8_t msg[1500];
    size_t m = 0;
    if (pn_snmp_handle(s, buf, (size_t)n, msg, sizeof(msg), &m) == 0 && m > 0) {
        sendto(s->fd_snmp, msg, m, 0, (struct sockaddr *)&src, sl);
    }
}
