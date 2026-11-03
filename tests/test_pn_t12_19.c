/*
 * T12-19: the SNMP agent must read the request.
 *
 * Before the fix, pn_snmp_handle ignores the datagram and always emits
 * one SNMPv1 GetResponse: request-id 1, community "public", sysName.0.
 * A manager cannot match that response to its request, GetNext never
 * ends, a wrong community is answered, and a non-SNMP payload is
 * reflected (amplification).
 *
 * Also covered here (2026-11-01 audit, same cause, same PR):
 *   - community other than the configured "public" → no response
 *   - non-SNMP UDP payload (deadbeef) → no response
 *   - response version follows the request (v1 = 0, v2c = 1)
 *   - GetNext returns the next implemented OID, or noSuchName (v1) /
 *     endOfMibView (v2c) when there is none
 *
 * The only implemented object is sysName.0 (NameOfStation). Other OIDs
 * are noSuchName on v1 and noSuchObject on v2c. MIB-II interfaces and
 * LLDP-MIB are not this item.
 */
#include "pn_internal.h"
#include "pn_stack.h"

#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static void dump_bytes(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "%02x%s", p[i], (i + 1 == n) ? "" : " ");
    }
    fprintf(stderr, "\n");
}

static const uint8_t k_sysname[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
                                    0x00};
static const uint8_t k_sysdescr[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
                                     0x00};
/* 1.3.6.1.2.1.1.5 — the sysName object, not the .0 instance. */
static const uint8_t k_sysname_obj[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01,
                                        0x05};
/* 1.3.6.1.2.1.1 — system. GetNext's successor is sysName.0. */
static const uint8_t k_system[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01};
/* 1.3.6.1.2.1.1.5.0.1 — past sysName.0. */
static const uint8_t k_past[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00,
                                 0x01};

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

static size_t put_tl(uint8_t *p, uint8_t tag, const uint8_t *v, size_t n)
{
    size_t i = 0;
    p[i++] = tag;
    i += put_len(p + i, n);
    if (n && v) {
        memcpy(p + i, v, n);
    }
    return i + n;
}

static size_t put_int(uint8_t *p, int32_t v)
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
    return put_tl(p, 0x02, b + s, (size_t)(4 - s));
}

typedef struct {
    const uint8_t *oid;
    size_t oid_len;
    const uint8_t *val;
    size_t val_len;
} req_vb_t;

static size_t build_msg(uint8_t *out, int version, const void *comm,
                        size_t comm_len, uint8_t pdu_tag, int32_t req_id,
                        const req_vb_t *vbs, size_t nvb)
{
    uint8_t vbl[512];
    size_t vl = 0;
    for (size_t i = 0; i < nvb; i++) {
        uint8_t one[256];
        size_t on = 0;
        on += put_tl(one + on, 0x06, vbs[i].oid, vbs[i].oid_len);
        if (vbs[i].val) {
            memcpy(one + on, vbs[i].val, vbs[i].val_len);
            on += vbs[i].val_len;
        } else {
            on += put_tl(one + on, 0x05, NULL, 0);
        }
        vl += put_tl(vbl + vl, 0x30, one, on);
    }
    uint8_t vbl_tl[560];
    size_t vbl_n = put_tl(vbl_tl, 0x30, vbl, vl);

    uint8_t pdu_body[700];
    size_t pb = 0;
    pb += put_int(pdu_body + pb, req_id);
    pb += put_int(pdu_body + pb, 0);
    pb += put_int(pdu_body + pb, 0);
    memcpy(pdu_body + pb, vbl_tl, vbl_n);
    pb += vbl_n;
    uint8_t pdu[760];
    size_t pn = put_tl(pdu, pdu_tag, pdu_body, pb);

    uint8_t msg_body[900];
    size_t mb = 0;
    mb += put_int(msg_body + mb, version);
    mb += put_tl(msg_body + mb, 0x04, (const uint8_t *)comm, comm_len);
    memcpy(msg_body + mb, pdu, pn);
    mb += pn;
    return put_tl(out, 0x30, msg_body, mb);
}

static int ber_head(const uint8_t *p, size_t n, uint8_t *tag,
                    const uint8_t **val, size_t *vlen, size_t *total)
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
    if (L > n - i) {
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
    if (n < 4 && (v[0] & 0x80)) {
        u |= 0xffffffffu << (n * 8);
    }
    *out = (int32_t)u;
    return 0;
}

static int oid_text(const uint8_t *v, size_t n, char *dst, size_t cap)
{
    if (n < 1 || cap < 4) {
        return -1;
    }
    size_t i = 0;
    uint32_t sub = 0;
    int first = 1;
    size_t used = 0;
    while (i < n) {
        int guard = 0;
        sub = 0;
        uint8_t c;
        do {
            if (i >= n || guard++ == 5) {
                return -1;
            }
            c = v[i++];
            sub = (sub << 7) | (uint32_t)(c & 0x7f);
        } while (c & 0x80);
        uint32_t arcs[2];
        size_t na = 1;
        if (first) {
            first = 0;
            na = 2;
            if (sub < 40) {
                arcs[0] = 0;
                arcs[1] = sub;
            } else if (sub < 80) {
                arcs[0] = 1;
                arcs[1] = sub - 40;
            } else {
                arcs[0] = 2;
                arcs[1] = sub - 80;
            }
        } else {
            arcs[0] = sub;
        }
        for (size_t a = 0; a < na; a++) {
            int wr = snprintf(dst + used, cap - used, "%s%u",
                              used ? "." : "", arcs[a]);
            if (wr < 0 || (size_t)wr >= cap - used) {
                return -1;
            }
            used += (size_t)wr;
        }
    }
    return 0;
}

#define VIEW_VB_MAX 4

typedef struct {
    int32_t version;
    int32_t req_id;
    int32_t err;
    int32_t idx;
    uint8_t community[32];
    size_t community_len;
    uint8_t pdu_tag;
    size_t nvb;
    char oid[VIEW_VB_MAX][64];
    uint8_t vtag[VIEW_VB_MAX];
    uint8_t vraw[VIEW_VB_MAX][256];
    size_t vlen[VIEW_VB_MAX];
} snmp_view_t;

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

static int parse_response(const uint8_t *msg, size_t n, snmp_view_t *o)
{
    memset(o, 0, sizeof(*o));
    uint8_t tag;
    const uint8_t *val;
    size_t vlen, total;
    if (ber_head(msg, n, &tag, &val, &vlen, &total) != 0 || tag != 0x30 ||
        total != n) {
        return -1;
    }
    const uint8_t *p = val;
    size_t left = vlen;
    if (take_int(&p, &left, &o->version) != 0) {
        return -1;
    }
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || tag != 0x04 ||
        vlen > sizeof(o->community)) {
        return -1;
    }
    memcpy(o->community, val, vlen);
    o->community_len = vlen;
    p += total;
    left -= total;
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || (tag & 0xE0) != 0xA0) {
        return -1;
    }
    if (total != left) {
        return -1;
    }
    o->pdu_tag = tag;
    p = val;
    left = vlen;
    if (take_int(&p, &left, &o->req_id) != 0 ||
        take_int(&p, &left, &o->err) != 0 ||
        take_int(&p, &left, &o->idx) != 0) {
        return -1;
    }
    if (ber_head(p, left, &tag, &val, &vlen, &total) != 0 || tag != 0x30 ||
        total != left) {
        return -1;
    }
    p = val;
    left = vlen;
    while (left > 0) {
        const uint8_t *vb;
        size_t vb_len, vb_total;
        if (o->nvb >= VIEW_VB_MAX ||
            ber_head(p, left, &tag, &vb, &vb_len, &vb_total) != 0 ||
            tag != 0x30) {
            return -1;
        }
        const uint8_t *q = vb;
        size_t ql = vb_len;
        const uint8_t *oidv;
        size_t oidn, oid_total;
        if (ber_head(q, ql, &tag, &oidv, &oidn, &oid_total) != 0 ||
            tag != 0x06) {
            return -1;
        }
        if (oid_text(oidv, oidn, o->oid[o->nvb], sizeof(o->oid[o->nvb])) != 0) {
            return -1;
        }
        q += oid_total;
        ql -= oid_total;
        const uint8_t *vv;
        size_t vn, vt;
        if (ber_head(q, ql, &tag, &vv, &vn, &vt) != 0 || vt != ql) {
            return -1;
        }
        o->vtag[o->nvb] = tag;
        if (vn > sizeof(o->vraw[0])) {
            return -1;
        }
        if (vn) {
            memcpy(o->vraw[o->nvb], vv, vn);
        }
        o->vlen[o->nvb] = vn;
        o->nvb++;
        p += vb_total;
        left -= vb_total;
    }
    return 0;
}

static pn_stack_t *make_stack(const char *name)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    snprintf(cfg.station_name, sizeof(cfg.station_name), "%s", name);
    cfg.mac_set = 1;
    cfg.mac[0] = 0x02;
    cfg.security_class = 0;
    return pn_stack_create(&cfg);
}

static int transact(pn_stack_t *s, const uint8_t *req, size_t n, uint8_t *resp,
                    size_t cap, size_t *rlen)
{
    *rlen = (size_t)-1;
    return pn_stack_handle_snmp(s, req, n, resp, cap, rlen);
}

static void expect_silent(pn_stack_t *s, const uint8_t *req, size_t n,
                          const char *what)
{
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = transact(s, req, n, resp, sizeof(resp), &rlen);
    if (rc != 0 || rlen != 0) {
        fprintf(stderr, "FAIL: %s: rc=%d rlen=%zu (want no response)\n", what,
                rc, rlen);
        if (rlen > 0 && rlen <= sizeof(resp)) {
            fprintf(stderr, "  response: ");
            dump_bytes(resp, rlen);
        }
        g_fail = 1;
    }
}

static int exchange(pn_stack_t *s, const uint8_t *req, size_t n, snmp_view_t *view,
                    const char *what)
{
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = transact(s, req, n, resp, sizeof(resp), &rlen);
    if (rc != 0 || rlen == 0 || parse_response(resp, rlen, view) != 0) {
        fprintf(stderr, "FAIL: %s: rc=%d rlen=%zu (response not a GetResponse)\n",
                what, rc, rlen);
        if (rlen > 0 && rlen <= sizeof(resp)) {
            fprintf(stderr, "  response: ");
            dump_bytes(resp, rlen);
        }
        g_fail = 1;
        return -1;
    }
    if (view->pdu_tag != 0xA2) {
        fprintf(stderr, "FAIL: %s: PDU tag 0x%02x (want GetResponse 0xA2)\n",
                what, view->pdu_tag);
        g_fail = 1;
        return -1;
    }
    return 0;
}

static req_vb_t one_oid(const uint8_t *oid, size_t n)
{
    req_vb_t vb;
    vb.oid = oid;
    vb.oid_len = n;
    vb.val = NULL;
    vb.val_len = 0;
    return vb;
}

static void check_community_public(const snmp_view_t *v, const char *what)
{
    static const char pub[] = "public";
    if (v->community_len != sizeof(pub) - 1 ||
        memcmp(v->community, pub, sizeof(pub) - 1) != 0) {
        fprintf(stderr, "FAIL: %s: community length %zu\n", what,
                v->community_len);
        g_fail = 1;
    }
}

static void test_request_id_echo(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysname, sizeof(k_sysname));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 0x1234, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "request-id 0x1234") != 0) {
        return;
    }
    if (v.req_id != 0x1234) {
        fprintf(stderr, "FAIL: request-id echo: got %d (0x%x), want 0x1234\n",
                v.req_id, (unsigned)v.req_id);
        g_fail = 1;
    }
    expect(v.version == 0, "v1 request echoed version 0");
    expect(v.err == 0, "GET sysName.0 error-status 0");
    expect(v.nvb == 1 && strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") == 0,
           "GET sysName.0 returns that OID");
    expect(v.vtag[0] == 0x04 && v.vlen[0] == 7 &&
               memcmp(v.vraw[0], "press-7", 7) == 0,
           "GET sysName.0 value is NameOfStation");
    check_community_public(&v, "request-id echo");
}

static void test_request_id_high_bit(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysname, sizeof(k_sysname));
    uint8_t req[256];
    int32_t id = (int32_t)0x80000001;
    size_t n = build_msg(req, 0, "public", 6, 0xA0, id, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "request-id 0x80000001") != 0) {
        return;
    }
    if (v.req_id != id) {
        fprintf(stderr,
                "FAIL: high-bit request-id: got %d (0x%x), want 0x80000001\n",
                v.req_id, (unsigned)v.req_id);
        g_fail = 1;
    }
}

static void test_get_unknown_v1(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysdescr, sizeof(k_sysdescr));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 1, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "GET sysDescr.0") != 0) {
        return;
    }
    if (v.err != 2 || v.idx != 1 || v.nvb != 1 ||
        strcmp(v.oid[0], "1.3.6.1.2.1.1.1.0") != 0) {
        fprintf(stderr,
                "FAIL: GET sysDescr.0: error-status %d error-index %d oid %s "
                "(want noSuchName 2, index 1, oid 1.3.6.1.2.1.1.1.0)\n",
                v.err, v.idx, v.nvb ? v.oid[0] : "(none)");
        g_fail = 1;
    }
    expect(v.vtag[0] == 0x05, "noSuchName varbind value stays NULL");
}

static void test_get_unknown_v2c(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysdescr, sizeof(k_sysdescr));
    uint8_t req[256];
    size_t n = build_msg(req, 1, "public", 6, 0xA0, 9, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "v2c GET sysDescr.0") != 0) {
        return;
    }
    if (v.version != 1) {
        fprintf(stderr, "FAIL: v2c GET version: got %d, want 1\n", v.version);
        g_fail = 1;
    }
    if (v.req_id != 9 || v.err != 0 || v.nvb != 1 ||
        strcmp(v.oid[0], "1.3.6.1.2.1.1.1.0") != 0 || v.vtag[0] != 0x80 ||
        v.vlen[0] != 0) {
        fprintf(stderr,
                "FAIL: v2c GET sysDescr.0: id %d err %d oid %s tag 0x%02x "
                "(want id 9, err 0, noSuchObject 0x80)\n",
                v.req_id, v.err, v.nvb ? v.oid[0] : "(none)",
                v.nvb ? v.vtag[0] : 0);
        g_fail = 1;
    }
}

static void test_get_scalar_without_instance(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysname_obj, sizeof(k_sysname_obj));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 3, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "GET sysName (no .0)") != 0) {
        return;
    }
    if (v.err != 2 || strcmp(v.oid[0], "1.3.6.1.2.1.1.5") != 0) {
        fprintf(stderr,
                "FAIL: GET sysName without .0: error-status %d oid %s "
                "(want noSuchName, oid 1.3.6.1.2.1.1.5)\n",
                v.err, v.nvb ? v.oid[0] : "(none)");
        g_fail = 1;
    }
}

static void test_two_varbinds_v1(pn_stack_t *s)
{
    req_vb_t vb[2];
    vb[0] = one_oid(k_sysname, sizeof(k_sysname));
    vb[1] = one_oid(k_sysdescr, sizeof(k_sysdescr));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 4, vb, 2);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "GET two varbinds") != 0) {
        return;
    }
    if (v.err != 2 || v.idx != 2 || v.nvb != 2 ||
        strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") != 0 ||
        strcmp(v.oid[1], "1.3.6.1.2.1.1.1.0") != 0) {
        fprintf(stderr,
                "FAIL: v1 GET mixed varbinds: err %d index %d nvb %zu "
                "(want noSuchName at index 2, both requested OIDs)\n",
                v.err, v.idx, v.nvb);
        g_fail = 1;
    }
}

static void test_community_and_garbage(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysname, sizeof(k_sysname));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "wrong", 5, 0xA0, 1, &vb, 1);
    expect_silent(s, req, n, "community \"wrong\"");

    n = build_msg(req, 0, "Public", 6, 0xA0, 1, &vb, 1);
    expect_silent(s, req, n, "community \"Public\"");

    n = build_msg(req, 0, "publicX", 7, 0xA0, 1, &vb, 1);
    expect_silent(s, req, n, "community \"publicX\"");

    static const uint8_t deadbeef[] = {0xde, 0xad, 0xbe, 0xef};
    expect_silent(s, deadbeef, sizeof(deadbeef), "UDP payload deadbeef");
    expect_silent(s, NULL, 4, "NULL request pointer");
    expect_silent(s, req, 0, "empty datagram");

    static const uint8_t trunc[] = {0x30, 0x10, 0x02, 0x01, 0x00};
    expect_silent(s, trunc, sizeof(trunc), "truncated SEQUENCE");
}

static void test_getnext(pn_stack_t *s)
{
    uint8_t req[256];
    snmp_view_t v;
    req_vb_t vb = one_oid(k_system, sizeof(k_system));
    size_t n = build_msg(req, 0, "public", 6, 0xA1, 11, &vb, 1);
    if (exchange(s, req, n, &v, "GetNext system") != 0) {
        return;
    }
    if (v.err != 0 || v.req_id != 11 || v.nvb != 1 ||
        strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") != 0 || v.vtag[0] != 0x04 ||
        v.vlen[0] != 7 || memcmp(v.vraw[0], "press-7", 7) != 0) {
        fprintf(stderr,
                "FAIL: GetNext(1.3.6.1.2.1.1): err %d id %d oid %s "
                "(want sysName.0 = press-7)\n",
                v.err, v.req_id, v.nvb ? v.oid[0] : "(none)");
        g_fail = 1;
    }

    vb = one_oid(k_sysname_obj, sizeof(k_sysname_obj));
    n = build_msg(req, 0, "public", 6, 0xA1, 12, &vb, 1);
    if (exchange(s, req, n, &v, "GetNext sysName") == 0) {
        expect(v.err == 0 && strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") == 0,
               "GetNext(sysName) returns sysName.0");
    }

    vb = one_oid(k_sysname, sizeof(k_sysname));
    n = build_msg(req, 0, "public", 6, 0xA1, 13, &vb, 1);
    if (exchange(s, req, n, &v, "GetNext sysName.0") == 0) {
        if (v.err != 2 || v.idx != 1 ||
            strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") != 0) {
            fprintf(stderr,
                    "FAIL: GetNext(sysName.0) v1: err %d index %d oid %s "
                    "(want noSuchName)\n",
                    v.err, v.idx, v.nvb ? v.oid[0] : "(none)");
            g_fail = 1;
        }
    }

    vb = one_oid(k_past, sizeof(k_past));
    n = build_msg(req, 0, "public", 6, 0xA1, 14, &vb, 1);
    if (exchange(s, req, n, &v, "GetNext past sysName.0") == 0) {
        if (v.err != 2 || strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0.1") != 0) {
            fprintf(stderr,
                    "FAIL: GetNext(past sysName.0): err %d oid %s "
                    "(want noSuchName, requested OID)\n",
                    v.err, v.nvb ? v.oid[0] : "(none)");
            g_fail = 1;
        }
    }

    vb = one_oid(k_sysname, sizeof(k_sysname));
    n = build_msg(req, 1, "public", 6, 0xA1, 15, &vb, 1);
    if (exchange(s, req, n, &v, "v2c GetNext sysName.0") == 0) {
        if (v.version != 1 || v.err != 0 || v.req_id != 15 ||
            strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") != 0 || v.vtag[0] != 0x82 ||
            v.vlen[0] != 0) {
            fprintf(stderr,
                    "FAIL: v2c GetNext(sysName.0): version %d err %d tag 0x%02x "
                    "oid %s (want version 1, endOfMibView 0x82)\n",
                    v.version, v.err, v.nvb ? v.vtag[0] : 0,
                    v.nvb ? v.oid[0] : "(none)");
            g_fail = 1;
        }
    }
}

static void test_set_readonly(pn_stack_t *s)
{
    static const uint8_t newname[] = {0x04, 0x03, 'n', 'e', 'w'};
    req_vb_t vb;
    vb.oid = k_sysname;
    vb.oid_len = sizeof(k_sysname);
    vb.val = newname;
    vb.val_len = sizeof(newname);
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA3, 21, &vb, 1);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "SET sysName.0") != 0) {
        return;
    }
    if (v.err != 4 || v.idx != 1 || strcmp(s->cfg.station_name, "press-7") != 0) {
        fprintf(stderr,
                "FAIL: SET sysName.0: err %d index %d name \"%s\" "
                "(want readOnly 4, name unchanged)\n",
                v.err, v.idx, s->cfg.station_name);
        g_fail = 1;
    }

    vb = one_oid(k_sysdescr, sizeof(k_sysdescr));
    n = build_msg(req, 0, "public", 6, 0xA3, 22, &vb, 1);
    if (exchange(s, req, n, &v, "SET sysDescr.0") == 0) {
        expect(v.err == 2 && v.idx == 1, "SET unknown OID is noSuchName");
    }

    vb.oid = k_sysname;
    vb.oid_len = sizeof(k_sysname);
    vb.val = newname;
    vb.val_len = sizeof(newname);
    n = build_msg(req, 1, "public", 6, 0xA3, 23, &vb, 1);
    if (exchange(s, req, n, &v, "v2c SET sysName.0") == 0) {
        if (v.version != 1 || v.err != 17 ||
            strcmp(s->cfg.station_name, "press-7") != 0) {
            fprintf(stderr,
                    "FAIL: v2c SET sysName.0: version %d err %d name \"%s\" "
                    "(want version 1, notWritable 17)\n",
                    v.version, v.err, s->cfg.station_name);
            g_fail = 1;
        }
    }
}

static void test_unsupported_pdu(pn_stack_t *s)
{
    req_vb_t vb = one_oid(k_sysname, sizeof(k_sysname));
    uint8_t req[256];
    /* GetResponse must not be reflected (response loop). */
    size_t n = build_msg(req, 0, "public", 6, 0xA2, 1, &vb, 1);
    expect_silent(s, req, n, "incoming GetResponse");
    /* GetBulk is not implemented. Do not answer with a canned sysName. */
    n = build_msg(req, 1, "public", 6, 0xA5, 1, &vb, 1);
    expect_silent(s, req, n, "GetBulk");
}

/* Same bytes as tools/ctt/proto/profinet/pn_plugin.c step_snmp_get. */
static void test_ctt_sysname_request(void)
{
    static const uint8_t k_get[] = {
        0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c,
        0x69, 0x63, 0xa0, 0x1a, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
        0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00};
    pn_stack_t *s = make_stack("sensor-line1");
    expect(s != NULL, "ctt stack");
    if (!s) {
        return;
    }
    snmp_view_t v;
    if (exchange(s, k_get, sizeof(k_get), &v, "CTT snmp_get") == 0) {
        expect(v.version == 0 && v.req_id == 1 && v.err == 0,
               "CTT request-id 1, version 0, noError");
        expect(v.nvb == 1 && strcmp(v.oid[0], "1.3.6.1.2.1.1.5.0") == 0,
               "CTT response contains sysName.0");
        expect(v.vtag[0] == 0x04 && v.vlen[0] == 12 &&
                   memcmp(v.vraw[0], "sensor-line1", 12) == 0,
               "CTT sysName value sensor-line1");
    }
    pn_stack_destroy(s);
}

static void test_long_name_and_toobig(void)
{
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    memset(cfg.station_name, 'n', 200);
    cfg.station_name[200] = '\0';
    cfg.mac_set = 1;
    pn_stack_t *s = pn_stack_create(&cfg);
    expect(s != NULL, "long-name stack");
    if (!s) {
        return;
    }
    req_vb_t vb = one_oid(k_sysname, sizeof(k_sysname));
    uint8_t req[256];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 30, &vb, 1);
    uint8_t resp[512];
    size_t rlen = 0;
    int rc = transact(s, req, n, resp, sizeof(resp), &rlen);
    snmp_view_t v;
    if (rc != 0 || parse_response(resp, rlen, &v) != 0 || v.err != 0 ||
        v.vtag[0] != 0x04 || v.vlen[0] != 200) {
        fprintf(stderr, "FAIL: 200-byte sysName: rc=%d rlen=%zu err=%d vlen=%zu\n",
                rc, rlen, v.err, v.nvb ? v.vlen[0] : 0);
        g_fail = 1;
    }
    rlen = 0;
    rc = transact(s, req, n, resp, 64, &rlen);
    if (rc != 0 || parse_response(resp, rlen, &v) != 0 || v.err != 1 ||
        v.req_id != 30 || v.nvb != 0) {
        fprintf(stderr,
                "FAIL: response that does not fit: rc=%d rlen=%zu err=%d nvb=%zu "
                "(want tooBig, empty varbind list)\n",
                rc, rlen, v.err, v.nvb);
        if (rlen > 0 && rlen <= sizeof(resp)) {
            fprintf(stderr, "  response: ");
            dump_bytes(resp, rlen);
        }
        g_fail = 1;
    }
    pn_stack_destroy(s);
}

static void test_empty_varbind_list(pn_stack_t *s)
{
    uint8_t req[128];
    size_t n = build_msg(req, 0, "public", 6, 0xA0, 40, NULL, 0);
    snmp_view_t v;
    if (exchange(s, req, n, &v, "empty varbind list") != 0) {
        return;
    }
    expect(v.err == 0 && v.idx == 0 && v.nvb == 0 && v.req_id == 40,
           "empty Get varbind list is noError");
}

int main(void)
{
    pn_stack_t *s = make_stack("press-7");
    if (!s) {
        fprintf(stderr, "FAIL: pn_stack_create\n");
        return 1;
    }
    test_request_id_echo(s);
    test_request_id_high_bit(s);
    test_get_unknown_v1(s);
    test_get_unknown_v2c(s);
    test_get_scalar_without_instance(s);
    test_two_varbinds_v1(s);
    test_community_and_garbage(s);
    test_getnext(s);
    test_set_readonly(s);
    test_unsupported_pdu(s);
    test_empty_varbind_list(s);
    pn_stack_destroy(s);
    test_ctt_sysname_request();
    test_long_name_and_toobig();
    if (g_fail) {
        fprintf(stderr, "T12-19 SNMP tests failed\n");
        return 1;
    }
    return 0;
}
