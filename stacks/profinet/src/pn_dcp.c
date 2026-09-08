#include "pn_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "pn_endian.h"

typedef struct {
    uint8_t *p;
    size_t cap;
    size_t n;
} wr_t;

static int wr_ok(wr_t *w, size_t add)
{
    return w->n + add <= w->cap;
}

static void wr_u8(wr_t *w, uint8_t v)
{
    if (wr_ok(w, 1)) {
        w->p[w->n++] = v;
    } else {
        w->n = w->cap + 1;
    }
}

static void wr_be16(wr_t *w, uint16_t v)
{
    wr_u8(w, (uint8_t)(v >> 8));
    wr_u8(w, (uint8_t)v);
}

static void wr_bytes(wr_t *w, const void *s, size_t n)
{
    if (!wr_ok(w, n)) {
        w->n = w->cap + 1;
        return;
    }
    memcpy(w->p + w->n, s, n);
    w->n += n;
}

static void wr_pad_even(wr_t *w, size_t payload_len)
{
    if (payload_len & 1u) {
        wr_u8(w, 0);
    }
}

static void wr_block(wr_t *w, uint8_t opt, uint8_t sub, const void *data,
                     size_t dlen)
{
    wr_u8(w, opt);
    wr_u8(w, sub);
    wr_be16(w, (uint16_t)dlen);
    wr_bytes(w, data, dlen);
    wr_pad_even(w, dlen);
}

static int parse_hdr(const uint8_t *p, size_t n, uint16_t *fid, uint8_t *sid,
                     uint8_t *st, uint32_t *xid, uint16_t *delay,
                     uint16_t *dlen, const uint8_t **blocks)
{
    if (n < 10) {
        return -EINVAL;
    }
    *fid = pn_rd_be16(p);
    *sid = p[2];
    *st = p[3];
    *xid = pn_rd_be32(p + 4);
    *delay = pn_rd_be16(p + 8);
    if (n < 12) {
        return -EINVAL;
    }
    *dlen = pn_rd_be16(p + 10);
    *blocks = p + 12;
    if (12u + *dlen > n) {
        return -EINVAL;
    }
    return 0;
}

static int extract_hmac_and_body(const uint8_t *payload, size_t plen,
                                 uint8_t mac[PN_HMAC_LEN], uint8_t *body,
                                 size_t *body_len)
{
    uint16_t fid, dlen, delay;
    uint8_t sid, st;
    uint32_t xid;
    const uint8_t *blocks;
    if (parse_hdr(payload, plen, &fid, &sid, &st, &xid, &delay, &dlen,
                  &blocks) != 0) {
        return -EINVAL;
    }

    uint8_t rebuilt[PN_FRAME_MAX];
    wr_t w = {rebuilt, sizeof(rebuilt), 0};
    wr_be16(&w, fid);
    wr_u8(&w, sid);
    wr_u8(&w, st);
    wr_bytes(&w, payload + 4, 4);
    wr_be16(&w, delay);
    size_t dlen_off = w.n;
    wr_be16(&w, 0);

    int have_mac = 0;
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t opt = blocks[off];
        uint8_t sub = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            return -EINVAL;
        }
        if (opt == PN_DCP_OPT_SEC && sub == PN_DCP_SUB_SEC_HMAC) {
            if (bl != PN_HMAC_LEN) {
                return -EINVAL;
            }
            memcpy(mac, blocks + off + 4, PN_HMAC_LEN);
            have_mac = 1;
        } else {
            wr_bytes(&w, blocks + off, total);
        }
        off += total;
    }
    if (!have_mac) {
        return -ENOENT;
    }
    uint16_t new_dlen = (uint16_t)(w.n - 12);
    pn_wr_be16(rebuilt + dlen_off, new_dlen);
    memcpy(body, rebuilt, w.n);
    *body_len = w.n;
    return 0;
}

int pn_dcp_verify_set(const pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (s->cfg.security_class < PN_SECURITY_CLASS_1) {
        return 0;
    }
    uint8_t mac[PN_HMAC_LEN];
    uint8_t body[PN_FRAME_MAX];
    size_t body_len = 0;
    if (extract_hmac_and_body(payload, plen, mac, body, &body_len) != 0) {
        return -EPERM;
    }
    return pn_sec_ok(s, body, body_len, mac) ? 0 : -EPERM;
}

static int name_eq(const char *a, const uint8_t *b, size_t bn)
{
    size_t an = strlen(a);
    if (an != bn) {
        return 0;
    }
    for (size_t i = 0; i < an; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

static int identify_match(const pn_stack_t *s, const uint8_t *blocks,
                          uint16_t dlen)
{
    int saw_all = 0;
    int saw_specific = 0;
    int ok = 1;
    size_t off = 0;
    if (dlen == 0) {
        return 1;
    }
    while (off + 4 <= dlen) {
        uint8_t opt = blocks[off];
        uint8_t sub = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        const uint8_t *data = blocks + off + 4;
        if (opt == PN_DCP_OPT_ALL && sub == 0xFF) {
            saw_all = 1;
        } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME) {
            saw_specific = 1;
            if (!name_eq(s->cfg.station_name, data, bl)) {
                ok = 0;
            }
        } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_ID &&
                   bl >= 4) {
            saw_specific = 1;
            uint16_t vid = pn_rd_be16(data);
            uint16_t did = pn_rd_be16(data + 2);
            if (vid != s->cfg.vendor_id || did != s->cfg.device_id) {
                ok = 0;
            }
        }
        off += total;
    }
    if (!ok) {
        return 0;
    }
    /* AllSelector, matching Name/DeviceID, or empty filter (= all).
     * Unrecognized-only filters must not elicit a response. */
    return saw_all || saw_specific;
}

static int dcp_ar_write_protect(const pn_stack_t *s)
{
    return s->ar.cm_state != PN_CM_OFFLINE;
}

static int dcp_is_name_or_ip(uint8_t opt, uint8_t sub)
{
    return (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME) ||
           (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM);
}

static int apply_blocks(pn_stack_t *s, const uint8_t *blocks, uint16_t dlen)
{
    int ip_changed = 0;
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t opt = blocks[off];
        uint8_t sub = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        const uint8_t *data = blocks + off + 4;
        const uint8_t *val = (bl >= 2) ? data + 2 : data;
        size_t vlen = (bl >= 2) ? (size_t)bl - 2 : 0;

        if (dcp_is_name_or_ip(opt, sub) && dcp_ar_write_protect(s)) {
            LOG_WARN("pn_dcp",
                     "AR active: DCP Set Name/IP 거부 (SC1 write protect)");
        } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME &&
                   vlen > 0) {
            size_t n = vlen < PN_STATION_NAME_MAX ? vlen : PN_STATION_NAME_MAX;
            memcpy(s->cfg.station_name, val, n);
            s->cfg.station_name[n] = '\0';
            LOG_INFO("pn_dcp", "NameOfStation=%s", s->cfg.station_name);
        } else if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM &&
                   vlen >= 12) {
            s->cfg.ip = pn_rd_be32(val);
            s->cfg.netmask = pn_rd_be32(val + 4);
            s->cfg.gateway = pn_rd_be32(val + 8);
            ip_changed = 1;
            LOG_INFO("pn_dcp", "IP set %u.%u.%u.%u",
                     (s->cfg.ip >> 24) & 0xff, (s->cfg.ip >> 16) & 0xff,
                     (s->cfg.ip >> 8) & 0xff, s->cfg.ip & 0xff);
        }
        off += total;
    }
    return ip_changed;
}

static void emit_prop(const pn_stack_t *s, wr_t *w, uint8_t opt, uint8_t sub)
{
    if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_TYPE) {
        wr_block(w, opt, sub, s->cfg.device_type, strlen(s->cfg.device_type));
    } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME) {
        wr_block(w, opt, sub, s->cfg.station_name, strlen(s->cfg.station_name));
    } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_ID) {
        uint8_t devid[4];
        pn_wr_be16(devid, s->cfg.vendor_id);
        pn_wr_be16(devid + 2, s->cfg.device_id);
        wr_block(w, opt, sub, devid, 4);
    } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_ROLE) {
        uint8_t role = 0x02;
        wr_block(w, opt, sub, &role, 1);
    } else if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM) {
        uint8_t ipb[12];
        pn_wr_be32(ipb, s->cfg.ip);
        pn_wr_be32(ipb + 4, s->cfg.netmask);
        pn_wr_be32(ipb + 8, s->cfg.gateway);
        wr_block(w, opt, sub, ipb, 12);
    } else if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_MAC) {
        wr_block(w, opt, sub, s->cfg.mac, 6);
    } else if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_OPTS) {
        uint8_t opts[] = {PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, PN_DCP_OPT_DEV,
                          PN_DCP_SUB_DEV_NAME};
        wr_block(w, opt, sub, opts, sizeof(opts));
    }
}

static size_t build_identify_blocks(const pn_stack_t *s, uint8_t *out,
                                    size_t cap)
{
    wr_t w = {out, cap, 0};
    emit_prop(s, &w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_TYPE);
    emit_prop(s, &w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME);
    emit_prop(s, &w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ID);
    emit_prop(s, &w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ROLE);
    emit_prop(s, &w, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM);
    emit_prop(s, &w, PN_DCP_OPT_IP, PN_DCP_SUB_IP_MAC);
    emit_prop(s, &w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_OPTS);
    return w.n <= cap ? w.n : 0;
}

static size_t build_get_blocks(const pn_stack_t *s, const uint8_t *req,
                               uint16_t dlen, uint8_t *out, size_t cap)
{
    wr_t w = {out, cap, 0};
    int any = 0;
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t opt = req[off];
        uint8_t sub = req[off + 1];
        uint16_t bl = pn_rd_be16(req + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        size_t before = w.n;
        emit_prop(s, &w, opt, sub);
        if (w.n != before) {
            any = 1;
        }
        off += total;
    }
    if (!any) {
        return build_identify_blocks(s, out, cap);
    }
    return w.n <= cap ? w.n : 0;
}

static size_t build_set_ack(const pn_stack_t *s, const uint8_t *req,
                            uint16_t dlen, uint8_t *out, size_t cap)
{
    wr_t w = {out, cap, 0};
    int any = 0;
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t opt = req[off];
        uint8_t sub = req[off + 1];
        uint16_t bl = pn_rd_be16(req + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        if (!(opt == PN_DCP_OPT_SEC && sub == PN_DCP_SUB_SEC_HMAC)) {
            uint8_t blkerr = 0x00;
            if (dcp_is_name_or_ip(opt, sub) && dcp_ar_write_protect(s)) {
                blkerr = PN_DCP_BLOCK_ERROR_SET_NOT_POSSIBLE;
            }
            wr_u8(&w, PN_DCP_OPT_CTRL);
            wr_u8(&w, PN_DCP_SUB_CTRL_RESP);
            wr_be16(&w, 3);
            wr_u8(&w, opt);
            wr_u8(&w, sub);
            wr_u8(&w, blkerr);
            wr_u8(&w, 0);
            any = 1;
        }
        off += total;
    }
    if (!any) {
        wr_u8(&w, PN_DCP_OPT_CTRL);
        wr_u8(&w, PN_DCP_SUB_CTRL_RESP);
        wr_be16(&w, 3);
        wr_u8(&w, PN_DCP_OPT_DEV);
        wr_u8(&w, PN_DCP_SUB_DEV_NAME);
        wr_u8(&w, 0x00);
        wr_u8(&w, 0);
    }
    return w.n <= cap ? w.n : 0;
}

static void send_dcp(pn_stack_t *s, const uint8_t dst[6], uint16_t fid,
                     uint8_t sid, uint8_t st, uint32_t xid, uint16_t delay,
                     const uint8_t *blocks, size_t blen)
{
    uint8_t pay[PN_FRAME_MAX];
    wr_t w = {pay, sizeof(pay), 0};
    wr_be16(&w, fid);
    wr_u8(&w, sid);
    wr_u8(&w, st);
    uint8_t xidb[4];
    pn_wr_be32(xidb, xid);
    wr_bytes(&w, xidb, 4);
    wr_be16(&w, delay);
    wr_be16(&w, (uint16_t)blen);
    wr_bytes(&w, blocks, blen);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), dst, s->cfg.mac,
                               PN_ETHTYPE_PN, pay, w.n);
    if (flen) {
        pn_eth_send(s, frame, flen);
    }
}

void pn_dcp_send_hello(pn_stack_t *s)
{
    static const uint8_t hello_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
    uint8_t b[512];
    size_t n = build_identify_blocks(s, b, sizeof(b));
    if (!n) {
        return;
    }
    send_dcp(s, hello_mc, PN_FRAMEID_DCP_HELLO, PN_DCP_HELLO, PN_DCP_REQ,
             (uint32_t)(pn_now_ns() & 0xffffffffu), 0, b, n);
}

void pn_dcp_on_frame(pn_stack_t *s, const uint8_t *src, const uint8_t *payload,
                     size_t plen)
{
    uint16_t fid, dlen, delay;
    uint8_t sid, st;
    uint32_t xid;
    const uint8_t *blocks;
    if (parse_hdr(payload, plen, &fid, &sid, &st, &xid, &delay, &dlen,
                  &blocks) != 0) {
        return;
    }
    if (st != PN_DCP_REQ) {
        return;
    }

    if (sid == PN_DCP_IDENTIFY &&
        (fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_GETSET)) {
        if (!identify_match(s, blocks, dlen)) {
            return;
        }
        uint8_t b[512];
        size_t n = build_identify_blocks(s, b, sizeof(b));
        send_dcp(s, src, PN_FRAMEID_DCP_ID_RES, PN_DCP_IDENTIFY,
                 PN_DCP_RESP_SUCCESS, xid, 0, b, n);
        return;
    }

    if (sid == PN_DCP_GET) {
        uint8_t b[512];
        size_t n = build_get_blocks(s, blocks, dlen, b, sizeof(b));
        send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_GET,
                 PN_DCP_RESP_SUCCESS, xid, 0, b, n);
        return;
    }

    if (sid == PN_DCP_SET) {
        if (pn_dcp_verify_set(s, payload, plen) != 0) {
            LOG_WARN("pn_dcp", "unsigned/invalid DCP Set 거부");
            uint8_t err[8];
            wr_t w = {err, sizeof(err), 0};
            wr_u8(&w, PN_DCP_OPT_CTRL);
            wr_u8(&w, PN_DCP_SUB_CTRL_RESP);
            wr_be16(&w, 3);
            wr_u8(&w, PN_DCP_OPT_SEC);
            wr_u8(&w, PN_DCP_SUB_SEC_HMAC);
            wr_u8(&w, 0x03);
            wr_u8(&w, 0);
            send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_SET,
                     PN_DCP_RESP_UNSUP, xid, 0, err, w.n);
            return;
        }
        int ip_changed = apply_blocks(s, blocks, dlen);
        if (ip_changed && s->cfg.apply_os_ip) {
            pn_if_apply_ipv4(s->cfg.iface, s->cfg.ip, s->cfg.netmask,
                             s->cfg.gateway);
        }
        if (ip_changed) {
            /* A live AR still talks L2 cyclic to the old controller while
             * RPC/SNMP move to the new unicast address. Drop it. */
            if (s->ar.cm_state != PN_CM_OFFLINE) {
                pn_ar_reset(s);
            }
            pn_stack_rebind_udp(s);
        }
        uint8_t ok[64];
        size_t n = build_set_ack(s, blocks, dlen, ok, sizeof(ok));
        send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_SET,
                 PN_DCP_RESP_SUCCESS, xid, 0, ok, n);
        if (ip_changed) {
            pn_dcp_send_hello(s);
        }
        return;
    }
}
