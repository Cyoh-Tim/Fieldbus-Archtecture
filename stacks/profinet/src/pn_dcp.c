#include "pn_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "pn_endian.h"

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

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

/* Identify.res / Get.res / Hello.req block: BlockInfo then value.
 * DCPBlockLength includes BlockInfo and excludes the odd-length pad. */
static void wr_block(wr_t *w, uint8_t opt, uint8_t sub, uint16_t block_info,
                     const void *data, size_t dlen)
{
    uint16_t blen = (uint16_t)(2u + dlen);
    wr_u8(w, opt);
    wr_u8(w, sub);
    wr_be16(w, blen);
    wr_be16(w, block_info);
    wr_bytes(w, data, dlen);
    wr_pad_even(w, blen);
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

static int is_hex_lc(uint8_t c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int pn_dcp_name_ok(const uint8_t *name, size_t n)
{
    if (!name || n == 0 || n > PN_STATION_NAME_MAX) {
        return 0;
    }
    /* Reserved PortName: "port-" + exactly 3 hex digits (+ optional rest). */
    if (n >= 8 && memcmp(name, "port-", 5) == 0 && is_hex_lc(name[5]) &&
        is_hex_lc(name[6]) && is_hex_lc(name[7]) &&
        (n == 8 || name[8] == '-')) {
        return 0;
    }

    int labels = 0;
    int ip_like = 1;
    int ip_octets = 0;
    size_t i = 0;
    while (i < n) {
        if (name[i] == '.') {
            return 0; /* empty label */
        }
        size_t start = i;
        int all_digit = 1;
        while (i < n && name[i] != '.') {
            uint8_t c = name[i];
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-')) {
                return 0;
            }
            if (c < '0' || c > '9') {
                all_digit = 0;
            }
            i++;
        }
        size_t lab = i - start;
        if (lab < 1 || lab > 63) {
            return 0;
        }
        if (name[start] == '-' || name[i - 1] == '-') {
            return 0;
        }
        labels++;
        if (ip_like && all_digit && lab <= 3 && ip_octets < 4) {
            int v = 0;
            for (size_t k = start; k < i; k++) {
                v = v * 10 + (name[k] - '0');
            }
            if (v > 255) {
                ip_like = 0;
            } else {
                ip_octets++;
            }
        } else {
            ip_like = 0;
        }
        if (i < n) {
            if (name[i] != '.') {
                return 0;
            }
            i++;
            if (i == n) {
                return 0; /* trailing dot */
            }
        }
    }
    if (ip_like && ip_octets == 4 && labels == 4) {
        return 0;
    }
    return labels >= 1;
}

/* HMAC over FrameID..end excluding the Security block itself. */
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
    {
        size_t cap = w.cap;
        if (w.n > cap) {
            return -EINVAL;
        }
    }
    if (w.n < 12) {
        return -EINVAL;
    }
    uint16_t new_dlen = (uint16_t)(w.n - 12);
    pn_wr_be16(rebuilt + dlen_off, new_dlen);
    memcpy(body, rebuilt, w.n);
    *body_len = w.n;
    return 0;
}

static int dcp_require_integrity(const pn_stack_t *s)
{
#ifdef PN_ENFORCE_SECURITY_CLASS
    return 1;
#else
    return s->cfg.security_class >= PN_VENDOR_INTEGRITY ||
           s->cfg.enforce_security_class;
#endif
}

int pn_dcp_verify_set(const pn_stack_t *s, const uint8_t *payload, size_t plen)
{
    if (!dcp_require_integrity(s)) {
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

static void apply_blocks(pn_stack_t *s, const uint8_t *blocks, uint16_t dlen)
{
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
        /* Set blocks include 2-byte BlockQualifier */
        const uint8_t *val = (bl >= 2) ? data + 2 : data;
        size_t vlen = (bl >= 2) ? (size_t)bl - 2 : 0;

        if (opt == PN_DCP_OPT_DEV && sub == PN_DCP_SUB_DEV_NAME && vlen > 0) {
            if (!pn_dcp_name_ok(val, vlen)) {
                LOG_WARN("pn_dcp", "NameOfStation rejected (DNS/PN rules)");
            } else {
                size_t n =
                    vlen < PN_STATION_NAME_MAX ? vlen : PN_STATION_NAME_MAX;
                memcpy(s->cfg.station_name, val, n);
                s->cfg.station_name[n] = '\0';
                LOG_INFO("pn_dcp", "NameOfStation=%s", s->cfg.station_name);
            }
        } else if (opt == PN_DCP_OPT_IP && sub == PN_DCP_SUB_IP_PARAM &&
                   vlen >= 12) {
            s->cfg.ip = pn_rd_be32(val);
            s->cfg.netmask = pn_rd_be32(val + 4);
            s->cfg.gateway = pn_rd_be32(val + 8);
            LOG_INFO("pn_dcp", "IP set %u.%u.%u.%u",
                     (s->cfg.ip >> 24) & 0xff, (s->cfg.ip >> 16) & 0xff,
                     (s->cfg.ip >> 8) & 0xff, s->cfg.ip & 0xff);
        } else if (opt == PN_DCP_OPT_CTRL && sub == PN_DCP_SUB_CTRL_SIGNAL) {
            LOG_INFO("pn_dcp", "DCP Signal accepted (LED flash stub)");
        }
        off += total;
    }
}

static int blocks_have(const uint8_t *blocks, uint16_t dlen, uint8_t opt,
                       uint8_t sub)
{
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t o = blocks[off];
        uint8_t su = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        if (o == opt && su == sub) {
            return 1;
        }
        off += total;
    }
    return 0;
}

static int set_has_invalid_name(const uint8_t *blocks, uint16_t dlen)
{
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t o = blocks[off];
        uint8_t su = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            break;
        }
        if (o == PN_DCP_OPT_DEV && su == PN_DCP_SUB_DEV_NAME) {
            const uint8_t *data = blocks + off + 4;
            const uint8_t *val = (bl >= 2) ? data + 2 : data;
            size_t vlen = (bl >= 2) ? (size_t)bl - 2 : 0;
            if (vlen == 0 || !pn_dcp_name_ok(val, vlen)) {
                return 1;
            }
        }
        off += total;
    }
    return 0;
}

static int ident_filters_match(const pn_stack_t *s, const uint8_t *blocks,
                               uint16_t dlen)
{
    size_t off = 0;
    while (off + 4 <= dlen) {
        uint8_t o = blocks[off];
        uint8_t su = blocks[off + 1];
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + bl + (bl & 1u);
        if (off + total > dlen) {
            return 0;
        }
        const uint8_t *data = blocks + off + 4;
        if (o == PN_DCP_OPT_ALL) {
            /* All selector matches every station. */
        } else if (o == PN_DCP_OPT_DEV && su == PN_DCP_SUB_DEV_NAME) {
            size_t n = strlen(s->cfg.station_name);
            if (bl != n || memcmp(data, s->cfg.station_name, n) != 0) {
                return 0;
            }
        } else if (o == PN_DCP_OPT_DEV && su == PN_DCP_SUB_DEV_ID) {
            if (bl < 4) {
                return 0;
            }
            if (pn_rd_be16(data) != s->cfg.vendor_id ||
                pn_rd_be16(data + 2) != s->cfg.device_id) {
                return 0;
            }
        } else if (o == PN_DCP_OPT_DEV && su == PN_DCP_SUB_DEV_TYPE) {
            size_t n = strlen(s->cfg.device_type);
            if (bl != n || memcmp(data, s->cfg.device_type, n) != 0) {
                return 0;
            }
        } else if (o == PN_DCP_OPT_DEV && su == PN_DCP_SUB_DEV_ROLE) {
            if (bl < 1 || data[0] != 0x02) {
                return 0;
            }
        } else {
            return 0;
        }
        off += total;
    }
    return 1;
}

static size_t build_identify_blocks(const pn_stack_t *s, uint8_t *out,
                                    size_t cap)
{
    wr_t w = {out, cap, 0};
    wr_block(&w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_TYPE, PN_DCP_BLOCKINFO_NONE,
             s->cfg.device_type, strlen(s->cfg.device_type));
    wr_block(&w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME, PN_DCP_BLOCKINFO_NONE,
             s->cfg.station_name, strlen(s->cfg.station_name));
    uint8_t devid[4];
    pn_wr_be16(devid, s->cfg.vendor_id);
    pn_wr_be16(devid + 2, s->cfg.device_id);
    wr_block(&w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ID, PN_DCP_BLOCKINFO_NONE, devid,
             4);
    /* RoleDetails stays 0x02 (IO-Controller). 0x01 is T12-22. */
    uint8_t role[2] = {0x02, 0x00};
    wr_block(&w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_ROLE, PN_DCP_BLOCKINFO_NONE,
             role, sizeof(role));
    uint8_t ipb[12];
    pn_wr_be32(ipb, s->cfg.ip);
    pn_wr_be32(ipb + 4, s->cfg.netmask);
    pn_wr_be32(ipb + 8, s->cfg.gateway);
    uint16_t ip_info =
        s->cfg.ip != 0 ? PN_DCP_BLOCKINFO_IP_SET : PN_DCP_BLOCKINFO_NONE;
    wr_block(&w, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, ip_info, ipb, 12);
    wr_block(&w, PN_DCP_OPT_IP, PN_DCP_SUB_IP_MAC, PN_DCP_BLOCKINFO_NONE,
             s->cfg.mac, 6);
    /* DeviceOptions: IP, Device */
    uint8_t opts[] = {PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM, PN_DCP_OPT_DEV,
                      PN_DCP_SUB_DEV_NAME};
    wr_block(&w, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_OPTS, PN_DCP_BLOCKINFO_NONE,
             opts, sizeof(opts));
    if (w.n > cap) {
        return 0;
    }
    return w.n;
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

static uint64_t ident_delay_ns(const pn_stack_t *s, uint16_t delay_factor)
{
    if (delay_factor == 0) {
        return 0;
    }
    uint32_t mac16 =
        ((uint32_t)s->cfg.mac[4] << 8) | (uint32_t)s->cfg.mac[5];
    uint32_t slots = mac16 % (uint32_t)delay_factor;
    return (uint64_t)slots * 10000000ull; /* 10 ms units */
}

static void send_identify_res(pn_stack_t *s, const uint8_t dst[6], uint32_t xid)
{
    uint8_t b[512];
    size_t n = build_identify_blocks(s, b, sizeof(b));
    send_dcp(s, dst, PN_FRAMEID_DCP_ID_RES, PN_DCP_IDENTIFY, PN_DCP_RESP_SUCCESS,
             xid, 0, b, n);
}

static void queue_or_send_ident(pn_stack_t *s, const uint8_t src[6], uint32_t xid,
                                uint16_t delay)
{
    uint64_t wait = ident_delay_ns(s, delay);
    if (wait == 0) {
        send_identify_res(s, src, xid);
        return;
    }
    memcpy(s->dcp_ident_dst, src, 6);
    s->dcp_ident_xid = xid;
    s->dcp_ident_due_ns = pn_now_ns() + wait;
    s->dcp_ident_pending = 1;
}

void pn_dcp_poll(pn_stack_t *s)
{
    if (!s || !s->dcp_ident_pending) {
        return;
    }
    if (pn_now_ns() < s->dcp_ident_due_ns) {
        return;
    }
    send_identify_res(s, s->dcp_ident_dst, s->dcp_ident_xid);
    s->dcp_ident_pending = 0;
}

static void send_set_not_possible(pn_stack_t *s, const uint8_t src[6],
                                  uint32_t xid, uint8_t opt, uint8_t sub)
{
    uint8_t err[8];
    wr_t w = {err, sizeof(err), 0};
    wr_u8(&w, PN_DCP_OPT_CTRL);
    wr_u8(&w, PN_DCP_SUB_CTRL_RESPONSE);
    wr_be16(&w, 3);
    wr_u8(&w, opt);
    wr_u8(&w, sub);
    wr_u8(&w, 0x03); /* set not possible */
    wr_u8(&w, 0);
    send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_SET, PN_DCP_RESP_UNSUP, xid,
             0, err, w.n);
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
        if (!ident_filters_match(s, blocks, dlen)) {
            return;
        }
        queue_or_send_ident(s, src, xid, delay);
        return;
    }

    if (sid == PN_DCP_GET) {
        uint8_t b[512];
        size_t n = build_identify_blocks(s, b, sizeof(b));
        send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_GET,
                 PN_DCP_RESP_SUCCESS, xid, 0, b, n);
        return;
    }

    if (sid == PN_DCP_SET) {
        if (pn_dcp_verify_set(s, payload, plen) != 0) {
            LOG_WARN("pn_dcp",
                     "vendor integrity extension: unsigned/invalid DCP Set 거부");
            send_set_not_possible(s, src, xid, PN_DCP_OPT_SEC,
                                  PN_DCP_SUB_SEC_HMAC);
            return;
        }
        if (set_has_invalid_name(blocks, dlen)) {
            LOG_WARN("pn_dcp", "DCP Set NameOfStation invalid — 거부");
            send_set_not_possible(s, src, xid, PN_DCP_OPT_DEV,
                                  PN_DCP_SUB_DEV_NAME);
            return;
        }
        int set_ip = blocks_have(blocks, dlen, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM);
        int set_sig = blocks_have(blocks, dlen, PN_DCP_OPT_CTRL,
                                  PN_DCP_SUB_CTRL_SIGNAL);
        apply_blocks(s, blocks, dlen);
        uint8_t ok[8];
        wr_t w = {ok, sizeof(ok), 0};
        wr_u8(&w, PN_DCP_OPT_CTRL);
        wr_u8(&w, PN_DCP_SUB_CTRL_RESPONSE);
        wr_be16(&w, 3);
        if (set_sig) {
            wr_u8(&w, PN_DCP_OPT_CTRL);
            wr_u8(&w, PN_DCP_SUB_CTRL_SIGNAL);
        } else if (set_ip) {
            wr_u8(&w, PN_DCP_OPT_IP);
            wr_u8(&w, PN_DCP_SUB_IP_PARAM);
        } else {
            wr_u8(&w, PN_DCP_OPT_DEV);
            wr_u8(&w, PN_DCP_SUB_DEV_NAME);
        }
        wr_u8(&w, 0x00); /* OK */
        wr_u8(&w, 0);
        send_dcp(s, src, PN_FRAMEID_DCP_GETSET, PN_DCP_SET,
                 PN_DCP_RESP_SUCCESS, xid, 0, ok, w.n);
        if (set_ip) {
            /* Device announces new IP (DCP Hello.Req, FrameID 0xFEFC). */
            pn_dcp_send_hello(s);
        }
        return;
    }

    /* Hello.Req from a peer is ignored (Device originates Hello). */
}

void pn_dcp_send_hello(pn_stack_t *s)
{
    if (!s) {
        return;
    }
    uint8_t b[512];
    size_t n = build_identify_blocks(s, b, sizeof(b));
    send_dcp(s, k_dcp_mc, PN_FRAMEID_DCP_HELLO, PN_DCP_HELLO, PN_DCP_REQ, 0, 0,
             b, n);
    LOG_INFO("pn_dcp", "TX Hello FrameID=0x%04x name=%s", PN_FRAMEID_DCP_HELLO,
             s->cfg.station_name);
}
