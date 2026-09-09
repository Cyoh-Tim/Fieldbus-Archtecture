#include "pn_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "logger.h"
#include "pn_endian.h"

#define RPC_HDR 80
#define RPC_PT_REQUEST 0
#define RPC_PT_RESPONSE 2
#define RPC_PT_REJECT 4

#define OP_CONNECT 0
#define OP_RELEASE 1
#define OP_READ 2
#define OP_WRITE 3
#define OP_CONTROL 4

/* PNIO Device interface UUID on the wire (mixed endian). */
static const uint8_t k_pnio_if[16] = {0x01, 0x00, 0xA0, 0xDE, 0x97, 0x6C,
                                      0xD1, 0x11, 0x82, 0x71, 0x00, 0xA0,
                                      0x24, 0x42, 0xDF, 0x7D};

static int walk_blocks(const uint8_t *p, size_t n,
                       int (*cb)(uint16_t type, const uint8_t *body,
                                 uint16_t blen, void *u),
                       void *u)
{
    size_t off = 0;
    while (off + 6 <= n) {
        uint16_t type = pn_rd_be16(p + off);
        uint16_t blen = pn_rd_be16(p + off + 2);
        if (blen < 2 || off + 4u + blen > n) {
            break;
        }
        const uint8_t *body = p + off + 6; /* after type,len,ver */
        uint16_t body_len = (uint16_t)(blen - 2);
        if (cb(type, body, body_len, u) != 0) {
            return -1;
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
    return 0;
}

typedef struct {
    pn_stack_t *s;
    int saw_sec;
    int sec_ok;
    const uint8_t *stub;
    size_t stub_len;
} sec_walk_t;

typedef struct {
    uint16_t slot;
    uint16_t subslot;
    uint16_t index;
    int saw;
} read_walk_t;

typedef struct {
    uint16_t slot;
    uint16_t subslot;
    uint16_t index;
    const uint8_t *data;
    uint32_t dlen;
    int saw;
} write_walk_t;

typedef struct {
    uint16_t command;
    int saw;
} ctrl_walk_t;

static int parse_read_req(uint16_t type, const uint8_t *body, uint16_t blen,
                          void *u)
{
    read_walk_t *r = u;
    /* IODReadReq: seq(2) ARUUID(16) API(4) slot(2) subslot(2) pad(2) index(2) */
    if (type == PN_BLOCK_IOD_READ_REQ && blen >= 30) {
        r->slot = pn_rd_be16(body + 22);
        r->subslot = pn_rd_be16(body + 24);
        r->index = pn_rd_be16(body + 28);
        r->saw = 1;
    }
    return 0;
}

static int parse_write_req(uint16_t type, const uint8_t *body, uint16_t blen,
                           void *u)
{
    write_walk_t *w = u;
    if (type == PN_BLOCK_IOD_WRITE_REQ && blen >= 30) {
        w->slot = pn_rd_be16(body + 22);
        w->subslot = pn_rd_be16(body + 24);
        w->index = pn_rd_be16(body + 28);
        w->dlen = pn_rd_be32(body + 30);
        w->data = (blen > 34) ? body + 34 : NULL;
        uint32_t avail = (blen > 34) ? (uint32_t)(blen - 34) : 0;
        if (w->dlen > avail) {
            w->dlen = avail;
        }
        w->saw = 1;
    }
    return 0;
}

static int parse_ctrl_req(uint16_t type, const uint8_t *body, uint16_t blen,
                          void *u)
{
    ctrl_walk_t *c = u;
    if (type == PN_BLOCK_CONTROL_REQ && blen >= 24) {
        /* pad(2) + ARUUID(16) + session(2) + reserved(2) + command(2) */
        size_t cmd_off = (blen >= 26) ? 22u : 20u;
        c->command = pn_rd_be16(body + cmd_off);
        c->saw = 1;
    }
    return 0;
}

static int strip_sec_cb(uint16_t type, const uint8_t *body, uint16_t blen,
                        void *u)
{
    sec_walk_t *w = u;
    if (type == PN_BLOCK_SEC_INT) {
        w->saw_sec = 1;
        if (blen >= 2 + PN_HMAC_LEN) {
            /* body: alg_id(2) + hmac(32) */
            const uint8_t *mac = body + 2;
            /* HMAC is over whole stub; caller verifies after rebuild. */
            memcpy(w->s->last_rpc_resp, mac, PN_HMAC_LEN); /* temp store */
            w->sec_ok = 1;
        }
        (void)blen;
    }
    return 0;
}

static int parse_ar_iocr(uint16_t type, const uint8_t *body, uint16_t blen,
                         void *u)
{
    pn_stack_t *s = u;
    if (type == PN_BLOCK_AR_REQ && blen >= 16 + 2 + 6) {
        memcpy(s->ar.uuid, body + 2, PN_UUID_LEN);
        s->ar.session_key = pn_rd_be16(body + 2 + 16);
        memcpy(s->ar.initiator_mac, body + 2 + 16 + 2, 6);
    } else if (type == PN_BLOCK_IOCR_REQ && blen >= 18) {
        uint16_t iocr_type = pn_rd_be16(body);
        uint16_t data_len = pn_rd_be16(body + 10);
        uint16_t frame_id = pn_rd_be16(body + 12);
        uint16_t sc = pn_rd_be16(body + 14);
        uint16_t rr = pn_rd_be16(body + 16);
        s->ar.send_clock_factor = sc;
        s->ar.reduction_ratio = rr;
        if (iocr_type == PN_IOCR_INPUT) {
            s->ar.in_frame_id = frame_id;
            s->ar.in_data_len = data_len > 1 ? (uint16_t)(data_len - 1) : 0;
        } else if (iocr_type == PN_IOCR_OUTPUT) {
            s->ar.out_frame_id = frame_id;
            s->ar.out_data_len = data_len > 1 ? (uint16_t)(data_len - 1) : 0;
        }
    }
    return 0;
}

static int verify_connect_sec(pn_stack_t *s, const uint8_t *blocks, size_t n)
{
    if (s->cfg.security_class < PN_SECURITY_CLASS_1) {
        return 0;
    }
    uint8_t mac[PN_HMAC_LEN];
    int have = 0;
    uint8_t rebuilt[2048];
    size_t rn = 0;
    size_t off = 0;
    while (off + 6 <= n) {
        uint16_t type = pn_rd_be16(blocks + off);
        uint16_t blen = pn_rd_be16(blocks + off + 2);
        size_t total = 4u + blen;
        if (blen < 2 || off + total > n) {
            break;
        }
        if (off + total < n && (total & 1u)) {
            total++;
        }
        if (type == PN_BLOCK_SEC_INT) {
            if (blen >= 2 + 2 + PN_HMAC_LEN) {
                memcpy(mac, blocks + off + 8, PN_HMAC_LEN); /* ver(2)+alg(2)+mac */
                have = 1;
            } else if (blen >= 2 + PN_HMAC_LEN) {
                memcpy(mac, blocks + off + 6, PN_HMAC_LEN);
                have = 1;
            }
        } else {
            if (rn + total > sizeof(rebuilt)) {
                return -EPERM;
            }
            memcpy(rebuilt + rn, blocks + off, total);
            rn += total;
        }
        off += total;
    }
    if (!have) {
        LOG_WARN("pn_rpc", "Security Class 1: Connect 에 integrity block 없음");
        return -EPERM;
    }
    if (!pn_sec_ok(s, rebuilt, rn, mac)) {
        LOG_WARN("pn_rpc", "Security Class 1: Connect HMAC 불일치");
        return -EPERM;
    }
    return 0;
}

static size_t wr_block(uint8_t *p, uint16_t type, const uint8_t *body,
                       uint16_t body_len)
{
    uint16_t blen = (uint16_t)(2 + body_len);
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, blen);
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, body_len);
    size_t n = 4u + blen;
    if (n & 1u) {
        p[n++] = 0;
    }
    return n;
}

static size_t build_connect_res_blocks(pn_stack_t *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    uint8_t ar[2 + 16 + 2 + 6 + 2];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001); /* ARType IOCARSingle */
    memcpy(ar + 2, s->ar.uuid, 16);
    pn_wr_be16(ar + 18, s->ar.session_key);
    memcpy(ar + 20, s->cfg.mac, 6);
    pn_wr_be16(ar + 26, PN_RPC_PORT);
    n += wr_block(out + n, PN_BLOCK_AR_RES, ar, sizeof(ar));

    uint8_t iocr_in[6];
    pn_wr_be16(iocr_in, PN_IOCR_INPUT);
    pn_wr_be16(iocr_in + 2, 1);
    pn_wr_be16(iocr_in + 4, s->ar.in_frame_id ? s->ar.in_frame_id : 0x8001);
    n += wr_block(out + n, PN_BLOCK_IOCR_RES, iocr_in, sizeof(iocr_in));

    uint8_t iocr_out[6];
    pn_wr_be16(iocr_out, PN_IOCR_OUTPUT);
    pn_wr_be16(iocr_out + 2, 2);
    pn_wr_be16(iocr_out + 4, s->ar.out_frame_id ? s->ar.out_frame_id : 0x8002);
    n += wr_block(out + n, PN_BLOCK_IOCR_RES, iocr_out, sizeof(iocr_out));

    uint8_t alarm[8];
    memset(alarm, 0, sizeof(alarm));
    pn_wr_be16(alarm, 0x0001);
    pn_wr_be16(alarm + 2, 1);
    pn_wr_be16(alarm + 4, 200);
    pn_wr_be16(alarm + 6, 0x00A0);
    n += wr_block(out + n, PN_BLOCK_ALARMCR_RES, alarm, sizeof(alarm));

    if (n > cap) {
        return 0;
    }
    (void)strip_sec_cb;
    (void)k_pnio_if;
    return n;
}

static size_t wrap_rpc_resp(const uint8_t *req, uint8_t *resp, size_t cap,
                            const uint8_t *stub, size_t stub_len)
{
    if (cap < RPC_HDR + stub_len) {
        return 0;
    }
    memcpy(resp, req, RPC_HDR);
    resp[1] = RPC_PT_RESPONSE;
    pn_wr_le16(resp + 74, (uint16_t)stub_len);
    memcpy(resp + RPC_HDR, stub, stub_len);
    return RPC_HDR + stub_len;
}

static const uint8_t *ndr_blocks(const uint8_t *stub, size_t len, size_t *blen)
{
    /* argsMax, argsLen, max, offset, actual  — 5 x uint32 LE */
    if (len < 20) {
        return NULL;
    }
    uint32_t args_len = pn_rd_le32(stub + 4);
    uint32_t actual = pn_rd_le32(stub + 16);
    uint32_t n = args_len < actual ? args_len : actual;
    if (20 + n > len) {
        n = (uint32_t)(len - 20);
    }
    *blen = n;
    return stub + 20;
}

static size_t ndr_wrap(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t wrap_rpc_req(uint8_t *out, size_t cap, uint16_t op,
                           const uint8_t *stub, size_t stub_len)
{
    if (cap < RPC_HDR + stub_len) {
        return 0;
    }
    memset(out, 0, RPC_HDR);
    out[0] = 1;
    out[1] = RPC_PT_REQUEST;
    pn_wr_le16(out + 68, op);
    pn_wr_le16(out + 74, (uint16_t)stub_len);
    memcpy(out + RPC_HDR, stub, stub_len);
    return RPC_HDR + stub_len;
}

static void queue_app_ready(pn_stack_t *s)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    memcpy(body + 2, s->ar.uuid, 16);
    pn_wr_be16(body + 18, s->ar.session_key);
    pn_wr_be16(body + 22, PN_CONTROL_APP_READY);
    uint8_t blocks[64];
    size_t bn = wr_block(blocks, PN_BLOCK_CONTROL_REQ, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    s->pending_rpc_tx_len =
        wrap_rpc_req(s->pending_rpc_tx, sizeof(s->pending_rpc_tx), OP_CONTROL,
                     stub, sn);
    s->ar.app_ready = 1;
    LOG_INFO("pn_rpc", "queued ApplicationReady indication");
}

static void flush_pending_rpc(pn_stack_t *s)
{
    if (s->fd_rpc < 0 || !s->rpc_peer_set || s->pending_rpc_tx_len == 0) {
        return;
    }
    sendto(s->fd_rpc, s->pending_rpc_tx, s->pending_rpc_tx_len, 0,
           (struct sockaddr *)&s->rpc_peer, sizeof(s->rpc_peer));
    s->pending_rpc_tx_len = 0;
}

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len)
{
    if (len < RPC_HDR) {
        return -EINVAL;
    }
    uint8_t ptype = pdu[1];
    if (ptype != RPC_PT_REQUEST) {
        return -EINVAL;
    }
    uint16_t op = pn_rd_le16(pdu + 68);
    const uint8_t *stub = pdu + RPC_HDR;
    size_t slen = len - RPC_HDR;
    uint16_t declared = pn_rd_le16(pdu + 74);
    if (declared < slen) {
        slen = declared;
    }

    uint8_t stub_out[2048];
    size_t so = 0;

    if (op == OP_CONNECT) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (!blocks) {
            return -EINVAL;
        }
        if (verify_connect_sec(s, blocks, blen) != 0) {
            uint8_t err[4];
            pn_wr_be32(err, 0x81u << 24); /* generic PNIO error */
            so = ndr_wrap(stub_out, err, 4);
            *out_len = wrap_rpc_resp(pdu, resp, cap, stub_out, so);
            return 0;
        }
        memset(&s->ar, 0, sizeof(s->ar));
        walk_blocks(blocks, blen, parse_ar_iocr, s);
        if (s->ar.in_frame_id == 0) {
            s->ar.in_frame_id = 0x8001;
        }
        if (s->ar.out_frame_id == 0) {
            s->ar.out_frame_id = 0x8002;
        }
        if (s->ar.in_data_len == 0) {
            s->ar.in_data_len = s->cfg.input_len;
        }
        if (s->ar.out_data_len == 0) {
            s->ar.out_data_len = s->cfg.output_len;
        }
        uint8_t blocks_res[512];
        size_t bn = build_connect_res_blocks(s, blocks_res, sizeof(blocks_res));
        so = ndr_wrap(stub_out, blocks_res, bn);
        s->ar.established = 1;
        LOG_INFO("pn_rpc",
                 "AR established in_fid=0x%04x out_fid=0x%04x in=%u out=%u",
                 s->ar.in_frame_id, s->ar.out_frame_id, s->ar.in_data_len,
                 s->ar.out_data_len);
    } else if (op == OP_RELEASE) {
        s->ar.established = 0;
        memset(&s->ar, 0, sizeof(s->ar));
        uint8_t z[4] = {0};
        so = ndr_wrap(stub_out, z, 4);
        LOG_INFO("pn_rpc", "AR released");
    } else if (op == OP_CONTROL) {
        ctrl_walk_t cw = {.command = PN_CONTROL_PRM_END, .saw = 0};
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_ctrl_req, &cw);
        }
        if (!cw.saw) {
            cw.command = PN_CONTROL_PRM_END;
        }
        uint8_t cres[26];
        memset(cres, 0, sizeof(cres));
        memcpy(cres + 2, s->ar.uuid, 16);
        pn_wr_be16(cres + 18, s->ar.session_key);
        pn_wr_be16(cres + 22, cw.command);
        uint8_t blocks_res[64];
        size_t bn = wr_block(blocks_res, PN_BLOCK_CONTROL_RES, cres,
                             sizeof(cres));
        so = ndr_wrap(stub_out, blocks_res, bn);
        s->ar.established = 1;
        if (cw.command == PN_CONTROL_PRM_END) {
            s->ar.prm_end = 1;
            queue_app_ready(s);
            LOG_INFO("pn_rpc", "ParameterEnd accepted, ApplicationReady queued");
        } else if (cw.command == PN_CONTROL_APP_READY) {
            s->ar.app_ready = 1;
            LOG_INFO("pn_rpc", "ApplicationReady control accepted");
        }
    } else if (op == OP_READ) {
        uint8_t rec[256];
        size_t rlen = 0;
        read_walk_t rw = {.slot = 0, .subslot = 1, .index = PN_INDEX_IM0,
                          .saw = 0};
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_read_req, &rw);
        }
        pn_record_read(s, rw.slot, rw.subslot, rw.index, rec, sizeof(rec),
                       &rlen);
        so = ndr_wrap(stub_out, rec, rlen);
    } else if (op == OP_WRITE) {
        write_walk_t ww = {.slot = 0, .subslot = 1, .index = 0, .data = NULL,
                           .dlen = 0, .saw = 0};
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_write_req, &ww);
        }
        if (ww.saw) {
            pn_record_write(s, ww.slot, ww.subslot, ww.index, ww.data, ww.dlen);
            LOG_INFO("pn_rpc", "Write index=0x%04x slot=%u sub=%u len=%u",
                     ww.index, ww.slot, ww.subslot, ww.dlen);
        }
        uint8_t z[4] = {0};
        so = ndr_wrap(stub_out, z, 4);
    } else {
        return -ENOSYS;
    }

    *out_len = wrap_rpc_resp(pdu, resp, cap, stub_out, so);
    return 0;
}

void pn_rpc_poll(pn_stack_t *s)
{
    if (s->fd_rpc < 0) {
        return;
    }
    uint8_t buf[2048];
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);
    ssize_t n = recvfrom(s->fd_rpc, buf, sizeof(buf), MSG_DONTWAIT,
                         (struct sockaddr *)&src, &sl);
    if (n <= 0) {
        flush_pending_rpc(s);
        return;
    }
    s->rpc_peer = src;
    s->rpc_peer_set = 1;
    uint8_t resp[2048];
    size_t rlen = 0;
    if (pn_rpc_handle(s, buf, (size_t)n, resp, sizeof(resp), &rlen) == 0 &&
        rlen > 0) {
        sendto(s->fd_rpc, resp, rlen, 0, (struct sockaddr *)&src, sl);
    }
    flush_pending_rpc(s);
}
