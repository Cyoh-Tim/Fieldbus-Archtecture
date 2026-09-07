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

#define OP_CONNECT 0
#define OP_RELEASE 1
#define OP_READ 2
#define OP_WRITE 3
#define OP_CONTROL 4

static const uint8_t k_pnio_ctl[16] = {0x02, 0x00, 0xA0, 0xDE, 0x97, 0x6C,
                                       0xD1, 0x11, 0x82, 0x71, 0x00, 0xA0,
                                       0x24, 0x42, 0xDF, 0x7D};

static int rpc_le(const uint8_t *pdu)
{
    uint8_t d = pdu[4];
    return (d & 0x10u) || (d & 0x01u);
}

static uint16_t rd16(const uint8_t *p, int le)
{
    return le ? pn_rd_le16(p) : pn_rd_be16(p);
}

static uint32_t rd32(const uint8_t *p, int le)
{
    return le ? pn_rd_le32(p) : pn_rd_be32(p);
}

static void wr16(uint8_t *p, uint16_t v, int le)
{
    if (le) {
        pn_wr_le16(p, v);
    } else {
        pn_wr_be16(p, v);
    }
}

static void wr32(uint8_t *p, uint32_t v, int le)
{
    if (le) {
        pn_wr_le32(p, v);
    } else {
        pn_wr_be32(p, v);
    }
}

static void uuid_to_mixed(uint8_t out[16], const uint8_t in[16])
{
    out[0] = in[3];
    out[1] = in[2];
    out[2] = in[1];
    out[3] = in[0];
    out[4] = in[5];
    out[5] = in[4];
    out[6] = in[7];
    out[7] = in[6];
    memcpy(out + 8, in + 8, 8);
}

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
        const uint8_t *body = p + off + 6;
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
                memcpy(mac, blocks + off + 8, PN_HMAC_LEN);
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
        LOG_WARN("pn_rpc", "security_class=1: Connect 에 integrity block 없음");
        return -EPERM;
    }
    if (!pn_sec_ok(s, rebuilt, rn, mac)) {
        LOG_WARN("pn_rpc", "security_class=1: Connect HMAC 불일치");
        return -EPERM;
    }
    return 0;
}

static void parse_iocr_apis(pn_iocr_t *cr, const uint8_t *body, uint16_t blen)
{
    if (blen < 40) {
        return;
    }
    uint16_t napis = pn_rd_be16(body + 38);
    size_t off = 40;
    for (uint16_t a = 0; a < napis && off + 8 <= blen; a++) {
        off += 4; /* API */
        uint16_t nd = pn_rd_be16(body + off);
        off += 2;
        for (uint16_t i = 0; i < nd && off + 6 <= blen; i++) {
            if (cr->n_data < PN_IOBJ_MAX) {
                cr->data[cr->n_data].slot = pn_rd_be16(body + off);
                cr->data[cr->n_data].subslot = pn_rd_be16(body + off + 2);
                cr->data[cr->n_data].frame_off = pn_rd_be16(body + off + 4);
                cr->n_data++;
            }
            off += 6;
        }
        if (off + 2 > blen) {
            break;
        }
        uint16_t nc = pn_rd_be16(body + off);
        off += 2;
        for (uint16_t i = 0; i < nc && off + 6 <= blen; i++) {
            if (cr->n_iocs < PN_IOBJ_MAX) {
                cr->iocs[cr->n_iocs].slot = pn_rd_be16(body + off);
                cr->iocs[cr->n_iocs].subslot = pn_rd_be16(body + off + 2);
                cr->iocs[cr->n_iocs].frame_off = pn_rd_be16(body + off + 4);
                cr->n_iocs++;
            }
            off += 6;
        }
    }
}

static int parse_connect_block(uint16_t type, const uint8_t *body, uint16_t blen,
                               void *u)
{
    pn_stack_t *s = u;
    pn_ar_t *ar = &s->ar;
    if (type == PN_BLOCK_AR_REQ && blen >= 26) {
        memcpy(ar->uuid, body + 2, PN_UUID_LEN);
        ar->session_key = pn_rd_be16(body + 18);
        memcpy(ar->initiator_mac, body + 20, 6);
        if (blen >= 42) {
            memcpy(ar->initiator_uuid, body + 26, PN_UUID_LEN);
        }
        if (blen >= 50) {
            ar->initiator_udp = pn_rd_be16(body + 48);
        }
    } else if (type == PN_BLOCK_IOCR_REQ && blen >= 18) {
        pn_iocr_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.type = pn_rd_be16(body);
        if (blen >= 4) {
            tmp.reference = pn_rd_be16(body + 2);
        }
        /* IOCRType, IOCRReference, LT, IOCRProperties, DataLength, FrameID,
         * SendClock, ReductionRatio, Phase, Sequence, FrameSendOffset,
         * Watchdog, DataHold, TagHeader, MAC, NumberOfAPIs */
        tmp.data_len = pn_rd_be16(body + 10);
        tmp.frame_id = pn_rd_be16(body + 12);
        tmp.send_clock = pn_rd_be16(body + 14);
        tmp.reduction = pn_rd_be16(body + 16);
        if (blen >= 32) {
            tmp.watchdog = pn_rd_be16(body + 26);
            tmp.datahold = pn_rd_be16(body + 28);
            uint16_t tag = pn_rd_be16(body + 30);
            tmp.pcp = (uint8_t)((tag >> 13) & 0x7);
            tmp.vlan_id = (uint16_t)(tag & 0x0FFFu);
        }
        parse_iocr_apis(&tmp, body, blen);
        if (tmp.type == PN_IOCR_INPUT) {
            ar->iocr_in = tmp;
            ar->send_clock_factor = tmp.send_clock;
            ar->reduction_ratio = tmp.reduction;
            ar->watchdog_factor = tmp.watchdog;
        } else if (tmp.type == PN_IOCR_OUTPUT) {
            ar->iocr_out = tmp;
            if (!ar->send_clock_factor) {
                ar->send_clock_factor = tmp.send_clock;
                ar->reduction_ratio = tmp.reduction;
                ar->watchdog_factor = tmp.watchdog;
            }
        }
    } else if (type == PN_BLOCK_EXPSUB_REQ && blen >= 16) {
        uint16_t napis = pn_rd_be16(body);
        size_t off = 2;
        for (uint16_t a = 0; a < napis && off + 14 <= blen; a++) {
            off += 4; /* API */
            uint16_t slot = pn_rd_be16(body + off);
            off += 2;
            off += 4; /* ModuleIdent */
            off += 2; /* ModuleProperties */
            uint16_t nsub = pn_rd_be16(body + off);
            off += 2;
            for (uint16_t i = 0; i < nsub && off + 8 <= blen; i++) {
                uint16_t subslot = pn_rd_be16(body + off);
                off += 2;
                off += 4; /* SubmoduleIdent */
                uint16_t props = pn_rd_be16(body + off);
                off += 2;
                uint16_t stype = (uint16_t)(props & 0x3u);
                int ndesc = (stype == 3) ? 2 : (stype == 0 ? 0 : 1);
                pn_submod_t sm;
                memset(&sm, 0, sizeof(sm));
                sm.slot = slot;
                sm.subslot = subslot;
                sm.iops_len = 1;
                sm.iocs_len = 1;
                for (int d = 0; d < ndesc && off + 6 <= blen; d++) {
                    uint16_t dd = pn_rd_be16(body + off);
                    uint16_t dlen = pn_rd_be16(body + off + 2);
                    uint8_t iocs = body[off + 4];
                    uint8_t iops = body[off + 5];
                    off += 6;
                    if (dd == 1) {
                        sm.in_len = dlen;
                        sm.iops_len = iops ? iops : 1;
                        sm.iocs_len = iocs ? iocs : sm.iocs_len;
                    } else if (dd == 2) {
                        sm.out_len = dlen;
                        if (iops) {
                            sm.iops_len = iops;
                        }
                        if (iocs) {
                            sm.iocs_len = iocs;
                        }
                    }
                }
                if (ar->n_sub < PN_SUBMOD_MAX) {
                    sm.in_pi = ar->in_data_len;
                    sm.out_pi = ar->out_data_len;
                    if ((uint32_t)ar->in_data_len + sm.in_len <= PN_IO_MAX) {
                        ar->in_data_len = (uint16_t)(ar->in_data_len + sm.in_len);
                    }
                    if ((uint32_t)ar->out_data_len + sm.out_len <= PN_IO_MAX) {
                        ar->out_data_len =
                            (uint16_t)(ar->out_data_len + sm.out_len);
                    }
                    ar->sub[ar->n_sub++] = sm;
                }
            }
        }
    }
    return 0;
}

static void finalize_ar(pn_stack_t *s)
{
    pn_ar_t *a = &s->ar;
    if (a->n_sub == 0) {
        a->sub[0].slot = 1;
        a->sub[0].subslot = 1;
        a->sub[0].in_len = s->cfg.input_len;
        a->sub[0].out_len = s->cfg.output_len;
        a->sub[0].in_pi = 0;
        a->sub[0].out_pi = 0;
        a->sub[0].iops_len = 1;
        a->sub[0].iocs_len = 1;
        a->n_sub = 1;
        a->in_data_len = s->cfg.input_len;
        a->out_data_len = s->cfg.output_len;
    }
    if (a->in_data_len == 0) {
        a->in_data_len = s->cfg.input_len;
    }
    if (a->out_data_len == 0) {
        a->out_data_len = s->cfg.output_len;
    }
    if (a->iocr_in.frame_id == 0) {
        a->iocr_in.frame_id = 0x8001;
        a->iocr_in.type = PN_IOCR_INPUT;
    }
    if (a->iocr_out.frame_id == 0 || a->iocr_out.frame_id == 0xFFFFu) {
        a->iocr_out.frame_id = 0x8000;
        a->iocr_out.type = PN_IOCR_OUTPUT;
    }
    a->in_frame_id = a->iocr_in.frame_id;
    a->out_frame_id = a->iocr_out.frame_id;
    if (a->iocr_in.data_len == 0) {
        a->iocr_in.data_len = (uint16_t)(a->in_data_len + 1);
    }
    if (a->iocr_out.data_len == 0) {
        a->iocr_out.data_len = (uint16_t)(a->out_data_len + 1);
    }
    if (a->iocr_in.n_data == 0 && a->n_sub > 0) {
        a->iocr_in.data[0].slot = a->sub[0].slot;
        a->iocr_in.data[0].subslot = a->sub[0].subslot;
        a->iocr_in.data[0].frame_off = 0;
        a->iocr_in.n_data = 1;
    }
    if (a->iocr_out.n_data == 0 && a->n_sub > 0) {
        a->iocr_out.data[0].slot = a->sub[0].slot;
        a->iocr_out.data[0].subslot = a->sub[0].subslot;
        a->iocr_out.data[0].frame_off = 0;
        a->iocr_out.n_data = 1;
    }
    if (a->send_clock_factor == 0) {
        a->send_clock_factor = 32;
    }
    if (a->reduction_ratio == 0) {
        uint32_t cyc = s->cfg.cycle_us ? s->cfg.cycle_us : 8000;
        uint32_t rr = cyc / 1000u;
        a->reduction_ratio = rr ? (uint16_t)rr : 1;
    }
    if (a->watchdog_factor == 0) {
        a->watchdog_factor = 3;
    }
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
    pn_wr_be16(ar, 0x0001);
    memcpy(ar + 2, s->ar.uuid, 16);
    pn_wr_be16(ar + 18, s->ar.session_key);
    memcpy(ar + 20, s->cfg.mac, 6);
    pn_wr_be16(ar + 26, PN_RPC_PORT);
    n += wr_block(out + n, PN_BLOCK_AR_RES, ar, sizeof(ar));

    uint8_t iocr_in[6];
    pn_wr_be16(iocr_in, PN_IOCR_INPUT);
    pn_wr_be16(iocr_in + 2, s->ar.iocr_in.reference ? s->ar.iocr_in.reference : 1);
    pn_wr_be16(iocr_in + 4, s->ar.in_frame_id);
    n += wr_block(out + n, PN_BLOCK_IOCR_RES, iocr_in, sizeof(iocr_in));

    uint8_t iocr_out[6];
    pn_wr_be16(iocr_out, PN_IOCR_OUTPUT);
    pn_wr_be16(iocr_out + 2,
               s->ar.iocr_out.reference ? s->ar.iocr_out.reference : 2);
    pn_wr_be16(iocr_out + 4, s->ar.out_frame_id);
    n += wr_block(out + n, PN_BLOCK_IOCR_RES, iocr_out, sizeof(iocr_out));

    uint8_t alarm[6];
    pn_wr_be16(alarm, 0x0001);
    pn_wr_be16(alarm + 2, 1);
    pn_wr_be16(alarm + 4, 200);
    n += wr_block(out + n, PN_BLOCK_ALARMCR_RES, alarm, sizeof(alarm));

    return n > cap ? 0 : n;
}

static size_t wrap_rpc_resp(const uint8_t *req, uint8_t *resp, size_t cap,
                            const uint8_t *stub, size_t stub_len)
{
    if (cap < RPC_HDR + stub_len) {
        return 0;
    }
    memcpy(resp, req, RPC_HDR);
    resp[1] = RPC_PT_RESPONSE;
    wr16(resp + 74, (uint16_t)stub_len, rpc_le(req));
    memcpy(resp + RPC_HDR, stub, stub_len);
    return RPC_HDR + stub_len;
}

static const uint8_t *ndr_blocks(const uint8_t *stub, size_t len, size_t *blen,
                                 int le)
{
    if (len < 20) {
        return NULL;
    }
    uint32_t args_len = rd32(stub + 4, le);
    uint32_t actual = rd32(stub + 16, le);
    uint32_t n = args_len < actual ? args_len : actual;
    if (20 + n > len) {
        n = (uint32_t)(len - 20);
    }
    *blen = n;
    return stub + 20;
}

static size_t ndr_wrap(uint8_t *out, const uint8_t *blocks, size_t n, int le)
{
    wr32(out, (uint32_t)n, le);
    wr32(out + 4, (uint32_t)n, le);
    wr32(out + 8, (uint32_t)n, le);
    wr32(out + 12, 0, le);
    wr32(out + 16, (uint32_t)n, le);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

static size_t build_control_block(uint8_t *out, uint16_t btype,
                                  const pn_ar_t *ar, uint16_t cmd)
{
    uint8_t body[26];
    memset(body, 0, sizeof(body));
    memcpy(body + 2, ar->uuid, 16);
    pn_wr_be16(body + 18, ar->session_key);
    pn_wr_be16(body + 22, cmd);
    return wr_block(out, btype, body, sizeof(body));
}

static int first_block_type(const uint8_t *blocks, size_t n, uint16_t *type,
                            const uint8_t **body, uint16_t *blen)
{
    if (n < 6) {
        return -1;
    }
    *type = pn_rd_be16(blocks);
    uint16_t ln = pn_rd_be16(blocks + 2);
    if (ln < 2 || 4u + ln > n) {
        return -1;
    }
    *body = blocks + 6;
    *blen = (uint16_t)(ln - 2);
    return 0;
}

static void queue_apprdy(pn_stack_t *s)
{
    uint8_t stub[128];
    uint8_t blk[64];
    size_t bn = build_control_block(blk, PN_BLOCK_APPRDY_REQ, &s->ar,
                                    PN_CTRL_APP_RDY);
    int le = s->ar.rpc_le;
    size_t so = ndr_wrap(stub, blk, bn, le);

    uint8_t hdr[RPC_HDR];
    memset(hdr, 0, sizeof(hdr));
    if (s->ar.last_rpc_hdr_set) {
        memcpy(hdr, s->ar.last_rpc_hdr, RPC_HDR);
    } else {
        hdr[0] = 4;
        hdr[4] = 0x10; /* little-endian drep */
        le = 1;
    }
    hdr[1] = RPC_PT_REQUEST;
    memcpy(hdr + 24, k_pnio_ctl, 16);
    if (s->ar.initiator_uuid[0] | s->ar.initiator_uuid[1] |
        s->ar.initiator_uuid[15]) {
        uint8_t mixed[16];
        uuid_to_mixed(mixed, s->ar.initiator_uuid);
        memcpy(hdr + 8, mixed, 16);
    }
    hdr[40] ^= 0x5A; /* distinct activity UUID */
    wr32(hdr + 64, 1, le);
    wr16(hdr + 68, OP_CONTROL, le);
    wr16(hdr + 70, 0xFFFF, le);
    wr16(hdr + 72, 0xFFFF, le);
    wr16(hdr + 74, (uint16_t)so, le);
    wr16(hdr + 76, 0, le);

    if (RPC_HDR + so > sizeof(s->rpc_tx)) {
        return;
    }
    memcpy(s->rpc_tx, hdr, RPC_HDR);
    memcpy(s->rpc_tx + RPC_HDR, stub, so);
    s->rpc_tx_len = RPC_HDR + so;
    s->rpc_tx_ip = s->ar.initiator_ip;
    s->rpc_tx_port = PN_RPC_PORT;
    s->rpc_tx_pending = 1;
}

static void enter_dataex(pn_stack_t *s)
{
    s->ar.cm_state = PN_CM_DATAEX;
    s->ar.established = 1;
    s->last_cpm_ns = pn_now_ns();
    s->last_rt_ns = 0;
    LOG_INFO("pn_rpc", "DATAEX in_fid=0x%04x out_fid=0x%04x cycle=%uus wd=%u",
             s->ar.in_frame_id, s->ar.out_frame_id,
             (unsigned)(pn_ar_cycle_ns(&s->ar, s->cfg.cycle_us) / 1000ull),
             s->ar.watchdog_factor);
}

static size_t build_read_res(pn_stack_t *s, const uint8_t *body, uint16_t blen,
                             uint8_t *out, size_t cap)
{
    uint16_t slot = 0, sub = 1, index = PN_INDEX_IM0;
    uint16_t seq = 0;
    uint8_t uuid[16];
    memset(uuid, 0, sizeof(uuid));
    uint32_t api = 0;
    if (blen >= 30) {
        seq = pn_rd_be16(body);
        memcpy(uuid, body + 2, 16);
        api = pn_rd_be32(body + 18);
        slot = pn_rd_be16(body + 22);
        sub = pn_rd_be16(body + 24);
        index = pn_rd_be16(body + 28);
    }
    uint8_t rec[256];
    size_t rlen = 0;
    if (pn_record_read(s, slot, sub, index, rec, sizeof(rec), &rlen) != 0) {
        rlen = 0;
    }
    uint8_t hdr[64];
    memset(hdr, 0, sizeof(hdr));
    pn_wr_be16(hdr, seq);
    memcpy(hdr + 2, uuid, 16);
    pn_wr_be32(hdr + 18, api);
    pn_wr_be16(hdr + 22, slot);
    pn_wr_be16(hdr + 24, sub);
    pn_wr_be16(hdr + 28, index);
    pn_wr_be32(hdr + 30, (uint32_t)rlen);
    /* additionalValue1/2 + 20 pad already zero */
    uint8_t blk[64 + 256];
    size_t bn = wr_block(blk, PN_BLOCK_READ_RES, hdr, 58);
    memcpy(blk + bn, rec, rlen);
    bn += rlen;
    if (bn > cap) {
        return 0;
    }
    memcpy(out, blk, bn);
    return bn;
}

static size_t build_write_res(const uint8_t *body, uint16_t blen, uint8_t *out,
                              size_t cap)
{
    uint8_t hdr[64];
    memset(hdr, 0, sizeof(hdr));
    size_t copy = blen < 58 ? blen : 58;
    memcpy(hdr, body, copy);
    pn_wr_be32(hdr + 30, 0); /* recordDataLength */
    size_t n = wr_block(out, PN_BLOCK_WRITE_RES, hdr, 58);
    return n > cap ? 0 : n;
}

int pn_rpc_handle_from(pn_stack_t *s, const uint8_t *pdu, size_t len,
                       uint32_t src_ip, uint16_t src_port, uint8_t *resp,
                       size_t cap, size_t *out_len)
{
    if (len < RPC_HDR) {
        return -EINVAL;
    }
    int le = rpc_le(pdu);
    uint8_t ptype = pdu[1];
    if (ptype == RPC_PT_RESPONSE) {
        /* ApplicationReady confirmation */
        if (s->ar.cm_state == PN_CM_W_APPRDY) {
            enter_dataex(s);
        }
        return -EINVAL;
    }
    if (ptype != RPC_PT_REQUEST) {
        return -EINVAL;
    }
    uint16_t op = rd16(pdu + 68, le);
    const uint8_t *stub = pdu + RPC_HDR;
    size_t slen = len - RPC_HDR;
    uint16_t declared = rd16(pdu + 74, le);
    if (declared && declared < slen) {
        slen = declared;
    }

    uint8_t stub_out[2048];
    size_t so = 0;

    if (op == OP_CONNECT) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen, le);
        if (!blocks) {
            return -EINVAL;
        }
        if (verify_connect_sec(s, blocks, blen) != 0) {
            uint8_t err[4] = {0x81, 0x00, 0x00, 0x00};
            so = ndr_wrap(stub_out, err, 4, le);
            *out_len = wrap_rpc_resp(pdu, resp, cap, stub_out, so);
            return 0;
        }
        pn_ar_reset(s);
        s->ar.rpc_le = le;
        memcpy(s->ar.last_rpc_hdr, pdu, RPC_HDR);
        s->ar.last_rpc_hdr_set = 1;
        if (src_ip) {
            s->ar.initiator_ip = src_ip;
        }
        s->ar.initiator_udp = src_port;
        walk_blocks(blocks, blen, parse_connect_block, s);
        finalize_ar(s);
        uint8_t blocks_res[512];
        size_t bn = build_connect_res_blocks(s, blocks_res, sizeof(blocks_res));
        so = ndr_wrap(stub_out, blocks_res, bn, le);
        s->ar.cm_state = PN_CM_CONNECTED;
        s->ar.established = 0;
        LOG_INFO("pn_rpc",
                 "Connect.res in_fid=0x%04x out_fid=0x%04x in=%u out=%u sc=%u rr=%u",
                 s->ar.in_frame_id, s->ar.out_frame_id, s->ar.in_data_len,
                 s->ar.out_data_len, s->ar.send_clock_factor,
                 s->ar.reduction_ratio);
    } else if (op == OP_RELEASE) {
        pn_ar_reset(s);
        uint8_t z[4] = {0};
        so = ndr_wrap(stub_out, z, 4, le);
        LOG_INFO("pn_rpc", "AR released");
    } else if (op == OP_CONTROL) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen, le);
        uint16_t btype = 0, body_len = 0, cmd = 0;
        const uint8_t *body = NULL;
        if (blocks) {
            first_block_type(blocks, blen, &btype, &body, &body_len);
            if (body && body_len >= 24) {
                cmd = pn_rd_be16(body + 22);
            }
        }
        int prm_end = (btype == PN_BLOCK_PRMEND_REQ) || (cmd & PN_CTRL_PRM_END);
        int rel = (btype == PN_BLOCK_RELEASE_REQ) || (cmd & PN_CTRL_RELEASE);
        uint16_t res_type = PN_BLOCK_PRMEND_RES;
        uint16_t res_cmd = PN_CTRL_DONE;
        if (rel) {
            pn_ar_reset(s);
            res_type = PN_BLOCK_RELEASE_RES;
            LOG_INFO("pn_rpc", "AR released (Control)");
        } else if (prm_end && s->ar.cm_state >= PN_CM_CONNECTED) {
            s->ar.cm_state = PN_CM_W_APPRDY;
            queue_apprdy(s);
            LOG_INFO("pn_rpc", "PrmEnd → ApplicationReady");
            enter_dataex(s);
            res_type = PN_BLOCK_PRMEND_RES;
        }
        uint8_t blk[64];
        size_t bn = build_control_block(blk, res_type, &s->ar, res_cmd);
        so = ndr_wrap(stub_out, blk, bn, le);
    } else if (op == OP_READ) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen, le);
        uint16_t btype = 0, body_len = 0;
        const uint8_t *body = NULL;
        uint8_t rec_blk[512];
        size_t rn = 0;
        if (blocks && first_block_type(blocks, blen, &btype, &body, &body_len) ==
                          0) {
            rn = build_read_res(s, body, body_len, rec_blk, sizeof(rec_blk));
        } else {
            uint8_t rec[256];
            size_t rlen = 0;
            pn_record_read(s, 0, 1, PN_INDEX_IM0, rec, sizeof(rec), &rlen);
            memcpy(rec_blk, rec, rlen);
            rn = rlen;
        }
        so = ndr_wrap(stub_out, rec_blk, rn, le);
    } else if (op == OP_WRITE) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen, le);
        uint16_t btype = 0, body_len = 0;
        const uint8_t *body = NULL;
        uint8_t wblk[80];
        size_t wn = 4;
        uint8_t z[4] = {0};
        memcpy(wblk, z, 4);
        if (blocks && first_block_type(blocks, blen, &btype, &body, &body_len) ==
                          0) {
            wn = build_write_res(body, body_len, wblk, sizeof(wblk));
        }
        so = ndr_wrap(stub_out, wblk, wn, le);
    } else {
        return -ENOSYS;
    }

    *out_len = wrap_rpc_resp(pdu, resp, cap, stub_out, so);
    return 0;
}

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len)
{
    return pn_rpc_handle_from(s, pdu, len, 0, 0, resp, cap, out_len);
}

void pn_rpc_flush_tx(pn_stack_t *s)
{
    if (!s->rpc_tx_pending || s->rpc_tx_len == 0) {
        return;
    }
    if (s->fd_rpc < 0) {
        return;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(s->rpc_tx_port ? s->rpc_tx_port : PN_RPC_PORT);
    dst.sin_addr.s_addr = htonl(s->rpc_tx_ip);
    sendto(s->fd_rpc, s->rpc_tx, s->rpc_tx_len, 0, (struct sockaddr *)&dst,
           sizeof(dst));
    s->rpc_tx_pending = 0;
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
        return;
    }
    uint32_t ip = ntohl(src.sin_addr.s_addr);
    uint16_t port = ntohs(src.sin_port);
    uint8_t resp[2048];
    size_t rlen = 0;
    if (pn_rpc_handle_from(s, buf, (size_t)n, ip, port, resp, sizeof(resp),
                           &rlen) == 0 &&
        rlen > 0) {
        sendto(s->fd_rpc, resp, rlen, 0, (struct sockaddr *)&src, sl);
    }
    pn_rpc_flush_tx(s);
}
