#include "pn_internal.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
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

/* PNIO Controller interface UUID: DEA00002-6C97-11D1-8271-00A02442DF7D */
static const uint8_t k_pnio_controller_if[16] = {
    0x02, 0x00, 0xA0, 0xDE, 0x97, 0x6C, 0xD1, 0x11,
    0x82, 0x71, 0x00, 0xA0, 0x24, 0x42, 0xDF, 0x7D};

#define PN_APP_READY_RETRY_NS 1000000000ull

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
    uint16_t seq;
    uint32_t api;
    uint16_t slot;
    uint16_t subslot;
    uint16_t index;
    uint8_t aruuid[PN_UUID_LEN];
    int saw;
    int saw_uuid;
} read_walk_t;

typedef struct {
    uint16_t seq;
    uint32_t api;
    uint16_t slot;
    uint16_t subslot;
    uint16_t index;
    const uint8_t *data;
    uint32_t dlen;
    uint8_t aruuid[PN_UUID_LEN];
    int saw;
    int saw_uuid;
} write_walk_t;

typedef struct {
    uint16_t command;
    uint8_t aruuid[PN_UUID_LEN];
    int saw;
    int saw_uuid;
} ctrl_walk_t;

typedef struct {
    uint8_t aruuid[PN_UUID_LEN];
    int saw_uuid;
} uuid_walk_t;

static void copy_uuid(uint8_t *dst, const uint8_t *src)
{
    memcpy(dst, src, PN_UUID_LEN);
}

/* PNIO Block UUIDField is canonical (big-endian time fields). DCE/RPC
 * object/interface UUIDs are mixed-endian (time_low/mid/hi little-endian). */
static void uuid_pnio_to_dcerpc(uint8_t out[PN_UUID_LEN], const uint8_t in[PN_UUID_LEN])
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

static int aruuid_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, PN_UUID_LEN) == 0;
}

static int parse_read_req(uint16_t type, const uint8_t *body, uint16_t blen,
                          void *u)
{
    read_walk_t *r = u;
    /* IODReadReq body (after BlockVersion): seq(2) ARUUID(16) API(4)
     * slot(2) subslot(2) pad(2) index(2). The fixed header is 64 bytes;
     * these fields sit in the first 30. */
    if (type == PN_BLOCK_IOD_READ_REQ && blen >= 30) {
        r->seq = pn_rd_be16(body);
        copy_uuid(r->aruuid, body + 2);
        r->saw_uuid = 1;
        r->api = pn_rd_be32(body + 18);
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
    /* Header fields only. Record bytes are not inside RWPadding; they follow
     * the whole block (see attach_write_payload). */
    if (type == PN_BLOCK_IOD_WRITE_REQ && blen >= 34) {
        w->seq = pn_rd_be16(body);
        copy_uuid(w->aruuid, body + 2);
        w->saw_uuid = 1;
        w->api = pn_rd_be32(body + 18);
        w->slot = pn_rd_be16(body + 22);
        w->subslot = pn_rd_be16(body + 24);
        w->index = pn_rd_be16(body + 28);
        w->dlen = pn_rd_be32(body + 30);
        w->saw = 1;
    }
    return 0;
}

/* IODWriteReqHeader is 64 bytes (BlockLength 60). RecordDataLength bytes
 * start at the first byte after that block, not at the 24-byte RWPadding. */
static void attach_write_payload(const uint8_t *blocks, size_t n, write_walk_t *w)
{
    w->data = NULL;
    if (!w->saw) {
        w->dlen = 0;
        return;
    }
    size_t off = 0;
    while (off + 6 <= n) {
        uint16_t type = pn_rd_be16(blocks + off);
        uint16_t blen = pn_rd_be16(blocks + off + 2);
        if (blen < 2 || off + 4u + (size_t)blen > n) {
            break;
        }
        size_t total = 4u + (size_t)blen;
        if (type == PN_BLOCK_IOD_WRITE_REQ) {
            size_t avail = n - (off + total);
            if ((size_t)w->dlen > avail) {
                w->dlen = (uint32_t)avail;
            }
            if (w->dlen > 0) {
                w->data = blocks + off + total;
            }
            return;
        }
        off += total;
        if (off & 1u) {
            off++;
        }
    }
    w->dlen = 0;
}

static int parse_ctrl_req(uint16_t type, const uint8_t *body, uint16_t blen,
                          void *u)
{
    ctrl_walk_t *c = u;
    if (type == PN_BLOCK_CONTROL_REQ && blen >= 24) {
        /* pad(2) + ARUUID(16) + session(2) + reserved(2) + command(2) */
        copy_uuid(c->aruuid, body + 2);
        c->saw_uuid = 1;
        size_t cmd_off = (blen >= 26) ? 22u : 20u;
        c->command = pn_rd_be16(body + cmd_off);
        c->saw = 1;
    }
    return 0;
}

static int parse_uuid_any(uint16_t type, const uint8_t *body, uint16_t blen,
                          void *u)
{
    uuid_walk_t *w = u;
    if (w->saw_uuid) {
        return 0;
    }
    if ((type == PN_BLOCK_AR_REQ && blen >= 18) ||
        (type == PN_BLOCK_CONTROL_REQ && blen >= 18) ||
        (type == PN_BLOCK_RELEASE_REQ && blen >= 18) ||
        (type == PN_BLOCK_IOD_READ_REQ && blen >= 18) ||
        (type == PN_BLOCK_IOD_WRITE_REQ && blen >= 18)) {
        copy_uuid(w->aruuid, body + 2);
        w->saw_uuid = 1;
    }
    return 0;
}

static int ar_owner_ok(const pn_stack_t *s, uint32_t src_ip)
{
    if (s->ar.owner_ip == 0 || src_ip == 0) {
        return 1;
    }
    return s->ar.owner_ip == src_ip;
}

typedef struct {
    uint8_t initiator_uuid[PN_UUID_LEN];
    int have_initiator_uuid;
} connect_ident_t;

static int ar_same_controller(const pn_stack_t *s, uint32_t src_ip,
                              const connect_ident_t *id)
{
    if (src_ip != 0 && s->ar.owner_ip == src_ip) {
        return 1;
    }
    if (id && id->have_initiator_uuid && s->ar.have_initiator_uuid &&
        memcmp(s->ar.initiator_uuid, id->initiator_uuid, PN_UUID_LEN) == 0) {
        return 1;
    }
    return 0;
}

static void ar_touch_cmi(pn_stack_t *s)
{
    s->ar.last_cmi_ns = pn_now_ns();
}

static int ar_uuid_ok(const pn_stack_t *s, int saw_uuid, const uint8_t *uuid)
{
    if (!s->ar.established) {
        return 1;
    }
    if (!saw_uuid) {
        return 0;
    }
    return aruuid_eq(s->ar.uuid, uuid);
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

/* GSDML-V2.35: DAP ModuleIdent 0x00000001 carries the interface submodule
 * (subslot 0x8000, ident 0x0002). MOD_IO 0x00000010 / subslot 1 ident
 * 0x00000011 is the single IO image. DAP subslot 1 and port 0x8001 are
 * not in the GSDML (T12-13), so they are not plugged. */
static const struct {
    uint16_t slot;
    uint32_t mod_ident;
    uint16_t subslot;
    uint32_t sub_ident;
    int is_io;
} k_plugs[] = {
    {0, 0x00000001u, 0x8000, 0x00000002u, 0},
    {1, 0x00000010u, 1, 0x00000011u, 1},
};

int pn_real_mod_ident(uint16_t slot, uint32_t *mod_ident)
{
    for (size_t i = 0; i < sizeof(k_plugs) / sizeof(k_plugs[0]); i++) {
        if (k_plugs[i].slot == slot) {
            if (mod_ident) {
                *mod_ident = k_plugs[i].mod_ident;
            }
            return 1;
        }
    }
    return 0;
}

int pn_real_sub_find(uint16_t slot, uint16_t subslot, uint32_t *sub_ident,
                     int *is_io)
{
    for (size_t i = 0; i < sizeof(k_plugs) / sizeof(k_plugs[0]); i++) {
        if (k_plugs[i].slot == slot && k_plugs[i].subslot == subslot) {
            if (sub_ident) {
                *sub_ident = k_plugs[i].sub_ident;
            }
            if (is_io) {
                *is_io = k_plugs[i].is_io;
            }
            return 1;
        }
    }
    return 0;
}

static void store_iocr_ref(pn_iocr_ref_t *tab, uint8_t *n, uint32_t api,
                           uint16_t slot, uint16_t subslot, uint16_t off)
{
    if (*n >= PN_IOCR_REF_MAX) {
        LOG_WARN("pn_rpc", "IOCR object table full (slot %u subslot 0x%04x)",
                 slot, subslot);
        return;
    }
    tab[*n].api = api;
    tab[*n].slot = slot;
    tab[*n].subslot = subslot;
    tab[*n].frame_off = off;
    (*n)++;
}

/* IOCRBlockReq body after BlockVersion. API list starts at offset 38:
 * NumberOfAPIs, then API, NumberOfIODataObjects, (Slot, Subslot,
 * FrameOffset)*, NumberOfIOCS, (Slot, Subslot, FrameOffset)*.
 * Returns 1 when at least one object was stored. */
static int parse_iocr_layout(const uint8_t *body, uint16_t blen, pn_ar_t *ar,
                             int is_input)
{
    if (blen < 40) {
        return 0;
    }
    uint16_t napis = pn_rd_be16(body + 38);
    size_t off = 40;
    pn_iocr_ref_t *data = is_input ? ar->in_io : ar->out_io;
    uint8_t *data_n = is_input ? &ar->in_io_n : &ar->out_io_n;
    pn_iocr_ref_t *iocs = is_input ? ar->in_iocs : ar->out_iocs;
    uint8_t *iocs_n = is_input ? &ar->in_iocs_n : &ar->out_iocs_n;
    uint8_t before = (uint8_t)(*data_n + *iocs_n);
    for (uint16_t a = 0; a < napis; a++) {
        if (off + 6 > blen) {
            break;
        }
        uint32_t api = pn_rd_be32(body + off);
        off += 4;
        uint16_t nobj = pn_rd_be16(body + off);
        off += 2;
        for (uint16_t i = 0; i < nobj; i++) {
            if (off + 6 > blen) {
                return (*data_n + *iocs_n) > before;
            }
            store_iocr_ref(data, data_n, api, pn_rd_be16(body + off),
                           pn_rd_be16(body + off + 2), pn_rd_be16(body + off + 4));
            off += 6;
        }
        if (off + 2 > blen) {
            break;
        }
        uint16_t niocs = pn_rd_be16(body + off);
        off += 2;
        for (uint16_t i = 0; i < niocs; i++) {
            if (off + 6 > blen) {
                return (*data_n + *iocs_n) > before;
            }
            store_iocr_ref(iocs, iocs_n, api, pn_rd_be16(body + off),
                           pn_rd_be16(body + off + 2), pn_rd_be16(body + off + 4));
            off += 6;
        }
    }
    return (*data_n + *iocs_n) > before;
}

/* ExpectedSubmoduleBlockReq. NO_IO(0), INPUT(1) and OUTPUT(2) each have
 * one DataDescription; INPUT_OUTPUT(3) has input then output.
 * Wireshark dissect_ExpectedSubmoduleBlockReq case 0x00: one Input
 * DataDescription follows. p-net reads at least one descriptor (two
 * only when Type is INPUT_OUTPUT). */
static void parse_expected_submodules(const uint8_t *body, uint16_t blen,
                                      pn_ar_t *ar)
{
    if (blen < 2) {
        return;
    }
    uint16_t napis = pn_rd_be16(body);
    size_t off = 2;
    for (uint16_t a = 0; a < napis; a++) {
        if (off + 14 > blen) {
            return;
        }
        uint32_t api = pn_rd_be32(body + off);
        off += 4;
        uint16_t slot = pn_rd_be16(body + off);
        off += 2;
        uint32_t mod = pn_rd_be32(body + off);
        off += 4;
        off += 2; /* ModuleProperties */
        uint16_t nsub = pn_rd_be16(body + off);
        off += 2;
        for (uint16_t s = 0; s < nsub; s++) {
            if (off + 8 > blen) {
                return;
            }
            uint16_t sub = pn_rd_be16(body + off);
            uint32_t sident = pn_rd_be32(body + off + 2);
            uint16_t props = pn_rd_be16(body + off + 6);
            off += 8;
            unsigned type = props & 3u;
            int ndesc = (type == 3) ? 2 : 1;
            pn_exp_sub_t *e = NULL;
            if (ar->exp_sub_n < PN_EXP_SUB_MAX) {
                e = &ar->exp_sub[ar->exp_sub_n++];
                e->api = api;
                e->slot = slot;
                e->mod_ident = mod;
                e->subslot = sub;
                e->sub_ident = sident;
                e->props = props;
            } else {
                LOG_WARN("pn_rpc", "ExpectedSubmodule table full");
            }
            for (int d = 0; d < ndesc; d++) {
                if (off + 6 > blen) {
                    return;
                }
                uint16_t dir = pn_rd_be16(body + off);
                uint16_t dlen = pn_rd_be16(body + off + 2);
                uint8_t liops = body[off + 5];
                off += 6;
                if (!e) {
                    continue;
                }
                if (dir == 1) {
                    e->has_in = 1;
                    e->in_len = dlen;
                    e->in_iops = liops;
                } else if (dir == 2) {
                    e->has_out = 1;
                    e->out_len = dlen;
                    e->out_iops = liops;
                }
            }
        }
    }
}

static int parse_ar_iocr(uint16_t type, const uint8_t *body, uint16_t blen,
                         void *u)
{
    pn_ar_t *ar = u;
    /* ARType(2) + ARUUID(16) + SessionKey(2) + CMInitiatorMacAdd(6).
     * 16+2+6 omitted the ARType and read the MAC 2 bytes past a
     * 24-byte body (fuzz_pn_rpc heap-buffer-overflow). */
    if (type == PN_BLOCK_AR_REQ && blen >= 2 + 16 + 2 + 6) {
        memcpy(ar->uuid, body + 2, PN_UUID_LEN);
        ar->session_key = pn_rd_be16(body + 2 + 16);
        memcpy(ar->initiator_mac, body + 2 + 16 + 2, 6);
        if (blen >= 42) {
            memcpy(ar->initiator_uuid, body + 26, PN_UUID_LEN);
            ar->have_initiator_uuid = 1;
        }
        /* ARProperties is 4 bytes at body offset 42. Bit 30 is
         * StartupMode (1 = Advanced). A short AR block is Legacy. */
        if (blen >= 46) {
            uint32_t props = pn_rd_be32(body + 42);
            ar->startup_advanced = (props & (1u << 30)) != 0;
        }
        /* ARProperties(4) + ActivityTimeoutFactor(2) + UDPRTPort(2) */
        if (blen >= 50) {
            ar->initiator_udp_rt_port = pn_rd_be16(body + 48);
        }
    } else if (type == PN_BLOCK_IOCR_REQ && blen >= 18) {
        uint16_t iocr_type = pn_rd_be16(body);
        uint16_t data_len = pn_rd_be16(body + 10);
        uint16_t frame_id = pn_rd_be16(body + 12);
        uint16_t sc = pn_rd_be16(body + 14);
        uint16_t rr = pn_rd_be16(body + 16);
        int is_out = (iocr_type == PN_IOCR_OUTPUT);
        int is_in = (iocr_type == PN_IOCR_INPUT);
        /* Data-hold watches O→T, so only the output CR supplies that
         * clock. The input CR clock is the RTC1 transmit period and
         * CycleCounter step. Neither CR may replace the other. */
        if (is_out) {
            ar->send_clock_factor = sc;
            ar->reduction_ratio = rr;
            /* IOCRBlockReq: WatchdogFactor @26, DataHoldFactor @28. */
            if (blen >= 28) {
                uint16_t wdog = pn_rd_be16(body + 26);
                uint16_t dhold = (blen >= 30) ? pn_rd_be16(body + 28) : 0;
                if (dhold != 0) {
                    ar->data_hold_factor = dhold;
                } else if (wdog != 0) {
                    ar->data_hold_factor = wdog;
                }
            }
            ar->out_frame_id = frame_id;
            ar->out_csdu_len = data_len;
        } else if (is_in) {
            ar->in_frame_id = frame_id;
            ar->in_csdu_len = data_len;
            ar->in_send_clock_factor = sc;
            ar->in_reduction_ratio = rr;
        }
        if (is_in || is_out) {
            int laid = parse_iocr_layout(body, blen, ar, is_in);
            if (laid) {
                if (is_in) {
                    ar->have_in_layout = 1;
                } else {
                    ar->have_out_layout = 1;
                }
            } else {
                /* No IODataObject list: keep the previous fixed-layout
                 * length (DataLength minus the single IOPS byte). */
                uint16_t legacy = data_len > 1 ? (uint16_t)(data_len - 1) : 0;
                if (is_out) {
                    ar->out_data_len = legacy;
                } else {
                    ar->in_data_len = legacy;
                }
            }
        }
    } else if (type == PN_BLOCK_EXPSUB_REQ) {
        parse_expected_submodules(body, blen, ar);
    } else if (type == PN_BLOCK_ALARMCR_REQ && blen >= 14) {
        /* AlarmCRType(2) LT(2) Properties(4) RTATimeoutFactor(2)
         * RTARetries(2) LocalAlarmReference(2). The reference is the
         * controller endpoint our alarms must address. */
        ar->rta_timeout_factor = pn_rd_be16(body + 8);
        ar->rta_retries = pn_rd_be16(body + 10);
        ar->alarm_dst_ref = pn_rd_be16(body + 12);
        ar->have_alarm_cr = 1;
    }
    return 0;
}

static int verify_connect_sec(pn_stack_t *s, const uint8_t *blocks, size_t n)
{
    if (s->cfg.security_class < PN_VENDOR_INTEGRITY) {
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
        LOG_WARN("pn_rpc",
                 "vendor integrity extension: Connect 에 integrity block 없음");
        return -EPERM;
    }
    if (!pn_sec_ok(s, rebuilt, rn, mac)) {
        LOG_WARN("pn_rpc",
                 "vendor integrity extension: Connect HMAC 불일치");
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

/* IODReadResHeader (0x8009) or IODWriteResHeader (0x8008): fixed 64 bytes
 * (BlockLength 60). Read appends record bytes; write does not. */
static size_t iod_rw_res(uint8_t *out, size_t cap, uint16_t type, uint16_t seq,
                         const uint8_t aruuid[PN_UUID_LEN], uint32_t api,
                         uint16_t slot, uint16_t subslot, uint16_t index,
                         uint32_t record_len, const uint8_t *rec, size_t rec_len)
{
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, seq);
    if (aruuid) {
        memcpy(body + 2, aruuid, PN_UUID_LEN);
    }
    pn_wr_be32(body + 18, api);
    pn_wr_be16(body + 22, slot);
    pn_wr_be16(body + 24, subslot);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, record_len);
    if (cap < 64u + rec_len) {
        return 0;
    }
    size_t n = wr_block(out, type, body, sizeof(body));
    if (rec_len > 0 && rec) {
        memcpy(out + n, rec, rec_len);
        n += rec_len;
    }
    return n;
}

/* SubmoduleState: format indicator (bit 15) and IdentInfo (bits 11..14).
 * ARInfo OWN is 0. See PN services Table 215/216. */
#define PN_SUBSTATE_WRONG ((uint16_t)(0x8000u | (2u << 11)))
#define PN_SUBSTATE_NO    ((uint16_t)(0x8000u | (3u << 11)))
#define PN_MOD_NO         0u
#define PN_MOD_PROPER     2u
#define PN_MOD_SUBSTITUTE 3u /* Table 214: avoid WRONG_MODULE when one is plugged */

static int append_block(uint8_t *out, size_t cap, size_t *n, uint16_t type,
                        const uint8_t *body, uint16_t body_len)
{
    size_t add = 6u + (size_t)body_len;
    if (add & 1u) {
        add++;
    }
    if (*n + add > cap) {
        LOG_WARN("pn_rpc", "Connect response block 0x%04x does not fit", type);
        return -1;
    }
    *n += wr_block(out + *n, type, body, body_len);
    return 0;
}

/* ModuleDiffBlock body. Omitted (return 0) when nothing differs.
 * A plugged-but-wrong module is SUBSTITUTE and reports the real ident.
 * NumberOfSubmodules is 0 when the slot is empty. */
static size_t build_module_diff_body(const pn_ar_t *ar, uint8_t *body, size_t cap)
{
    if (ar->exp_sub_n == 0 || cap < 2) {
        return 0;
    }
    uint8_t apis[640];
    size_t an = 0;
    uint16_t napi = 0;
    uint8_t i = 0;
    while (i < ar->exp_sub_n) {
        uint32_t api = ar->exp_sub[i].api;
        uint8_t api_end = i;
        while (api_end < ar->exp_sub_n && ar->exp_sub[api_end].api == api) {
            api_end++;
        }
        uint8_t mods[512];
        size_t mn = 0;
        uint16_t nmod = 0;
        uint8_t m = i;
        while (m < api_end) {
            uint16_t slot = ar->exp_sub[m].slot;
            uint32_t exp_mod = ar->exp_sub[m].mod_ident;
            uint8_t mend = m;
            while (mend < api_end && ar->exp_sub[mend].slot == slot &&
                   ar->exp_sub[mend].mod_ident == exp_mod) {
                mend++;
            }
            uint32_t real_mod = 0;
            int have_mod = pn_real_mod_ident(slot, &real_mod);
            uint8_t subs[256];
            size_t sn = 0;
            uint16_t nsub = 0;
            uint16_t mod_state;
            uint32_t report_ident;
            if (!have_mod) {
                mod_state = PN_MOD_NO;
                report_ident = 0;
            } else if (real_mod != exp_mod) {
                mod_state = PN_MOD_SUBSTITUTE;
                report_ident = real_mod;
                for (uint8_t s = m; s < mend; s++) {
                    uint32_t real_sub = 0;
                    int is_io = 0;
                    int have_sub = pn_real_sub_find(slot, ar->exp_sub[s].subslot,
                                                    &real_sub, &is_io);
                    if (sn + 8 > sizeof(subs)) {
                        break;
                    }
                    pn_wr_be16(subs + sn, ar->exp_sub[s].subslot);
                    pn_wr_be32(subs + sn + 2, have_sub ? real_sub : 0);
                    pn_wr_be16(subs + sn + 6,
                               have_sub ? PN_SUBSTATE_WRONG : PN_SUBSTATE_NO);
                    sn += 8;
                    nsub++;
                }
            } else {
                mod_state = PN_MOD_PROPER;
                report_ident = real_mod;
                for (uint8_t s = m; s < mend; s++) {
                    uint32_t real_sub = 0;
                    int is_io = 0;
                    int have_sub = pn_real_sub_find(slot, ar->exp_sub[s].subslot,
                                                    &real_sub, &is_io);
                    int differ = !have_sub || real_sub != ar->exp_sub[s].sub_ident;
                    if (!differ) {
                        continue;
                    }
                    if (sn + 8 > sizeof(subs)) {
                        break;
                    }
                    pn_wr_be16(subs + sn, ar->exp_sub[s].subslot);
                    pn_wr_be32(subs + sn + 2, have_sub ? real_sub : 0);
                    pn_wr_be16(subs + sn + 6,
                               have_sub ? PN_SUBSTATE_WRONG : PN_SUBSTATE_NO);
                    sn += 8;
                    nsub++;
                }
                if (nsub == 0) {
                    m = mend;
                    continue;
                }
            }
            if (mn + 10u + sn > sizeof(mods)) {
                LOG_WARN("pn_rpc", "ModuleDiff truncated");
                break;
            }
            pn_wr_be16(mods + mn, slot);
            pn_wr_be32(mods + mn + 2, report_ident);
            pn_wr_be16(mods + mn + 6, mod_state);
            mn += 8;
            pn_wr_be16(mods + mn, nsub);
            mn += 2;
            if (sn > 0) {
                memcpy(mods + mn, subs, sn);
                mn += sn;
            }
            nmod++;
            m = mend;
        }
        if (nmod > 0 && an + 6u + mn <= sizeof(apis)) {
            pn_wr_be32(apis + an, api);
            an += 4;
            pn_wr_be16(apis + an, nmod);
            an += 2;
            memcpy(apis + an, mods, mn);
            an += mn;
            napi++;
        }
        i = api_end;
    }
    if (napi == 0 || 2u + an > cap) {
        return 0;
    }
    pn_wr_be16(body, napi);
    memcpy(body + 2, apis, an);
    return 2u + an;
}

/* ARServerBlock body. The whole block (header included) is a multiple of
 * 4; wr_block's total is 6 + body, so body ≡ 2 (mod 4). */
static uint16_t ar_server_body(const pn_stack_t *s, uint8_t *body, size_t cap)
{
    size_t name_len = strlen(s->cfg.station_name);
    if (name_len > PN_STATION_NAME_MAX) {
        name_len = PN_STATION_NAME_MAX;
    }
    if (cap < 2u + name_len + 3u) {
        return 0;
    }
    pn_wr_be16(body, (uint16_t)name_len);
    memcpy(body + 2, s->cfg.station_name, name_len);
    size_t n = 2u + name_len;
    while ((n % 4u) != 2u) {
        body[n++] = 0;
    }
    return (uint16_t)n;
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
    /* RT_CLASS_1 CMResponderUDPRTPort is the L2 RT marker 0x8892, the
     * same role as CMInitiatorUDPRTPort. PN_RPC_PORT (0x8894) is the
     * CM RPC socket, not this field. */
    pn_wr_be16(ar + 26, PN_ETHTYPE_PN);
    if (append_block(out, cap, &n, PN_BLOCK_AR_RES, ar, sizeof(ar)) != 0) {
        return 0;
    }

    uint8_t iocr_in[6];
    pn_wr_be16(iocr_in, PN_IOCR_INPUT);
    pn_wr_be16(iocr_in + 2, 1);
    pn_wr_be16(iocr_in + 4, s->ar.in_frame_id ? s->ar.in_frame_id : 0x8001);
    if (append_block(out, cap, &n, PN_BLOCK_IOCR_RES, iocr_in, sizeof(iocr_in)) !=
        0) {
        return 0;
    }

    uint8_t iocr_out[6];
    pn_wr_be16(iocr_out, PN_IOCR_OUTPUT);
    pn_wr_be16(iocr_out + 2, 2);
    pn_wr_be16(iocr_out + 4, s->ar.out_frame_id ? s->ar.out_frame_id : 0x8002);
    if (append_block(out, cap, &n, PN_BLOCK_IOCR_RES, iocr_out,
                     sizeof(iocr_out)) != 0) {
        return 0;
    }

    /* AlarmCRType, LocalAlarmReference (this device), MaxAlarmDataLength.
     * BlockLength is 8. The response has no tag header. */
    uint8_t alarm[6];
    memset(alarm, 0, sizeof(alarm));
    pn_wr_be16(alarm, 0x0001);
    pn_wr_be16(alarm + 2, s->ar.alarm_src_ref ? s->ar.alarm_src_ref : 1);
    pn_wr_be16(alarm + 4, 200);
    if (append_block(out, cap, &n, PN_BLOCK_ALARMCR_RES, alarm, sizeof(alarm)) !=
        0) {
        return 0;
    }

    uint8_t diff[768];
    size_t dn = build_module_diff_body(&s->ar, diff, sizeof(diff));
    if (dn > 0 && dn <= 0xFFFFu) {
        if (append_block(out, cap, &n, PN_BLOCK_MOD_DIFF, diff, (uint16_t)dn) !=
            0) {
            return 0;
        }
    }

    /* ARServerBlock only in advanced startup mode. A Legacy Connect
     * response that carries it is rejected by the controller. */
    if (s->ar.startup_advanced) {
        uint8_t server[2 + PN_STATION_NAME_MAX + 4];
        uint16_t sn = ar_server_body(s, server, sizeof(server));
        if (sn > 0) {
            if (append_block(out, cap, &n, PN_BLOCK_AR_SERVER, server, sn) !=
                0) {
                return 0;
            }
        }
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
    /* Do not use `20 + n > len`: n==UINT32_MAX wraps and accepts a 4 GiB
     * window, then walk_blocks reads off the stub (fuzz SEGV). */
    if (n > len - 20) {
        n = (uint32_t)(len - 20);
    }
    *blen = n;
    return stub + 20;
}

/* Request NDR (device-originated calls such as ApplicationReady):
 * ArgsMaximum, ArgsLength, MaximumCount, Offset, ActualCount, blocks. */
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

/* Response NDR: PNIOStatus, ArgsLength, MaxCount, Offset, ActualCount, blocks.
 * status is ErrorCode, ErrorDecode, ErrorCode1, ErrorCode2 (NULL = OK).
 * Length words are little-endian and count the block bytes that follow. */
static size_t ndr_res(uint8_t *out, const uint8_t status[4],
                      const uint8_t *blocks, size_t n)
{
    if (status) {
        memcpy(out, status, 4);
    } else {
        memset(out, 0, 4);
    }
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    if (n > 0 && blocks) {
        memcpy(out + 20, blocks, n);
    }
    return 20u + n;
}

static void fill_activity_uuid(uint8_t *u)
{
    static uint32_t seq;
    uint64_t t = pn_now_ns();
    memset(u, 0, PN_UUID_LEN);
    pn_wr_be32(u, (uint32_t)(t >> 32));
    pn_wr_be32(u + 4, (uint32_t)t);
    pn_wr_be32(u + 8, ++seq);
    u[12] = 0x80;
    u[13] = 0x00;
    u[14] = 0x40;
    u[15] = 0x04;
}

static void clear_pending_rpc(pn_stack_t *s)
{
    s->pending_rpc_tx_len = 0;
    s->pending_rpc_tx_ns = 0;
}

static size_t wrap_rpc_req(uint8_t *out, size_t cap, uint16_t op,
                           const uint8_t *stub, size_t stub_len,
                           const uint8_t *object_uuid)
{
    if (cap < RPC_HDR + stub_len) {
        return 0;
    }
    memset(out, 0, RPC_HDR);
    out[0] = 4; /* DCE/RPC connectionless */
    out[1] = RPC_PT_REQUEST;
    out[2] = 0x20; /* idempotent */
    out[4] = 0x10; /* drep: little-endian integers */
    if (object_uuid) {
        uuid_pnio_to_dcerpc(out + 8, object_uuid);
    }
    memcpy(out + 24, k_pnio_controller_if, PN_UUID_LEN);
    fill_activity_uuid(out + 40);
    pn_wr_le32(out + 60, 1); /* if_vers */
    pn_wr_le16(out + 68, op);
    pn_wr_le16(out + 70, 0xFFFF);
    pn_wr_le16(out + 72, 0xFFFF);
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
    size_t bn = wr_block(blocks, PN_BLOCK_APP_READY_REQ, body, sizeof(body));
    uint8_t stub[128];
    size_t sn = ndr_wrap(stub, blocks, bn);
    const uint8_t *obj =
        s->ar.have_initiator_uuid ? s->ar.initiator_uuid : NULL;
    s->pending_rpc_tx_len =
        wrap_rpc_req(s->pending_rpc_tx, sizeof(s->pending_rpc_tx), OP_CONTROL,
                     stub, sn, obj);
    s->pending_rpc_tx_ns = 0;
    s->ar.app_ready = 1;
    LOG_INFO("pn_rpc", "queued ApplicationReady indication");
}

/* PNIOStatus as ErrorCode<<24 | ErrorDecode<<16 | ErrorCode1<<8 | ErrorCode2.
 * Written in little-endian drep order (this stack always emits LE NDR;
 * a big-endian request is T12-14). Logical DB 81 02 0B is bytes 0B 02 81 DB.
 *
 * Cycle rejects use the IOCR codes below. Other rejects still pass
 * PN_PNIO_ERR_LEGACY (0x81000000). Queue 59 owns the other-controller
 * status DB 81 40 04 and must stay xfail after this change. */
#define PN_PNIO_ERR_LEGACY  (0x81u << 24)
/* ErrorCode2 10 = GatingCycle / SendClockFactor (Wireshark pn_io_error_code2_pnio_2). */
#define PN_PNIO_ERR_IOCR_SCF 0xDB81020Au
/* ErrorCode2 11 = ReductionRatio, including a period below cycle_us. */
#define PN_PNIO_ERR_IOCR_RR  0xDB81020Bu

static int reply_pnio_err(const uint8_t *pdu, uint8_t *resp, size_t cap,
                          size_t *out_len, uint8_t *stub_out,
                          uint32_t pnio_status)
{
    /* Connect.rsp stub: PNIOStatus, ArgsLength=0, MaxCount=0, Offset=0,
     * ActualCount=0. No blocks. */
    uint8_t status[4];
    pn_wr_le32(status, pnio_status);
    size_t so = ndr_res(stub_out, status, NULL, 0);
    *out_len = wrap_rpc_resp(pdu, resp, cap, stub_out, so);
    return 0;
}

/* Input IOCR only. This device is RT Class 1, so the same rules apply
 * whether or not the request filled IOCRProperties.RTClass.
 *
 * p-net pf_cmdev_check_iocr_param / pf_cmdev_check_iocr_param_full:
 * - SCF not in {1,2,4,8,16,32,64,128} → ErrorCode2 10 (DB 81 02 0A).
 * - RR outside 1..512, or RR >= 256 with SCF > 64, or RR == 512 with
 *   SCF > 32 → ErrorCode2 11 (DB 81 02 0B). RR need not be a power of two.
 * - If those pass and SCF×RR×31.25 µs < cfg.cycle_us → ErrorCode2 11.
 *   cfg.cycle_us is the fastest update the device can produce.
 *
 * Output CR timing is the controller's send clock and is not limited
 * here. No input IOCR (AR-only Connect) is not a short-cycle request.
 * GSDML SendClock="32" is what we advertise; a factor still inside the
 * RT Class 1 set is not rejected for that advertisement. */
typedef struct {
    uint32_t min_us;
    uint32_t err;
} iocr_min_t;

/* 1, 2, 4, ..., 128. Zero and values above 128 are not in the set. */
static int scf_rt_class_1(uint16_t sc)
{
    return sc >= 1 && sc <= 128 && (sc & (uint16_t)(sc - 1u)) == 0;
}

static int check_input_iocr_min(uint16_t type, const uint8_t *body,
                                uint16_t blen, void *u)
{
    iocr_min_t *c = u;
    if (c->err != 0 || type != PN_BLOCK_IOCR_REQ || blen < 18) {
        return 0;
    }
    if (pn_rd_be16(body) != PN_IOCR_INPUT) {
        return 0;
    }
    uint16_t sc = pn_rd_be16(body + 14);
    uint16_t rr = pn_rd_be16(body + 16);
    if (!scf_rt_class_1(sc)) {
        c->err = PN_PNIO_ERR_IOCR_SCF;
        LOG_WARN("pn_rpc",
                 "Connect rejected: SendClockFactor %u not in 1/2/4/.../128 "
                 "PNIOStatus DB 81 02 0A",
                 sc);
        return 0;
    }
    if (rr < 1 || rr > 512 || (rr >= 256 && sc > 64) || (rr == 512 && sc > 32)) {
        c->err = PN_PNIO_ERR_IOCR_RR;
        LOG_WARN("pn_rpc",
                 "Connect rejected: ReductionRatio %u SendClockFactor %u "
                 "outside RT Class 1 range PNIOStatus DB 81 02 0B",
                 rr, sc);
        return 0;
    }
    uint64_t period_ns = (uint64_t)sc * (uint64_t)rr * PN_SEND_CLOCK_BASE_NS;
    uint64_t min_ns = (uint64_t)c->min_us * 1000ull;
    if (period_ns < min_ns) {
        c->err = PN_PNIO_ERR_IOCR_RR;
        LOG_WARN("pn_rpc",
                 "Connect rejected: input period %u*%u*31.25us < cycle_us %u "
                 "PNIOStatus DB 81 02 0B",
                 sc, rr, c->min_us);
        return 0;
    }
    return 0;
}

static int consume_app_ready_res(pn_stack_t *s, const uint8_t *stub, size_t slen)
{
    if (s->pending_rpc_tx_len == 0) {
        return -EINVAL;
    }
    size_t blen = 0;
    const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
    if (!blocks || blen < 2) {
        return -EINVAL;
    }
    if (pn_rd_be16(blocks) != PN_BLOCK_APP_READY_RES) {
        return -EINVAL;
    }
    clear_pending_rpc(s);
    LOG_INFO("pn_rpc", "ApplicationReady confirmed (0x8112)");
    return 0;
}

static void app_ready_dest(const pn_stack_t *s, struct sockaddr_in *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->sin_family = AF_INET;
    /* ApplicationReady is DCE/RPC to the controller PNIO RPC server.
     * The UDP port is always PN_RPC_PORT (34964 / 0x8894).
     * CMInitiatorUDPRTPort is an RT marker, not this destination. */
    uint16_t port = PN_RPC_PORT;
    dst->sin_port = htons(port);
    if (s->ar.owner_ip != 0) {
        dst->sin_addr.s_addr = htonl(s->ar.owner_ip);
    } else if (s->rpc_peer_set) {
        dst->sin_addr = s->rpc_peer.sin_addr;
    }
}

static void flush_pending_rpc(pn_stack_t *s)
{
    if (s->fd_rpc < 0 || s->pending_rpc_tx_len == 0) {
        return;
    }
    if (!s->ar.established) {
        clear_pending_rpc(s);
        return;
    }
    struct sockaddr_in dst;
    app_ready_dest(s, &dst);
    if (dst.sin_addr.s_addr == 0) {
        return;
    }
    uint64_t now = pn_now_ns();
    if (s->pending_rpc_tx_ns != 0 &&
        now - s->pending_rpc_tx_ns < PN_APP_READY_RETRY_NS) {
        return;
    }
    sendto(s->fd_rpc, s->pending_rpc_tx, s->pending_rpc_tx_len, 0,
           (struct sockaddr *)&dst, sizeof(dst));
    s->pending_rpc_tx_ns = now;
}

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len, uint32_t src_ip)
{
    if (len < RPC_HDR) {
        return -EINVAL;
    }
    uint8_t ptype = pdu[1];
    uint16_t op = pn_rd_le16(pdu + 68);
    const uint8_t *stub = pdu + RPC_HDR;
    size_t slen = len - RPC_HDR;
    uint16_t declared = pn_rd_le16(pdu + 74);
    if (declared < slen) {
        slen = declared;
    }
    if (ptype == RPC_PT_RESPONSE) {
        *out_len = 0;
        if (op != OP_CONTROL) {
            return -EINVAL;
        }
        return consume_app_ready_res(s, stub, slen);
    }
    if (ptype != RPC_PT_REQUEST) {
        return -EINVAL;
    }

    uint8_t stub_out[2048];
    size_t so = 0;

    if (op == OP_CONNECT) {
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (!blocks) {
            return -EINVAL;
        }
        /* Security, block parse, and ownership all finish against a
         * temporary AR. A rejected Connect does not touch s->ar. */
        if (verify_connect_sec(s, blocks, blen) != 0) {
            return reply_pnio_err(pdu, resp, cap, out_len, stub_out,
                                  PN_PNIO_ERR_LEGACY);
        }
        pn_ar_t parsed;
        memset(&parsed, 0, sizeof(parsed));
        if (walk_blocks(blocks, blen, parse_ar_iocr, &parsed) != 0) {
            return reply_pnio_err(pdu, resp, cap, out_len, stub_out,
                                  PN_PNIO_ERR_LEGACY);
        }
        iocr_min_t min_ck;
        memset(&min_ck, 0, sizeof(min_ck));
        min_ck.min_us = s->cfg.cycle_us;
        (void)walk_blocks(blocks, blen, check_input_iocr_min, &min_ck);
        if (min_ck.err != 0) {
            return reply_pnio_err(pdu, resp, cap, out_len, stub_out, min_ck.err);
        }
        connect_ident_t ident;
        memset(&ident, 0, sizeof(ident));
        ident.have_initiator_uuid = parsed.have_initiator_uuid;
        if (parsed.have_initiator_uuid) {
            memcpy(ident.initiator_uuid, parsed.initiator_uuid, PN_UUID_LEN);
        }
        if (s->ar.established && !ar_same_controller(s, src_ip, &ident)) {
            LOG_WARN("pn_rpc", "Connect rejected: AR already established");
            return reply_pnio_err(pdu, resp, cap, out_len, stub_out,
                                  PN_PNIO_ERR_LEGACY);
        }
        if (parsed.in_frame_id == 0) {
            parsed.in_frame_id = 0x8001;
        }
        if (parsed.out_frame_id == 0) {
            parsed.out_frame_id = 0x8002;
        }
        /* A parsed IODataObject list owns the C_SDU length. Without one,
         * keep the fixed layout sized from config. */
        if (!parsed.have_in_layout && parsed.in_data_len == 0) {
            parsed.in_data_len = s->cfg.input_len;
        }
        if (!parsed.have_out_layout && parsed.out_data_len == 0) {
            parsed.out_data_len = s->cfg.output_len;
        }
        parsed.established = 1;
        parsed.owner_ip = src_ip;
        parsed.last_cmi_ns = pn_now_ns();
        pn_alarm_arm(&parsed);
        if (s->ar.established) {
            LOG_INFO("pn_rpc", "same-controller Connect replaces established AR");
        }
        s->ar = parsed;
        s->last_rt_ns = 0;
        clear_pending_rpc(s);
        uint8_t blocks_res[1280];
        size_t bn = build_connect_res_blocks(s, blocks_res, sizeof(blocks_res));
        so = ndr_res(stub_out, NULL, blocks_res, bn);
        LOG_INFO("pn_rpc",
                 "AR established in_fid=0x%04x out_fid=0x%04x in=%u out=%u",
                 s->ar.in_frame_id, s->ar.out_frame_id,
                 s->ar.have_in_layout ? s->ar.in_csdu_len : s->ar.in_data_len,
                 s->ar.have_out_layout ? s->ar.out_csdu_len : s->ar.out_data_len);
    } else if (op == OP_RELEASE) {
        int had_ar = s->ar.established;
        uint8_t rel_uuid[PN_UUID_LEN];
        uint16_t rel_session = 0;
        memset(rel_uuid, 0, sizeof(rel_uuid));
        if (had_ar) {
            memcpy(rel_uuid, s->ar.uuid, PN_UUID_LEN);
            rel_session = s->ar.session_key;
            if (!ar_owner_ok(s, src_ip)) {
                LOG_WARN("pn_rpc", "Release rejected: sender IP mismatch");
                return -EPERM;
            }
            uuid_walk_t uw;
            memset(&uw, 0, sizeof(uw));
            size_t blen = 0;
            const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
            if (blocks) {
                walk_blocks(blocks, blen, parse_uuid_any, &uw);
            }
            if (!uw.saw_uuid && slen >= 20 + PN_UUID_LEN) {
                /* NDR payload may be a raw UUID without a block header. */
                copy_uuid(uw.aruuid, stub + 20);
                uw.saw_uuid = 1;
            }
            if (!ar_uuid_ok(s, uw.saw_uuid, uw.aruuid)) {
                LOG_WARN("pn_rpc", "Release rejected: ARUUID mismatch");
                return -EPERM;
            }
        }
        s->ar.established = 0;
        memset(&s->ar, 0, sizeof(s->ar));
        clear_pending_rpc(s);
        if (had_ar) {
            /* ReleaseBlockRes 0x8114. Same body as IODControlRes:
             * pad, ARUUID, SessionKey, AlarmSequenceNumber,
             * ControlCommand Done. */
            uint8_t cres[26];
            memset(cres, 0, sizeof(cres));
            memcpy(cres + 2, rel_uuid, PN_UUID_LEN);
            pn_wr_be16(cres + 18, rel_session);
            pn_wr_be16(cres + 22, PN_CONTROL_DONE);
            uint8_t blocks_res[64];
            size_t bn = wr_block(blocks_res, PN_BLOCK_RELEASE_RES, cres,
                                 sizeof(cres));
            so = ndr_res(stub_out, NULL, blocks_res, bn);
        } else {
            uint8_t z[4] = {0};
            so = ndr_res(stub_out, NULL, z, 4);
        }
        LOG_INFO("pn_rpc", "AR released");
    } else if (op == OP_CONTROL) {
        if (!s->ar.established) {
            LOG_WARN("pn_rpc", "Control without AR — fail closed (no RTC1)");
            return -EINVAL;
        }
        if (!ar_owner_ok(s, src_ip)) {
            LOG_WARN("pn_rpc", "Control rejected: sender IP mismatch");
            return -EPERM;
        }
        ctrl_walk_t cw;
        memset(&cw, 0, sizeof(cw));
        cw.command = PN_CONTROL_PRM_END;
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_ctrl_req, &cw);
        }
        if (!cw.saw) {
            cw.command = PN_CONTROL_PRM_END;
        }
        if (!ar_uuid_ok(s, cw.saw_uuid, cw.aruuid)) {
            LOG_WARN("pn_rpc", "Control rejected: ARUUID mismatch");
            return -EPERM;
        }
        uint8_t cres[26];
        memset(cres, 0, sizeof(cres));
        memcpy(cres + 2, s->ar.uuid, 16);
        pn_wr_be16(cres + 18, s->ar.session_key);
        pn_wr_be16(cres + 22, PN_CONTROL_DONE);
        uint8_t blocks_res[64];
        size_t bn = wr_block(blocks_res, PN_BLOCK_CONTROL_RES, cres,
                             sizeof(cres));
        so = ndr_res(stub_out, NULL, blocks_res, bn);
        s->ar.established = 1;
        ar_touch_cmi(s);
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
        read_walk_t rw;
        memset(&rw, 0, sizeof(rw));
        rw.slot = 0;
        rw.subslot = 1;
        rw.index = PN_INDEX_IM0;
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_read_req, &rw);
        }
        if (s->ar.established) {
            if (!ar_owner_ok(s, src_ip)) {
                LOG_WARN("pn_rpc", "Read rejected: sender IP mismatch");
                return -EPERM;
            }
            if (!ar_uuid_ok(s, rw.saw_uuid, rw.aruuid)) {
                LOG_WARN("pn_rpc", "Read rejected: ARUUID mismatch");
                return -EPERM;
            }
            ar_touch_cmi(s);
        }
        pn_record_read(s, rw.slot, rw.subslot, rw.index, rec, sizeof(rec),
                       &rlen);
        uint8_t blocks_res[64 + 256];
        size_t bn = iod_rw_res(blocks_res, sizeof(blocks_res),
                               PN_BLOCK_IOD_READ_RES, rw.seq, rw.aruuid, rw.api,
                               rw.slot, rw.subslot, rw.index, (uint32_t)rlen,
                               rec, rlen);
        so = ndr_res(stub_out, NULL, blocks_res, bn);
    } else if (op == OP_WRITE) {
        write_walk_t ww;
        memset(&ww, 0, sizeof(ww));
        ww.slot = 0;
        ww.subslot = 1;
        size_t blen = 0;
        const uint8_t *blocks = ndr_blocks(stub, slen, &blen);
        if (blocks) {
            walk_blocks(blocks, blen, parse_write_req, &ww);
            attach_write_payload(blocks, blen, &ww);
        }
        if (!s->ar.established) {
            LOG_WARN("pn_rpc", "Write without AR — fail closed");
            return -EINVAL;
        }
        if (!ar_owner_ok(s, src_ip)) {
            LOG_WARN("pn_rpc", "Write rejected: sender IP mismatch");
            return -EPERM;
        }
        if (!ar_uuid_ok(s, ww.saw_uuid, ww.aruuid)) {
            LOG_WARN("pn_rpc", "Write rejected: ARUUID mismatch");
            return -EPERM;
        }
        ar_touch_cmi(s);
        if (ww.saw) {
            pn_record_write(s, ww.slot, ww.subslot, ww.index, ww.data, ww.dlen);
            LOG_INFO("pn_rpc", "Write index=0x%04x slot=%u sub=%u len=%u",
                     ww.index, ww.slot, ww.subslot, ww.dlen);
        }
        uint8_t blocks_res[64];
        size_t bn = iod_rw_res(blocks_res, sizeof(blocks_res),
                               PN_BLOCK_IOD_WRITE_RES, ww.seq, ww.aruuid, ww.api,
                               ww.slot, ww.subslot, ww.index, ww.dlen, NULL, 0);
        so = ndr_res(stub_out, NULL, blocks_res, bn);
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
    if (pn_rpc_handle(s, buf, (size_t)n, resp, sizeof(resp), &rlen,
                      ntohl(src.sin_addr.s_addr)) == 0 &&
        rlen > 0) {
        sendto(s->fd_rpc, resp, rlen, 0, (struct sockaddr *)&src, sl);
    }
    flush_pending_rpc(s);
}
