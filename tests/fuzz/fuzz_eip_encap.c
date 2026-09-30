/*
 * EtherNet/IP encapsulation + UCMM fuzzer.
 *
 * The original harness registered one session and stitched it into SendRRData
 * frames, but almost never emitted a valid CIP path. llvm-cov of the 1h corpus:
 * eip_encap.c 72%, eip_cip.c 17.5%, eip_cm.c 0%. Plateau cov=320 / ft=386.
 *
 * Byte 0 selects a mode. A live session is kept on three Adapter stacks:
 *   - open (security_class=0, protection_mode=0)
 *   - protected (protection_mode=1 → Set/Reset privilege reject)
 *   - integrity (security_class=1 + PSK; mutating UCMM needs HMAC)
 *
 * ListInterfaces and SendUnitData are not implemented (invalid-cmd). CIP
 * Multiple Service Packet is not a service here (0x0A = ATTR_READONLY status).
 * Unconnected Send 0x52 is defined but not handled (service not supported).
 *
 * Forward Open takes a Class 1 slot (EIP_CLASS1_CONN_MAX). Modes that open
 * one also Forward Close it before returning. On security_class=1 the close
 * must be HMAC'd; otherwise the stack rejects it and the slot stays taken.
 */
#include "eip_endian.h"
#include "eip_sec.h"
#include "eip_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FUZZ_IO_IN  8
#define FUZZ_IO_OUT 8
#define FUZZ_ASM_CFG 100
#define FUZZ_ASM_OUT 101
#define FUZZ_ASM_IN  150

typedef struct {
    eip_stack_t *s;
    uint32_t session;
    uint16_t conn_serial;
    uint16_t orig_vendor;
    uint32_t orig_serial;
} fuzz_eip_t;

static fuzz_eip_t g_open;
static fuzz_eip_t g_prot;
static fuzz_eip_t g_sec;

static uint8_t u8_at(const uint8_t *p, size_t plen, size_t i, uint8_t def)
{
    return i < plen ? p[i] : def;
}

static int send_encap(fuzz_eip_t *st, const uint8_t *req, size_t req_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    *resp_len = 0;
    return eip_stack_handle_encap(st->s, req, req_len, resp, resp_cap, resp_len);
}

static int send_cip(fuzz_eip_t *st, const uint8_t *cip, size_t cip_len, int hmac,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 64 + 256];
    uint8_t mac_item[4 + EIP_HMAC_LEN];
    size_t mac_len = 0;
    if (cip_len > 256) {
        cip_len = 256;
    }
    if (hmac && st->session) {
        mac_len = eip_sec_append_mac_item(st->s, st->session, cip, cip_len,
                                          mac_item, sizeof(mac_item));
    }
    uint8_t *body = req + EIP_ENCAP_HDR_SIZE;
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, mac_len ? 3 : 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;
    if (mac_len) {
        memcpy(body + boff, mac_item, mac_len);
        boff += mac_len;
    }
    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, st->session);
    return send_encap(st, req, EIP_ENCAP_HDR_SIZE + boff, resp, resp_cap,
                      resp_len);
}

static int register_session(fuzz_eip_t *st)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (send_encap(st, req, sizeof(req), resp, sizeof(resp), &n) == 0 &&
        n >= 8) {
        uint32_t h = eip_rd_le32(resp + 4);
        if (h != 0) {
            st->session = h;
            return 0;
        }
    }
    return -1;
}

static void ensure_session(fuzz_eip_t *st)
{
    if (st->session == 0) {
        (void)register_session(st);
    }
}

static size_t cip_cls8(uint8_t *cip, size_t cap, uint8_t svc, uint8_t cls,
                       uint8_t inst, int with_attr, uint8_t attr,
                       const uint8_t *data, size_t dlen)
{
    size_t path = with_attr ? 6u : 4u;
    if (2u + path + dlen > cap) {
        return 0;
    }
    cip[0] = svc;
    cip[1] = (uint8_t)(path / 2u);
    cip[2] = 0x20;
    cip[3] = cls;
    cip[4] = 0x24;
    cip[5] = inst;
    size_t off = 6;
    if (with_attr) {
        cip[6] = 0x30;
        cip[7] = attr;
        off = 8;
    }
    if (dlen) {
        memcpy(cip + off, data, dlen);
        off += dlen;
    }
    return off;
}

static size_t cip_cls16(uint8_t *cip, size_t cap, uint8_t svc, uint16_t cls,
                        uint8_t inst, uint8_t attr, const uint8_t *data,
                        size_t dlen)
{
    size_t path = 8u; /* 16-bit class + inst + attr */
    if (2u + path + dlen > cap) {
        return 0;
    }
    cip[0] = svc;
    cip[1] = 4;
    cip[2] = 0x21;
    cip[3] = 0x00;
    eip_wr_le16(cip + 4, cls);
    cip[6] = 0x24;
    cip[7] = inst;
    cip[8] = 0x30;
    cip[9] = attr;
    if (dlen) {
        memcpy(cip + 10, data, dlen);
    }
    return 10u + dlen;
}

static void get_attr(fuzz_eip_t *st, uint8_t cls, uint8_t inst, uint8_t attr)
{
    uint8_t cip[16];
    uint8_t resp[512];
    size_t n = 0;
    size_t cl = cip_cls8(cip, sizeof(cip), CIP_SVC_GET_ATTR_SINGLE, cls, inst, 1,
                         attr, NULL, 0);
    if (cl) {
        (void)send_cip(st, cip, cl, 0, resp, sizeof(resp), &n);
    }
}

static uint32_t parse_fo_o2t(const uint8_t *resp, size_t n)
{
    size_t start = n > EIP_ENCAP_HDR_SIZE ? EIP_ENCAP_HDR_SIZE : 0;
    for (size_t i = start; i + 12 < n; i++) {
        uint8_t svc = resp[i];
        if (resp[i + 2] != 0) {
            continue;
        }
        if (svc == (uint8_t)(CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) ||
            svc == (uint8_t)(CIP_SVC_LARGE_FORWARD_OPEN | CIP_SVC_REPLY)) {
            return eip_rd_le32(resp + i + 4);
        }
    }
    return 0;
}

static int forward_open(fuzz_eip_t *st, int large, int hmac)
{
    uint8_t fo[80];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0);
    off += 4;
    st->conn_serial++;
    if (st->conn_serial == 0) {
        st->conn_serial = 1;
    }
    eip_wr_le16(fo + off, st->conn_serial);
    off += 2;
    eip_wr_le16(fo + off, st->orig_vendor);
    off += 2;
    eip_wr_le32(fo + off, st->orig_serial);
    off += 4;
    fo[off++] = 7;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 8000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, FUZZ_IO_OUT);
        off += 4;
    } else {
        eip_wr_le16(fo + off, FUZZ_IO_OUT);
        off += 2;
    }
    eip_wr_le32(fo + off, 8000);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, FUZZ_IO_IN);
        off += 4;
    } else {
        eip_wr_le16(fo + off, FUZZ_IO_IN);
        off += 2;
    }
    fo[off++] = 0x01;
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = (uint8_t)FUZZ_ASM_CFG;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)FUZZ_ASM_OUT;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)FUZZ_ASM_IN;

    uint8_t cip[2 + 4 + 80];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);

    uint8_t resp[512];
    size_t n = 0;
    if (send_cip(st, cip, 6 + off, hmac, resp, sizeof(resp), &n) != 0) {
        return -1;
    }
    return parse_fo_o2t(resp, n) ? 0 : -1;
}

static void forward_close(fuzz_eip_t *st, int hmac)
{
    uint8_t fc[12];
    memset(fc, 0, sizeof(fc));
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, st->conn_serial);
    eip_wr_le16(fc + 4, st->orig_vendor);
    eip_wr_le32(fc + 6, st->orig_serial);
    uint8_t cip[2 + 4 + 12];
    cip[0] = CIP_SVC_FORWARD_CLOSE;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fc, 12);
    uint8_t resp[128];
    size_t n = 0;
    (void)send_cip(st, cip, 6 + 12, hmac, resp, sizeof(resp), &n);
}

static eip_stack_t *make_stack(int security_class, uint32_t protection_mode)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = FUZZ_IO_IN;
    cfg.output_size = FUZZ_IO_OUT;
    cfg.input_assembly = FUZZ_ASM_IN;
    cfg.output_assembly = FUZZ_ASM_OUT;
    cfg.config_assembly = FUZZ_ASM_CFG;
    cfg.rpi_us = 8000;
    cfg.security_class = security_class;
    cfg.protection_mode = protection_mode;
    if (security_class >= EIP_SECURITY_CLASS_1) {
        memset(cfg.psk, 0x42, EIP_PSK_LEN);
        cfg.psk_set = 1;
    }
    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s) {
        return NULL;
    }
    (void)eip_stack_start(s);
    return s;
}

static int init_one(fuzz_eip_t *st, int security_class, uint32_t protection_mode,
                    uint32_t orig_serial)
{
    memset(st, 0, sizeof(*st));
    st->s = make_stack(security_class, protection_mode);
    if (!st->s) {
        return -1;
    }
    st->orig_vendor = 1;
    st->orig_serial = orig_serial;
    st->conn_serial = 0x1000;
    return register_session(st);
}

static int fuzz_init(void)
{
    if (init_one(&g_open, 0, 0, 0x11) != 0) {
        return -1;
    }
    if (init_one(&g_prot, 0, 1, 0x22) != 0) {
        return -1;
    }
    if (init_one(&g_sec, EIP_SECURITY_CLASS_1, 0, 0x33) != 0) {
        return -1;
    }
    return 0;
}

static void stitch_and_send(fuzz_eip_t *st, const uint8_t *data, size_t n)
{
    uint8_t buf[4096];
    uint8_t resp[EIP_TCP_BUF_MAX];
    size_t resp_len = 0;
    if (n > sizeof(buf)) {
        n = sizeof(buf);
    }
    if (n == 0) {
        return;
    }
    memcpy(buf, data, n);
    if (n >= EIP_ENCAP_HDR_SIZE && st->session != 0) {
        uint16_t cmd = eip_rd_le16(buf);
        if (cmd == EIP_CMD_SENDRRDATA || cmd == EIP_CMD_UNREGISTERSESSION ||
            cmd == EIP_CMD_SENDUNITDATA) {
            eip_wr_le32(buf + 4, st->session);
        }
    }
    (void)send_encap(st, buf, n, resp, sizeof(resp), &resp_len);
    if (n >= EIP_ENCAP_HDR_SIZE && eip_rd_le16(buf) == EIP_CMD_REGISTERSESSION &&
        resp_len >= 8) {
        uint32_t h = eip_rd_le32(resp + 4);
        if (h != 0) {
            st->session = h;
        }
    }
    if (n >= 2 && eip_rd_le16(buf) == EIP_CMD_UNREGISTERSESSION) {
        st->session = 0;
    }
}

static void send_cmd(fuzz_eip_t *st, uint16_t cmd)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    uint8_t resp[512];
    size_t n = 0;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, cmd);
    eip_wr_le32(req + 4, st->session);
    (void)send_encap(st, req, sizeof(req), resp, sizeof(resp), &n);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const uint8_t k_id_attr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17, 99};
    static const uint8_t k_tcp_attr[] = {1, 2, 3, 4, 10, 11, 99};
    static const uint8_t k_qos_attr[] = {1, 2, 3, 4, 5, 9};
    static const uint8_t k_asm_inst[] = {100, 101, 150, 1};
    static const uint8_t k_sec_attr[] = {1, 2, 3, 4};

    if (!g_open.s) {
        if (fuzz_init() != 0) {
            return 0;
        }
    }
    if (size == 0) {
        ensure_session(&g_open);
        return 0;
    }

    uint8_t mode = (uint8_t)(data[0] & 7u);
    const uint8_t *p = data + 1;
    size_t plen = size - 1;
    uint8_t cip[128];
    uint8_t resp[EIP_TCP_BUF_MAX];
    size_t resp_len = 0;
    uint8_t tmp[8];

    ensure_session(&g_open);

    switch (mode) {
    case 0: /* raw Encaps, session stitched (legacy corpus) */
        stitch_and_send(&g_open, p, plen);
        break;
    case 1: { /* Get Attribute Single across objects */
        uint8_t which = u8_at(p, plen, 0, 0) % 10u;
        if (which == 0) {
            get_attr(&g_open, CIP_CLASS_IDENTITY, 1,
                     k_id_attr[u8_at(p, plen, 1, 0) % (uint8_t)sizeof(k_id_attr)]);
        } else if (which == 1) {
            get_attr(&g_open, CIP_CLASS_MSG_ROUTER, 1, 1);
        } else if (which == 2) {
            get_attr(&g_open, CIP_CLASS_ASSEMBLY,
                     k_asm_inst[u8_at(p, plen, 1, 0) %
                                (uint8_t)sizeof(k_asm_inst)],
                     (u8_at(p, plen, 2, 0) & 1) ? 3 : 4);
        } else if (which == 3) {
            get_attr(&g_open, CIP_CLASS_TCPIP, 1,
                     k_tcp_attr[u8_at(p, plen, 1, 0) %
                                (uint8_t)sizeof(k_tcp_attr)]);
        } else if (which == 4) {
            get_attr(&g_open, CIP_CLASS_ETHERNET_LINK, 1,
                     (uint8_t)(1 + (u8_at(p, plen, 1, 0) % 3)));
        } else if (which == 5) {
            get_attr(&g_open, CIP_CLASS_QOS, 1,
                     k_qos_attr[u8_at(p, plen, 1, 0) %
                                (uint8_t)sizeof(k_qos_attr)]);
        } else if (which == 6) {
            get_attr(&g_open, CIP_CLASS_PORT, 1,
                     (uint8_t)(1 + (u8_at(p, plen, 1, 0) & 1)));
        } else if (which == 7) {
            get_attr(&g_open, CIP_CLASS_EIP_SECURITY, 1,
                     k_sec_attr[u8_at(p, plen, 1, 0) %
                                (uint8_t)sizeof(k_sec_attr)]);
        } else if (which == 8) {
            size_t cl = cip_cls16(cip, sizeof(cip), CIP_SVC_GET_ATTR_SINGLE,
                                  CIP_CLASS_LLDP_MGMT, 1,
                                  (uint8_t)(1 + (u8_at(p, plen, 1, 0) % 5)),
                                  NULL, 0);
            if (cl) {
                (void)send_cip(&g_open, cip, cl, 0, resp, sizeof(resp),
                               &resp_len);
            }
        } else {
            size_t cl = cip_cls16(cip, sizeof(cip), CIP_SVC_GET_ATTR_SINGLE,
                                  CIP_CLASS_LLDP_DATA_TABLE, 1, 1, NULL, 0);
            if (cl) {
                (void)send_cip(&g_open, cip, cl, 0, resp, sizeof(resp),
                               &resp_len);
            }
        }
        break;
    }
    case 2: { /* GetAttr All, Reset, Unconnected Send, service 0x0A */
        uint8_t k = u8_at(p, plen, 0, 0) & 3u;
        size_t cl = 0;
        if (k == 0) {
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_GET_ATTR_ALL,
                          CIP_CLASS_IDENTITY, 1, 0, 0, NULL, 0);
        } else if (k == 1) {
            uint8_t typ = u8_at(p, plen, 1, 0);
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_RESET, CIP_CLASS_IDENTITY, 1,
                          0, 0, &typ, 1);
        } else if (k == 2) {
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_UNCONNECTED_SEND,
                          CIP_CLASS_CONN_MANAGER, 1, 0, 0, p, plen > 8 ? 8 : plen);
        } else {
            cl = cip_cls8(cip, sizeof(cip), 0x0A, CIP_CLASS_IDENTITY, 1, 1, 1,
                          NULL, 0);
        }
        if (cl) {
            (void)send_cip(&g_open, cip, cl, 0, resp, sizeof(resp), &resp_len);
        }
        break;
    }
    case 3: { /* Set Attribute Single */
        uint8_t k = u8_at(p, plen, 0, 0) % 5u;
        size_t cl = 0;
        if (k == 0) {
            eip_wr_le32(tmp, 0);
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                          CIP_CLASS_IDENTITY, 1, 1, 17, tmp, 4);
        } else if (k == 1) {
            memset(tmp, 0x5A, FUZZ_IO_OUT);
            if (plen > 1) {
                memcpy(tmp, p + 1, (plen - 1) < FUZZ_IO_OUT ? (plen - 1)
                                                            : FUZZ_IO_OUT);
            }
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                          CIP_CLASS_ASSEMBLY, (uint8_t)FUZZ_ASM_OUT, 1, 3, tmp,
                          FUZZ_IO_OUT);
        } else if (k == 2) {
            tmp[0] = u8_at(p, plen, 1, 0x1B);
            cl = cip_cls8(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                          CIP_CLASS_QOS, 1, 1,
                          k_qos_attr[u8_at(p, plen, 2, 0) % 5u], tmp, 1);
        } else if (k == 3) {
            eip_wr_le32(tmp, 1);
            cl = cip_cls16(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                           CIP_CLASS_LLDP_MGMT, 1, 1, tmp, 4);
        } else {
            eip_wr_le16(tmp, 30);
            cl = cip_cls16(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                           CIP_CLASS_LLDP_MGMT, 1, 2, tmp, 2);
        }
        if (cl) {
            (void)send_cip(&g_open, cip, cl, 0, resp, sizeof(resp), &resp_len);
        }
        break;
    }
    case 4: /* Forward Open / Large / Close. Drop the slot before return. */
        if (u8_at(p, plen, 0, 0) & 1) {
            (void)forward_open(&g_open, 1, 0);
        } else {
            (void)forward_open(&g_open, 0, 0);
        }
        if (plen >= 1 && p[0] == 0xFF) {
            forward_close(&g_open, 0);
            (void)forward_open(&g_open, 0, 0);
        }
        forward_close(&g_open, 0);
        break;
    case 5: { /* ListIdentity / ListServices / ListInterfaces / NOP */
        uint16_t cmds[] = {EIP_CMD_LISTIDENTITY, EIP_CMD_LISTSERVICES,
                           EIP_CMD_LISTINTERFACES, EIP_CMD_NOP};
        send_cmd(&g_open, cmds[u8_at(p, plen, 0, 0) % 4u]);
        break;
    }
    case 6: /* Unregister + re-register, SendUnitData (invalid cmd) */
        if (u8_at(p, plen, 0, 0) & 1) {
            send_cmd(&g_open, EIP_CMD_UNREGISTERSESSION);
            g_open.session = 0;
            ensure_session(&g_open);
        } else {
            send_cmd(&g_open, EIP_CMD_SENDUNITDATA);
            stitch_and_send(&g_open, p, plen);
        }
        break;
    default: { /* protection_mode + security_class=1 variants */
        ensure_session(&g_prot);
        ensure_session(&g_sec);
        eip_wr_le32(tmp, 1);
        size_t cl = cip_cls8(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                             CIP_CLASS_IDENTITY, 1, 1, 17, tmp, 4);
        if (cl) {
            (void)send_cip(&g_prot, cip, cl, 0, resp, sizeof(resp), &resp_len);
        }
        cl = cip_cls8(cip, sizeof(cip), CIP_SVC_RESET, CIP_CLASS_IDENTITY, 1, 0,
                      0, NULL, 0);
        if (cl) {
            (void)send_cip(&g_prot, cip, cl, 0, resp, sizeof(resp), &resp_len);
        }
        get_attr(&g_prot, CIP_CLASS_IDENTITY, 1, 17);
        get_attr(&g_sec, CIP_CLASS_EIP_SECURITY, 1, 1);
        /* mutating without HMAC (reject) then with HMAC (accept) */
        memset(tmp, 0x11, FUZZ_IO_OUT);
        cl = cip_cls8(cip, sizeof(cip), CIP_SVC_SET_ATTR_SINGLE,
                      CIP_CLASS_ASSEMBLY, (uint8_t)FUZZ_ASM_OUT, 1, 3, tmp,
                      FUZZ_IO_OUT);
        if (cl) {
            (void)send_cip(&g_sec, cip, cl, 0, resp, sizeof(resp), &resp_len);
            (void)send_cip(&g_sec, cip, cl, 1, resp, sizeof(resp), &resp_len);
        }
        (void)forward_open(&g_sec, 0, 0); /* missing HMAC → privilege */
        (void)forward_open(&g_sec, 0, 1); /* HMAC'd FO */
        forward_close(&g_sec, 1); /* HMAC'd close, else the slot sticks */
        break;
    }
    }
    return 0;
}
