#include "eip_crypto.h"
#include "eip_endian.h"
#include "eip_internal.h"
#include "eip_sec.h"
#include "eip_stack.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int g_fail;

static void expect(int cond, const char *msg)
{
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_fail = 1;
    }
}

static uint32_t test_register(eip_stack_t *s)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp), &n) !=
        0) {
        return 0;
    }
    if (n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static size_t fo_append_asm_path(uint8_t *fo, size_t off, uint16_t cfg_asm,
                                 uint16_t out_asm, uint16_t in_asm)
{
    fo[off++] = 4;
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = (uint8_t)cfg_asm;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)out_asm;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)in_asm;
    return off;
}

static void test_identity_get(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.vendor_id = 0xABCD;
    cfg.device_type = 12;
    cfg.product_code = 7;
    cfg.major_rev = 1;
    cfg.minor_rev = 2;
    cfg.serial_number = 0x11223344;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "TestSensor");
    cfg.input_size = 64;
    cfg.output_size = 16;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;

    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "stack create");
    expect(eip_stack_start(s) == 0, "stack start mock");

    /* Build Get_Attribute_Single Identity attr 1 via SendRRData */
    uint8_t cip[8];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = 3; /* 3 words: class, instance, attr */
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_IDENTITY;
    cip[4] = 0x24;
    cip[5] = 1;
    cip[6] = 0x30;
    cip[7] = 1;

    uint8_t body[64];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 8);
    boff += 2;
    memcpy(body + boff, cip, 8);
    boff += 8;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 64];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, test_register(s));
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[512];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "encap SendRRData");
    expect(resp_len > EIP_ENCAP_HDR_SIZE, "response has body");
    expect(eip_rd_le16(resp + 0) == EIP_CMD_SENDRRDATA, "cmd echo");

    /* Find CIP reply vendor id 0xABCD */
    int found = 0;
    for (size_t i = 0; i + 2 <= resp_len; i++) {
        if (resp[i] == 0xCD && resp[i + 1] == 0xAB) {
            found = 1;
            break;
        }
    }
    expect(found, "vendor id 0xABCD in reply");

    eip_stack_destroy(s);
}

static void test_assembly_rw_and_forward_open(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = 32;
    cfg.output_size = 8;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "AsmTest");

    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "asm stack create");
    eip_stack_start(s);

    const char *msg = "BARCODE-1234567890";
    expect(eip_stack_write_input(s, 0, (const uint8_t *)msg, strlen(msg)) > 0,
           "write input image");

    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    expect(eip_stack_read_input(s, 0, buf, sizeof(buf)) > 0, "read input");
    expect(memcmp(buf, msg, strlen(msg)) == 0, "input roundtrip");

    /* Forward Open (standard) minimal body + empty path */
    uint8_t fo[64];
    size_t off = 0;
    fo[off++] = 0x0A; /* priority/tick */
    fo[off++] = 0x05; /* timeout ticks */
    eip_wr_le32(fo + off, 0);
    off += 4; /* O->T conn id */
    eip_wr_le32(fo + off, 0);
    off += 4; /* T->O conn id */
    eip_wr_le16(fo + off, 0x1234);
    off += 2; /* serial */
    eip_wr_le16(fo + off, 1);
    off += 2; /* vendor */
    eip_wr_le32(fo + off, 0x99);
    off += 4; /* orig serial */
    fo[off++] = 0; /* timeout multiplier */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 8000);
    off += 4; /* O->T RPI */
    eip_wr_le16(fo + off, 8);
    off += 2; /* O->T params size */
    eip_wr_le32(fo + off, 8000);
    off += 4; /* T->O RPI */
    eip_wr_le16(fo + off, 32);
    off += 2; /* T->O params size */
    fo[off++] = 0x01; /* transport class 1 */
    off = fo_append_asm_path(fo, off, 100, 101, 150);

    uint8_t path[8];
    size_t pu = 0;
    /* CM class 0x06 instance 1 */
    path[pu++] = 0x20;
    path[pu++] = CIP_CLASS_CONN_MANAGER;
    path[pu++] = 0x24;
    path[pu++] = 1;
    uint8_t cip[2 + 8 + 64];
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    memcpy(cip + 2, path, 4);
    memcpy(cip + 6, fo, off);

    uint8_t body[128];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    uint16_t cip_len = (uint16_t)(6 + off);
    eip_wr_le16(body + boff, cip_len);
    boff += 2;
    memcpy(body + boff, cip, cip_len);
    boff += cip_len;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 128];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, test_register(s));
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[512];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "forward open encap");
    expect(eip_stack_class1_up(s) == 1, "class1 up after forward open");

    /* Grab O->T conn id from Forward Open reply (service | 0x80 == 0xD4) */
    uint32_t o2t = 0;
    for (size_t i = EIP_ENCAP_HDR_SIZE; i + 12 < resp_len; i++) {
        if (resp[i] == (CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) &&
            resp[i + 2] == 0) {
            o2t = eip_rd_le32(resp + i + 4);
            break;
        }
    }
    expect(o2t != 0, "parsed o2t conn id");

    uint8_t io[64];
    size_t ioff = 0;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, 1);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, 2 + 8);
    ioff += 2;
    eip_wr_le16(io + ioff, 1);
    ioff += 2;
    memset(io + ioff, 0x5A, 8);
    ioff += 8;
    expect(eip_stack_handle_io(s, io, ioff) == 0, "handle class1 io");

    uint8_t outb[8];
    expect(eip_stack_read_output(s, 0, outb, 8) == 8, "read output len");
    expect(outb[0] == 0x5A, "output data consumed");

    eip_stack_destroy(s);
}

static void test_register_session(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "reg stack");

    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &resp_len) == 0,
           "register session");
    expect(eip_rd_le32(resp + 4) != 0, "session handle assigned");
    eip_stack_destroy(s);
}

static void test_security_integrity(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.security_class = EIP_SECURITY_CLASS_1;
    memset(cfg.psk, 0x11, EIP_PSK_LEN);
    cfg.psk_set = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "sec stack create");

    /* Forward Open CIP without MAC must be rejected (privilege) */
    uint8_t fo[64];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    memset(fo + off, 0, 8);
    off += 8;
    eip_wr_le16(fo + off, 0x55);
    off += 2;
    eip_wr_le16(fo + off, 1);
    off += 2;
    eip_wr_le32(fo + off, 1);
    off += 4;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 8000);
    off += 4;
    eip_wr_le16(fo + off, 8);
    off += 2;
    eip_wr_le32(fo + off, 8000);
    off += 4;
    eip_wr_le16(fo + off, 8);
    off += 2;
    fo[off++] = 1;
    off = fo_append_asm_path(fo, off, 100, 101, 150);

    uint8_t cip[2 + 4 + 64];
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    size_t cip_len = 6 + off;

    uint8_t body[128];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
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

    uint32_t sess = test_register(s);
    expect(sess != 0, "sec register session");

    uint8_t req[EIP_ENCAP_HDR_SIZE + 128];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess); /* session */
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[512];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "sec FO without mac encap");
    int saw_priv = 0;
    for (size_t i = EIP_ENCAP_HDR_SIZE; i + 3 < resp_len; i++) {
        if ((resp[i] & 0x7f) == CIP_SVC_FORWARD_OPEN &&
            (resp[i] & 0x80) && resp[i + 2] == CIP_STATUS_PRIVILEGE) {
            saw_priv = 1;
            break;
        }
    }
    expect(saw_priv, "FO without MAC -> privilege denied");
    expect(eip_stack_class1_up(s) == 0, "no class1 after reject");

    /* Same FO with valid integrity item */
    uint8_t material[4 + 128];
    eip_wr_le32(material, sess);
    memcpy(material + 4, cip, cip_len);
    uint8_t mac[EIP_HMAC_LEN];
    eip_hmac_sha256(cfg.psk, EIP_PSK_LEN, material, 4 + cip_len, mac);

    boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 3);
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
    eip_wr_le16(body + boff, EIP_SEC_ITEM_INTEGRITY);
    boff += 2;
    eip_wr_le16(body + boff, EIP_HMAC_LEN);
    boff += 2;
    memcpy(body + boff, mac, EIP_HMAC_LEN);
    boff += EIP_HMAC_LEN;

    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "sec FO with mac");
    expect(eip_stack_class1_up(s) == 1, "class1 up with valid MAC");

    /* Security object capability */
    uint8_t get[8];
    get[0] = CIP_SVC_GET_ATTR_SINGLE;
    get[1] = 3;
    get[2] = 0x20;
    get[3] = CIP_CLASS_EIP_SECURITY;
    get[4] = 0x24;
    get[5] = 1;
    get[6] = 0x30;
    get[7] = 2;
    boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 8);
    boff += 2;
    memcpy(body + boff, get, 8);
    boff += 8;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "security object get");
    int found_cap = 0;
    for (size_t i = 0; i + 4 <= resp_len; i++) {
        if (resp[i] == 0x01 && resp[i + 1] == 0x00 && resp[i + 2] == 0x00 &&
            resp[i + 3] == 0x00) {
            found_cap = 1; /* caps = integrity bit */
            break;
        }
    }
    expect(found_cap, "security capability integrity bit");

    eip_stack_destroy(s);
}

static int sendrr_get(eip_stack_t *s, uint16_t class_id, uint16_t inst,
                      uint16_t attr, uint8_t *cip_data, size_t *cip_data_len)
{
    uint8_t path[8];
    size_t pu = 0;
    path[pu++] = 0x20;
    path[pu++] = (uint8_t)class_id;
    path[pu++] = 0x24;
    path[pu++] = (uint8_t)inst;
    path[pu++] = 0x30;
    path[pu++] = (uint8_t)attr;
    /* 16-bit class for LLDP 0x109 */
    if (class_id > 0xff) {
        pu = 0;
        path[pu++] = 0x21;
        path[pu++] = 0x00;
        eip_wr_le16(path + pu, class_id);
        pu += 2;
        path[pu++] = 0x24;
        path[pu++] = (uint8_t)inst;
        path[pu++] = 0x30;
        path[pu++] = (uint8_t)attr;
    }
    uint8_t cip[16];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = (uint8_t)((pu + 1) / 2);
    memcpy(cip + 2, path, pu);
    size_t cip_len = 2 + pu;

    uint8_t body[64];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
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

    uint8_t req[EIP_ENCAP_HDR_SIZE + 64];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, test_register(s));
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    uint8_t resp[256];
    size_t resp_len = 0;
    if (eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                               sizeof(resp), &resp_len) != 0) {
        return -1;
    }
    /* find unconnected data item */
    if (resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return -1;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = resp_len - EIP_ENCAP_HDR_SIZE;
    size_t off = 6;
    uint16_t items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        uint16_t type = eip_rd_le16(b + off);
        uint16_t length = eip_rd_le16(b + off + 2);
        off += 4;
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 4) {
            if (b[off + 2] != 0) {
                return -2;
            }
            size_t n = length - 4;
            if (n > *cip_data_len) {
                n = *cip_data_len;
            }
            memcpy(cip_data, b + off + 4, n);
            *cip_data_len = n;
            return 0;
        }
        off += length;
        if (off > bl) {
            break;
        }
    }
    return -3;
}

static void test_qos_dscp_ct_defaults(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "qos stack");
    uint8_t data[8];
    size_t n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_QOS, 1, 5, data, &n) == 0, "qos explicit get");
    expect(n >= 1 && data[0] == EIP_DSCP_EXPLICIT, "DSCP Explicit=0x1B");
    n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_QOS, 1, 2, data, &n) == 0, "qos scheduled get");
    expect(n >= 1 && data[0] == EIP_DSCP_SCHEDULED, "DSCP Scheduled=0x2F");
    eip_stack_destroy(s);
}

static void test_acd_identity_state(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.acd_enable = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "acd stack");
    expect(eip_stack_acd_conflict(s, 1) == 0, "inject conflict");
    uint8_t data[8];
    size_t n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_IDENTITY, 1, 8, data, &n) == 0, "id state");
    expect(n >= 1 && data[0] == 2, "Identity state=MinorRF on ACD");
    n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_TCPIP, 1, 10, data, &n) == 0, "acd status");
    expect(n >= 4 && eip_rd_le32(data) == 1, "TCP/IP ACD Status=1");
    expect(eip_stack_acd_conflict(s, 0) == 0, "clear conflict");
    n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_IDENTITY, 1, 8, data, &n) == 0, "id state2");
    expect(n >= 1 && data[0] == 3, "Identity state back to operational");
    eip_stack_destroy(s);
}

static void test_lldp_mgmt_and_frame(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.lldp_enable = 1;
    cfg.lldp_tx_interval_sec = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "LLDPSensor");
    snprintf(cfg.iface, sizeof(cfg.iface), "eth0");
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "lldp stack");
    expect(eip_stack_start(s) == 0, "lldp start");
    eip_stack_poll(s);
    uint8_t data[8];
    size_t n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_LLDP_MGMT, 1, 1, data, &n) == 0,
           "lldp enable get");
    expect(n >= 4 && (eip_rd_le32(data) & 1) == 1, "LLDP global enable");
    n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_LLDP_MGMT, 1, 2, data, &n) == 0,
           "lldp interval get");
    expect(n >= 2 && eip_rd_le16(data) == 1, "LLDP tx interval");

    uint8_t frame[512];
    int flen = eip_stack_lldp_frame(s, frame, sizeof(frame));
    expect(flen > 14, "LLDP frame length");
    expect(frame[12] == 0x88 && frame[13] == 0xcc, "LLDP ethertype");
    int found_name = 0;
    for (int i = 0; i + 10 < flen; i++) {
        if (memcmp(frame + i, "LLDPSensor", 10) == 0) {
            found_name = 1;
            break;
        }
    }
    expect(found_name, "product name in LLDP");
    eip_stack_destroy(s);
}

static void test_class1_watchdog_and_rt_stats(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.rpi_us = 1000;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "wd stack");
    expect(eip_stack_start(s) == 0, "wd start");

    /* Forward Open with tiny RPI + timeout_mult=0 */
    uint8_t fo[48];
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    memset(fo + off, 0, 8);
    off += 8;
    eip_wr_le16(fo + off, 0x77);
    off += 2;
    eip_wr_le16(fo + off, 1);
    off += 2;
    eip_wr_le32(fo + off, 7);
    off += 4;
    fo[off++] = 0; /* timeout multiplier */
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, 100); /* O->T RPI 100us */
    off += 4;
    eip_wr_le16(fo + off, 8);
    off += 2;
    eip_wr_le32(fo + off, 100);
    off += 4;
    eip_wr_le16(fo + off, 8);
    off += 2;
    fo[off++] = 1;
    off = fo_append_asm_path(fo, off, EIP_ASM_CONFIG_DEFAULT,
                             EIP_ASM_OUTPUT_DEFAULT, EIP_ASM_INPUT_DEFAULT);

    uint8_t cip[80];
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    size_t cip_len = 6 + off;
    uint8_t body[128];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
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
    uint8_t req[EIP_ENCAP_HDR_SIZE + 128];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, test_register(s));
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    uint8_t resp[512];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "wd FO");
    expect(eip_stack_class1_up(s) == 1, "class1 after FO");

    uint32_t o2t = 0;
    for (size_t i = EIP_ENCAP_HDR_SIZE; i + 12 < resp_len; i++) {
        if (resp[i] == (CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) &&
            resp[i + 2] == 0) {
            o2t = eip_rd_le32(resp + i + 4);
            break;
        }
    }
    expect(o2t != 0, "o2t id");

    uint8_t io[64];
    size_t ioff = 0;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, 1);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, 10);
    ioff += 2;
    eip_wr_le16(io + ioff, 1);
    ioff += 2;
    memset(io + ioff, 0, 8);
    ioff += 8;
    expect(eip_stack_handle_io(s, io, ioff) == 0, "arm with first IO");

    usleep(2000); /* > watchdog (~400us) */
    eip_stack_poll(s);
    expect(eip_stack_class1_up(s) == 0, "class1 closed by watchdog");

    uint64_t last = 0, max = 0;
    uint32_t tos = 0;
    eip_stack_rt_stats(s, &last, &max, &tos);
    expect(tos >= 1, "timeout counter");
    expect(last > 0 || max > 0, "rt stats updated");
    eip_stack_destroy(s);
}

static void test_list_identity_and_protection(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.vendor_id = 0x1234;
    cfg.protection_mode = 0x1;
    snprintf(cfg.product_name, sizeof(cfg.product_name), "ProtSensor");
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "listid stack");

    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
    uint8_t resp[256];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                  &resp_len) == 0,
           "list identity");
    expect(resp_len > EIP_ENCAP_HDR_SIZE, "list identity body");
    int found = 0;
    for (size_t i = 0; i + 2 <= resp_len; i++) {
        if (resp[i] == 0x34 && resp[i + 1] == 0x12) {
            found = 1;
            break;
        }
    }
    expect(found, "vendor in ListIdentity");

    uint8_t data[8];
    size_t n = sizeof(data);
    expect(sendrr_get(s, CIP_CLASS_IDENTITY, 1, 17, data, &n) == 0,
           "protection mode");
    expect(n >= 4 && eip_rd_le32(data) == 0x1, "protection mode value");
    eip_stack_destroy(s);
}

static uint8_t cip_status_from_encap(const uint8_t *resp, size_t n)
{
    /* Parse CPF Unconnected Data item; do not scan raw bytes (0x00B2
     * looks like a CIP reply because bit 0x80 is set). */
    if (!resp || n < EIP_ENCAP_HDR_SIZE + 8) {
        return 0xFF;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = n - EIP_ENCAP_HDR_SIZE;
    if (bl < 8) {
        return 0xFF;
    }
    size_t off = 6;
    uint16_t items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > bl) {
            return 0xFF;
        }
        uint16_t type = eip_rd_le16(b + off);
        uint16_t length = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + length > bl) {
            return 0xFF;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA && length >= 3) {
            return b[off + 2];
        }
        off += length;
    }
    return 0xFF;
}

static size_t pack_fo_sendrr(uint8_t *req, size_t req_cap, uint32_t sess,
                             const uint8_t *fo, size_t fo_len)
{
    uint8_t cip[96];
    if (6 + fo_len > sizeof(cip)) {
        return 0;
    }
    cip[0] = CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, fo_len);
    size_t cip_len = 6 + fo_len;
    uint8_t body[160];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
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
    if (EIP_ENCAP_HDR_SIZE + boff > req_cap) {
        return 0;
    }
    memset(req, 0, EIP_ENCAP_HDR_SIZE + boff);
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    return EIP_ENCAP_HDR_SIZE + boff;
}

static size_t build_std_fo(uint8_t *fo, uint16_t serial, uint32_t orig_serial,
                           uint32_t rpi, uint16_t o2t, uint16_t t2o,
                           uint8_t tmo, uint8_t in_asm)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    memset(fo + off, 0, 8);
    off += 8;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, 1);
    off += 2;
    eip_wr_le32(fo + off, orig_serial);
    off += 4;
    fo[off++] = tmo;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, rpi);
    off += 4;
    eip_wr_le16(fo + off, o2t);
    off += 2;
    eip_wr_le32(fo + off, rpi);
    off += 4;
    eip_wr_le16(fo + off, t2o);
    off += 2;
    fo[off++] = 1;
    off = fo_append_asm_path(fo, off, 100, 101, in_asm);
    return off;
}

static void test_g2_watchdog_dup_path_size(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.input_assembly = 150;
    cfg.output_assembly = 101;
    cfg.config_assembly = 100;
    cfg.rpi_us = 8000;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "g2 stack");
    expect(eip_stack_start(s) == 0, "g2 start");
    uint32_t sess = test_register(s);
    expect(sess != 0, "g2 session");

    uint8_t fo[64];
    uint8_t req[EIP_ENCAP_HDR_SIZE + 160];
    uint8_t resp[512];
    size_t resp_len = 0;

    /* Long RPI so watchdog does not fire while we probe rejects. */
    size_t fo_len = build_std_fo(fo, 0x77, 7, 8000, 8, 8, 4, 150);
    size_t req_len = pack_fo_sendrr(req, sizeof(req), sess, fo, fo_len);
    expect(eip_stack_handle_encap(s, req, req_len, resp, sizeof(resp),
                                  &resp_len) == 0,
           "g2 FO");
    expect(cip_status_from_encap(resp, resp_len) == CIP_STATUS_SUCCESS,
           "g2 FO success");
    expect(eip_stack_class1_up(s) == 1, "g2 class1 after FO");

    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, req_len, resp, sizeof(resp),
                                  &resp_len) == 0,
           "g2 dup FO encap");
    expect(cip_status_from_encap(resp, resp_len) == CIP_STATUS_CONN_FAILURE,
           "g2 dup FO connection failure");
    expect(eip_stack_class1_up(s) == 1, "g2 still one class1");

    fo_len = build_std_fo(fo, 0x78, 8, 8000, 8, 8, 4, 99);
    req_len = pack_fo_sendrr(req, sizeof(req), sess, fo, fo_len);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, req_len, resp, sizeof(resp),
                                  &resp_len) == 0,
           "g2 bad path encap");
    expect(cip_status_from_encap(resp, resp_len) == CIP_STATUS_PATH_DEST,
           "g2 bad path dest");
    expect(eip_stack_class1_up(s) == 1, "g2 class1 unchanged after bad path");

    fo_len = build_std_fo(fo, 0x88, 9, 8000, 99, 8, 4, 150);
    req_len = pack_fo_sendrr(req, sizeof(req), sess, fo, fo_len);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, req_len, resp, sizeof(resp),
                                  &resp_len) == 0,
           "g2 size encap");
    expect(cip_status_from_encap(resp, resp_len) == CIP_STATUS_INVALID_PARAM,
           "g2 size mismatch");
    expect(eip_stack_class1_up(s) == 1, "g2 class1 unchanged after size reject");

    /* Close the long-RPI conn, then FO with tiny RPI and no IO. */
    uint8_t fc[16];
    size_t foff = 0;
    fc[foff++] = 0x0A;
    fc[foff++] = 0x05;
    eip_wr_le16(fc + foff, 0x77);
    foff += 2;
    eip_wr_le16(fc + foff, 1);
    foff += 2;
    eip_wr_le32(fc + foff, 7);
    foff += 4;
    fc[foff++] = 0;
    fc[foff++] = 0;
    uint8_t fccip[32];
    fccip[0] = CIP_SVC_FORWARD_CLOSE;
    fccip[1] = 2;
    fccip[2] = 0x20;
    fccip[3] = CIP_CLASS_CONN_MANAGER;
    fccip[4] = 0x24;
    fccip[5] = 1;
    memcpy(fccip + 6, fc, foff);
    uint8_t body[80];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)(6 + foff));
    boff += 2;
    memcpy(body + boff, fccip, 6 + foff);
    boff += 6 + foff;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "g2 close");
    expect(eip_stack_class1_up(s) == 0, "g2 closed");

    fo_len = build_std_fo(fo, 0x79, 10, 100, 8, 8, 0, 150);
    req_len = pack_fo_sendrr(req, sizeof(req), sess, fo, fo_len);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, req_len, resp, sizeof(resp),
                                  &resp_len) == 0,
           "g2 tiny FO");
    expect(eip_stack_class1_up(s) == 1, "g2 class1 after tiny FO");
    usleep(2000);
    eip_stack_poll(s);
    expect(eip_stack_class1_up(s) == 0, "g2 FO without IO timed out");
    eip_stack_destroy(s);
}

static void test_g5_encap_session_and_cip_len(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "g5 stack");

    /* SendRRData with no registered session -> 0x64 */
    uint8_t body[32];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    body[boff++] = CIP_SVC_GET_ATTR_SINGLE;
    body[boff++] = 0;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 32];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, 0x11111111);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    uint8_t resp[128];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "g5 bad session encap");
    expect(resp_len >= 12, "g5 hdr");
    expect(eip_rd_le32(resp + 8) == EIP_ENCAP_STATUS_INVALID_SESSION,
           "g5 status 0x64");

    uint32_t sess = test_register(s);
    expect(sess != 0, "g5 register");

    /* CIP item length 0: reject (no cip[0] OOB) */
    boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "g5 empty cip encap");
    expect(eip_rd_le32(resp + 8) == EIP_ENCAP_STATUS_INVALID_CMD,
           "g5 empty cip status");

    /* Truncated Encaps: process fails, resp_len stays 0 (no uninit read). */
    uint8_t short_req[8];
    memset(short_req, 0xAA, sizeof(short_req));
    memset(resp, 0xBB, sizeof(resp));
    resp_len = 99;
    expect(eip_stack_handle_encap(s, short_req, sizeof(short_req), resp,
                                  sizeof(resp), &resp_len) == -EINVAL,
           "g5 short encap");
    expect(resp_len == 0, "g5 resp_len cleared on failure");
    eip_stack_destroy(s);
}

static uint32_t test_register_owned(eip_stack_t *s, uint32_t owner)
{
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    uint8_t resp[64];
    size_t n = 0;
    if (eip_stack_handle_encap_owned(s, owner, req, sizeof(req), resp,
                                     sizeof(resp), &n) != 0) {
        return 0;
    }
    if (n < 8) {
        return 0;
    }
    return eip_rd_le32(resp + 4);
}

static void test_g5_session_owner_and_close(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "g5o stack");

    uint32_t ha = test_register_owned(s, 0xA0000001u);
    uint32_t hb = test_register_owned(s, 0xA0000002u);
    expect(ha != 0 && hb != 0 && ha != hb, "g5o distinct handles");
    expect(!(ha == 1 && hb == 2), "g5o handles not sequential 1,2");
    expect(eip_stack_session_count(s) == 2, "g5o two sessions");

    uint8_t body[32];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_NULL_ADDR);
    boff += 2;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, EIP_ITEM_UNCONNECTED_DATA);
    boff += 2;
    eip_wr_le16(body + boff, 2);
    boff += 2;
    body[boff++] = CIP_SVC_GET_ATTR_SINGLE;
    body[boff++] = 0;

    uint8_t req[EIP_ENCAP_HDR_SIZE + 32];
    uint8_t resp[128];
    size_t resp_len = 0;
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, ha);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    expect(eip_stack_handle_encap_owned(s, 0xA0000002u, req,
                                        EIP_ENCAP_HDR_SIZE + boff, resp,
                                        sizeof(resp), &resp_len) == 0,
           "g5o foreign SendRR encap");
    expect(eip_rd_le32(resp + 8) == EIP_ENCAP_STATUS_INVALID_SESSION,
           "g5o foreign SendRR 0x64");

    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_UNREGISTERSESSION);
    eip_wr_le32(req + 4, ha);
    resp_len = 0;
    expect(eip_stack_handle_encap_owned(s, 0xA0000002u, req, EIP_ENCAP_HDR_SIZE,
                                        resp, sizeof(resp), &resp_len) == 0,
           "g5o foreign Unregister encap");
    expect(eip_rd_le32(resp + 8) == EIP_ENCAP_STATUS_INVALID_SESSION,
           "g5o foreign Unregister 0x64");
    expect(eip_stack_session_count(s) == 2, "g5o session kept");

    eip_stack_drop_encap_owner(s, 0xA0000001u);
    expect(eip_stack_session_count(s) == 1, "g5o drop owner A");
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, ha);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    resp_len = 0;
    expect(eip_stack_handle_encap_owned(s, 0xA0000001u, req,
                                        EIP_ENCAP_HDR_SIZE + boff, resp,
                                        sizeof(resp), &resp_len) == 0,
           "g5o SendRR after close");
    expect(eip_rd_le32(resp + 8) == EIP_ENCAP_STATUS_INVALID_SESSION,
           "g5o closed session 0x64");

    int filled = 1; /* B still registered */
    for (uint32_t i = 0; i < (uint32_t)EIP_CLASS3_SESSIONS_MAX; i++) {
        uint32_t owner = 0xB0000001u + i;
        if (owner == 0xA0000002u) {
            continue;
        }
        uint32_t h = test_register_owned(s, owner);
        if (h == 0) {
            break;
        }
        filled++;
        if (filled >= EIP_CLASS3_SESSIONS_MAX) {
            break;
        }
    }
    expect(filled == EIP_CLASS3_SESSIONS_MAX, "g5o table full");
    uint32_t overflow = test_register_owned(s, 0xC0FFEEu);
    expect(overflow == 0, "g5o 65th Register fails");
    eip_stack_drop_encap_owner(s, 0xA0000002u);
    expect(eip_stack_session_count(s) == EIP_CLASS3_SESSIONS_MAX - 1,
           "g5o slot reclaimed");
    uint32_t hnew = test_register_owned(s, 0xC0FFEEu);
    expect(hnew != 0, "g5o Register after reclaim");
    eip_stack_destroy(s);
}

static int sendrr_cip(eip_stack_t *s, uint32_t sess, const uint8_t *cip,
                      size_t cip_len, const uint8_t *mac, size_t mac_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    uint8_t body[256];
    size_t boff = 0;
    uint16_t items = mac_len ? 3 : 2;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, items);
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
        eip_wr_le16(body + boff, EIP_SEC_ITEM_INTEGRITY);
        boff += 2;
        eip_wr_le16(body + boff, (uint16_t)mac_len);
        boff += 2;
        memcpy(body + boff, mac, mac_len);
        boff += mac_len;
    }
    uint8_t req[EIP_ENCAP_HDR_SIZE + 256];
    memset(req, 0, EIP_ENCAP_HDR_SIZE + boff);
    eip_wr_le16(req, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, sess);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    return eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  resp_cap, resp_len);
}

static void test_g6_cip_set_reset_gates(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.protection_mode = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "g6 stack");
    uint8_t seed[8];
    memset(seed, 0xA5, sizeof(seed));
    expect(eip_stack_write_input(s, 0, seed, 8) == 8, "g6 seed input");

    uint32_t sess = test_register(s);
    expect(sess != 0, "g6 session");

    uint8_t reset[6] = {CIP_SVC_RESET, 2, 0x20, CIP_CLASS_IDENTITY, 0x24, 1};
    uint8_t resp[256];
    size_t n = 0;
    expect(eip_cip_route(s, reset, sizeof(reset), resp, sizeof(resp), &n) == 0,
           "g6 cip_route no session");
    expect(n >= 3 && resp[2] == CIP_STATUS_PRIVILEGE,
           "g6 unauthenticated reset -> 0x0F");

    uint8_t getid[8] = {CIP_SVC_GET_ATTR_SINGLE, 3, 0x20, CIP_CLASS_IDENTITY,
                        0x24, 1, 0x30, 1};
    n = 0;
    expect(eip_cip_route(s, getid, sizeof(getid), resp, sizeof(resp), &n) == 0,
           "g6 get without session");
    expect(n >= 3 && resp[2] == CIP_STATUS_SUCCESS, "g6 get still allowed");

    n = 0;
    expect(sendrr_cip(s, sess, reset, sizeof(reset), NULL, 0, resp, sizeof(resp),
                      &n) == 0,
           "g6 reset encap");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_SUCCESS,
           "g6 reset ok unprotected");
    uint8_t in[8];
    expect(eip_stack_read_input(s, 0, in, 8) == 8, "g6 read after reset");
    expect(in[0] == 0 && in[7] == 0, "g6 IO cleared");

    uint8_t qos_set[8] = {CIP_SVC_SET_ATTR_SINGLE, 3, 0x20, CIP_CLASS_QOS, 0x24,
                          1, 0x30, 5};
    uint8_t qos_body[9];
    memcpy(qos_body, qos_set, 8);
    qos_body[8] = 0x11;
    n = 0;
    expect(sendrr_cip(s, sess, qos_body, sizeof(qos_body), NULL, 0, resp,
                      sizeof(resp), &n) == 0,
           "g6 qos set");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_SUCCESS, "g6 qos set ok");

    eip_stack_destroy(s);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.protection_mode = 0x1;
    s = eip_stack_create(&cfg);
    expect(s != NULL, "g6 prot stack");
    memset(seed, 0x5A, sizeof(seed));
    eip_stack_write_input(s, 0, seed, 8);
    sess = test_register(s);
    n = 0;
    expect(sendrr_cip(s, sess, reset, sizeof(reset), NULL, 0, resp, sizeof(resp),
                      &n) == 0,
           "g6 prot reset encap");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_PRIVILEGE,
           "g6 reset protected -> 0x0F");
    expect(eip_stack_read_input(s, 0, in, 8) == 8, "g6 prot read");
    expect(in[0] == 0x5A, "g6 protected reset did not clear IO");

    uint8_t pm_set[12] = {CIP_SVC_SET_ATTR_SINGLE, 3, 0x20, CIP_CLASS_IDENTITY,
                          0x24, 1, 0x30, 17, 0, 0, 0, 0};
    n = 0;
    expect(sendrr_cip(s, sess, pm_set, sizeof(pm_set), NULL, 0, resp,
                      sizeof(resp), &n) == 0,
           "g6 prot mode write");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_PRIVILEGE,
           "g6 attr17 write protected");

    n = 0;
    expect(sendrr_cip(s, sess, qos_body, sizeof(qos_body), NULL, 0, resp,
                      sizeof(resp), &n) == 0,
           "g6 prot qos");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_PRIVILEGE,
           "g6 qos write protected");

    uint8_t lldp[14];
    size_t lo = 0;
    lldp[lo++] = CIP_SVC_SET_ATTR_SINGLE;
    lldp[lo++] = 4; /* words: 16-bit class + inst + attr = 8 bytes */
    lldp[lo++] = 0x21;
    lldp[lo++] = 0x00;
    eip_wr_le16(lldp + lo, CIP_CLASS_LLDP_MGMT);
    lo += 2;
    lldp[lo++] = 0x24;
    lldp[lo++] = 1;
    lldp[lo++] = 0x30;
    lldp[lo++] = 1;
    eip_wr_le32(lldp + lo, 0);
    lo += 4;
    n = 0;
    expect(sendrr_cip(s, sess, lldp, lo, NULL, 0, resp, sizeof(resp), &n) == 0,
           "g6 prot lldp");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_PRIVILEGE,
           "g6 lldp write protected");
    eip_stack_destroy(s);

    memset(&cfg, 0, sizeof(cfg));
    cfg.mock = 1;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.security_class = EIP_SECURITY_CLASS_1;
    memset(cfg.psk, 0x22, EIP_PSK_LEN);
    cfg.psk_set = 1;
    s = eip_stack_create(&cfg);
    expect(s != NULL, "g6 sec stack");
    sess = test_register(s);
    n = 0;
    expect(sendrr_cip(s, sess, reset, sizeof(reset), NULL, 0, resp, sizeof(resp),
                      &n) == 0,
           "g6 sec reset no mac");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_PRIVILEGE,
           "g6 reset without HMAC");

    uint8_t material[4 + 16];
    eip_wr_le32(material, sess);
    memcpy(material + 4, reset, sizeof(reset));
    uint8_t mac[EIP_HMAC_LEN];
    eip_hmac_sha256(cfg.psk, EIP_PSK_LEN, material, 4 + sizeof(reset), mac);
    n = 0;
    expect(sendrr_cip(s, sess, reset, sizeof(reset), mac, EIP_HMAC_LEN, resp,
                      sizeof(resp), &n) == 0,
           "g6 sec reset mac");
    expect(cip_status_from_encap(resp, n) == CIP_STATUS_SUCCESS,
           "g6 reset with HMAC");
    eip_stack_destroy(s);
}

static int tcp_connect_local(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) != 1) {
        close(fd);
        return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static void test_g7_eip_tcp_idle_and_per_ip(void)
{
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 0;
    snprintf(cfg.bind_ip, sizeof(cfg.bind_ip), "127.0.0.1");
    cfg.tcp_port = 16156;
    cfg.udp_io_port = 16157;
    cfg.input_size = 8;
    cfg.output_size = 8;
    cfg.idle_timeout_ms = 200;
    cfg.max_conn_per_ip = 1;
    cfg.lldp_enable = 0;
    cfg.acd_enable = 0;
    eip_stack_t *s = eip_stack_create(&cfg);
    expect(s != NULL, "g7 eip create");
    if (!s) {
        return;
    }
    if (eip_stack_start(s) != 0) {
        fprintf(stderr, "FAIL: g7 eip start (port busy?)\n");
        g_fail = 1;
        eip_stack_destroy(s);
        return;
    }
    int a = tcp_connect_local(16156);
    expect(a >= 0, "g7 eip connect a");
    for (int i = 0; i < 30; i++) {
        eip_stack_poll(s);
        usleep(1000);
    }
    int b = tcp_connect_local(16156);
    expect(b >= 0, "g7 eip connect b");
    for (int i = 0; i < 30; i++) {
        eip_stack_poll(s);
        usleep(1000);
    }
    uint8_t tmp[8];
    ssize_t nr = recv(b, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(nr == 0 || nr < 0, "g7 eip per-ip second dropped");
    if (b >= 0) {
        close(b);
    }

    usleep(250000);
    for (int i = 0; i < 20; i++) {
        eip_stack_poll(s);
        usleep(1000);
    }
    nr = recv(a, tmp, sizeof(tmp), MSG_DONTWAIT);
    expect(nr == 0 || nr < 0, "g7 eip idle dropped");
    if (a >= 0) {
        close(a);
    }
    eip_stack_destroy(s);
}

int main(void)
{
    test_register_session();
    test_identity_get();
    test_assembly_rw_and_forward_open();
    test_security_integrity();
    test_qos_dscp_ct_defaults();
    test_acd_identity_state();
    test_lldp_mgmt_and_frame();
    test_class1_watchdog_and_rt_stats();
    test_list_identity_and_protection();
    test_g2_watchdog_dup_path_size();
    test_g5_encap_session_and_cip_len();
    test_g5_session_owner_and_close();
    test_g6_cip_set_reset_gates();
    test_g7_eip_tcp_idle_and_per_ip();
    if (g_fail) {
        fprintf(stderr, "eip stack tests FAILED\n");
        return 1;
    }
    printf("eip stack tests OK (CT21/23 ship profile)\n");
    return 0;
}
