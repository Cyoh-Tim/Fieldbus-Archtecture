#include "eip_endian.h"
#include "eip_stack.h"

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
    eip_wr_le32(req + 4, 1);
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
    fo[off++] = 0;    /* path size words */

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
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);

    uint8_t resp[512];
    size_t resp_len = 0;
    expect(eip_stack_handle_encap(s, req, EIP_ENCAP_HDR_SIZE + boff, resp,
                                  sizeof(resp), &resp_len) == 0,
           "forward open encap");
    expect(eip_stack_class1_up(s) == 1, "class1 up after forward open");

    /* Grab O->T conn id from Forward Open reply (service | 0x80 == 0xD4) */
    uint32_t o2t = 0;
    for (size_t i = 0; i + 12 < resp_len; i++) {
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

int main(void)
{
    test_register_session();
    test_identity_get();
    test_assembly_rw_and_forward_open();
    if (g_fail) {
        fprintf(stderr, "eip stack tests FAILED\n");
        return 1;
    }
    printf("eip stack tests OK\n");
    return 0;
}
