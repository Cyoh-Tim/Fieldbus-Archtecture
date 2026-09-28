#include "eip_endian.h"
#include "eip_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static eip_stack_t *s;
    static uint32_t session;
    if (!s) {
        eip_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.mock = 1;
        cfg.input_size = 8;
        cfg.output_size = 8;
        cfg.input_assembly = 150;
        cfg.output_assembly = 101;
        cfg.config_assembly = 100;
        s = eip_stack_create(&cfg);
        if (!s) {
            return 0;
        }
        uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
        memset(req, 0, sizeof(req));
        eip_wr_le16(req, EIP_CMD_REGISTERSESSION);
        eip_wr_le16(req + 2, 4);
        eip_wr_le16(req + 24, 1);
        uint8_t resp[64];
        size_t n = 0;
        if (eip_stack_handle_encap(s, req, sizeof(req), resp, sizeof(resp),
                                   &n) == 0 &&
            n >= 8) {
            session = eip_rd_le32(resp + 4);
        }
    }
    uint8_t buf[4096];
    size_t n = size;
    if (n > sizeof(buf)) {
        n = sizeof(buf);
    }
    memcpy(buf, data, n);
    if (n >= EIP_ENCAP_HDR_SIZE && session != 0 &&
        eip_rd_le16(buf) == EIP_CMD_SENDRRDATA) {
        eip_wr_le32(buf + 4, session);
    }
    uint8_t resp[EIP_TCP_BUF_MAX];
    size_t resp_len = 0;
    (void)eip_stack_handle_encap(s, buf, n, resp, sizeof(resp), &resp_len);
    if (n >= 8 && eip_rd_le16(buf) == EIP_CMD_REGISTERSESSION &&
        resp_len >= 8 && eip_rd_le32(resp + 8) == 0) {
        uint32_t h = eip_rd_le32(resp + 4);
        if (h != 0) {
            session = h;
        }
    }
    return 0;
}
