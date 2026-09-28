#include "slmp_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static slmp_stack_t *s;
    if (!s) {
        slmp_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.role = SLMP_ROLE_SERVER;
        cfg.frame = SLMP_FRAME_3E_BINARY;
        cfg.pc_no = 0xFF;
        cfg.dest_module_io = 0x03FF;
        s = slmp_stack_create(&cfg);
        if (!s) {
            return 0;
        }
    }
    uint8_t resp[SLMP_FRAME_MAX];
    size_t resp_len = 0;
    (void)slmp_stack_handle_request(s, data, size, resp, sizeof(resp),
                                    &resp_len);
    return 0;
}
