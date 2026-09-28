#include "mb_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static mb_stack_t *s;
    if (!s) {
        mb_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.role = MB_ROLE_SERVER;
        cfg.unit_id = 1;
        cfg.n_holding = 64;
        cfg.n_input = 64;
        cfg.n_coil = 64;
        cfg.n_discrete = 64;
        s = mb_stack_create(&cfg);
        if (!s) {
            return 0;
        }
    }
    uint8_t resp[512];
    size_t resp_len = 0;
    (void)mb_stack_handle_adu(s, data, size, resp, sizeof(resp), &resp_len);
    return 0;
}
