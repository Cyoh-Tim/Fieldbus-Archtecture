#include "eip_stack.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static eip_stack_t *s;
    if (!s) {
        eip_cfg_t cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.mock = 1;
        cfg.input_size = 8;
        cfg.output_size = 8;
        s = eip_stack_create(&cfg);
        if (!s) {
            return 0;
        }
    }
    (void)eip_stack_handle_io(s, data, size);
    return 0;
}
