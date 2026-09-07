#include "pn_internal.h"

#include <string.h>

#include "pn_endian.h"

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len)
{
    (void)slot;
    (void)subslot;
    if (index != 0xAFF0) {
        if (cap >= 4) {
            memset(out, 0, 4);
            *out_len = 4;
            return 0;
        }
        return -1;
    }
    /* I&M0 */
    uint8_t im[54];
    memset(im, 0, sizeof(im));
    pn_wr_be16(im, s->cfg.vendor_id);
    memcpy(im + 2, "FB-ARCH-PN-DEV     ", 20); /* OrderID 20 bytes */
    memcpy(im + 22, "SN00000000000001", 16);
    pn_wr_be16(im + 38, 0x0001); /* HW rev */
    im[40] = 'V';
    im[41] = 1;
    im[42] = 0;
    im[43] = 0;
    pn_wr_be16(im + 44, 0);
    pn_wr_be16(im + 46, 0xF600); /* Profile IO */
    pn_wr_be16(im + 48, 0x0001);
    pn_wr_be16(im + 50, 0x0101);
    pn_wr_be16(im + 52, 0x001E); /* I&M0+1 supported-ish */
    if (cap < sizeof(im)) {
        return -1;
    }
    memcpy(out, im, sizeof(im));
    *out_len = sizeof(im);
    return 0;
}
