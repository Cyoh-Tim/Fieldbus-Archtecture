#include "pn_internal.h"

#include <string.h>

#include "pn_endian.h"

static void im_spaces(char *p, size_t n)
{
    memset(p, ' ', n);
}

static const uint8_t *im_payload(const uint8_t *data, size_t len, size_t want,
                                 size_t *out_n)
{
    /* CM Write may prefix a 6-byte BlockHeader (0x0020..0x0024). */
    if (data && len >= want + 6u && pn_rd_be16(data) >= PN_BLOCK_IM0 &&
        pn_rd_be16(data) <= 0x0030) {
        data += 6;
        len -= 6;
    }
    *out_n = len < want ? len : want;
    return data;
}

/* I&M record on the wire is BlockHeader (type, length, version 1.0) + payload.
 * block_length counts the version and the payload, not BlockType/BlockLength. */
static int emit_im(uint8_t *out, size_t cap, size_t *out_len, uint16_t btype,
                   const uint8_t *payload, size_t plen)
{
    if (cap < 6u + plen) {
        return -1;
    }
    pn_wr_be16(out, btype);
    pn_wr_be16(out + 2, (uint16_t)(2u + plen));
    out[4] = 1;
    out[5] = 0;
    if (plen > 0 && payload) {
        memcpy(out + 6, payload, plen);
    }
    *out_len = 6u + plen;
    return 0;
}

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len)
{
    (void)slot;
    (void)subslot;
    if (!s || !out || !out_len) {
        return -1;
    }

    if (index == PN_INDEX_IM0) {
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
        pn_wr_be16(im + 52, 0x001E); /* I&M1–4 supported */
        return emit_im(out, cap, out_len, PN_BLOCK_IM0, im, sizeof(im));
    }

    if (index == PN_INDEX_IM1) {
        uint8_t im[PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN];
        memcpy(im, s->im1_function, PN_IM1_FUNC_LEN);
        memcpy(im + PN_IM1_FUNC_LEN, s->im1_location, PN_IM1_LOC_LEN);
        return emit_im(out, cap, out_len, PN_BLOCK_IM1, im, sizeof(im));
    }
    if (index == PN_INDEX_IM2) {
        return emit_im(out, cap, out_len, PN_BLOCK_IM2, (const uint8_t *)s->im2_date,
                       PN_IM2_DATE_LEN);
    }
    if (index == PN_INDEX_IM3) {
        return emit_im(out, cap, out_len, PN_BLOCK_IM3, (const uint8_t *)s->im3_desc,
                       PN_IM3_DESC_LEN);
    }
    if (index == PN_INDEX_IM4) {
        return emit_im(out, cap, out_len, PN_BLOCK_IM4, s->im4_sig, PN_IM4_SIG_LEN);
    }

    /* Unknown index: empty record (not an RPC reject). */
    if (cap >= 4) {
        memset(out, 0, 4);
        *out_len = 4;
        return 0;
    }
    return -1;
}

int pn_record_write(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    uint16_t index, const uint8_t *data, size_t len)
{
    (void)slot;
    (void)subslot;
    if (!s) {
        return -1;
    }
    if (!data) {
        len = 0;
    }

    if (index == PN_INDEX_IM1) {
        size_t n = 0;
        const uint8_t *p = im_payload(data, len, PN_IM1_FUNC_LEN + PN_IM1_LOC_LEN,
                                      &n);
        im_spaces(s->im1_function, PN_IM1_FUNC_LEN);
        im_spaces(s->im1_location, PN_IM1_LOC_LEN);
        if (n > 0) {
            size_t f = n < PN_IM1_FUNC_LEN ? n : PN_IM1_FUNC_LEN;
            memcpy(s->im1_function, p, f);
            if (n > PN_IM1_FUNC_LEN) {
                size_t l = n - PN_IM1_FUNC_LEN;
                if (l > PN_IM1_LOC_LEN) {
                    l = PN_IM1_LOC_LEN;
                }
                memcpy(s->im1_location, p + PN_IM1_FUNC_LEN, l);
            }
        }
        return 0;
    }
    if (index == PN_INDEX_IM2) {
        size_t n = 0;
        const uint8_t *p = im_payload(data, len, PN_IM2_DATE_LEN, &n);
        im_spaces(s->im2_date, PN_IM2_DATE_LEN);
        if (n) {
            memcpy(s->im2_date, p, n);
        }
        return 0;
    }
    if (index == PN_INDEX_IM3) {
        size_t n = 0;
        const uint8_t *p = im_payload(data, len, PN_IM3_DESC_LEN, &n);
        im_spaces(s->im3_desc, PN_IM3_DESC_LEN);
        if (n) {
            memcpy(s->im3_desc, p, n);
        }
        return 0;
    }
    if (index == PN_INDEX_IM4) {
        size_t n = 0;
        const uint8_t *p = im_payload(data, len, PN_IM4_SIG_LEN, &n);
        memset(s->im4_sig, 0, PN_IM4_SIG_LEN);
        if (n) {
            memcpy(s->im4_sig, p, n);
        }
        return 0;
    }

    /* Parameter records (e.g. GSDML index 1) and other writes: accept. */
    return 0;
}
