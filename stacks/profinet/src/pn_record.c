#include "pn_internal.h"

#include <string.h>

#include "pn_endian.h"

static size_t rec_block(uint8_t *p, size_t cap, uint16_t type,
                        const uint8_t *body, uint16_t blen)
{
    size_t n = 6u + blen;
    if (n > cap) {
        return 0;
    }
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, (uint16_t)(2 + blen));
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, blen);
    return n;
}

static uint32_t default_mod_ident(uint16_t slot)
{
    return slot == 0 ? 1u : 0x10u;
}

static uint32_t default_sub_ident(uint16_t slot, uint16_t subslot)
{
    if (subslot == 0x8000) {
        return 2;
    }
    if (subslot == 0x8001) {
        return 3;
    }
    return slot == 0 ? 1u : 0x11u;
}

static void gsdml_subs(pn_submod_t *out, int *n, uint16_t in_len,
                       uint16_t out_len)
{
    memset(out, 0, 4 * sizeof(*out));
    out[0].slot = 0;
    out[0].subslot = 1;
    out[0].module_ident = 1;
    out[0].submodule_ident = 1;
    out[1].slot = 0;
    out[1].subslot = 0x8000;
    out[1].module_ident = 1;
    out[1].submodule_ident = 2;
    out[2].slot = 0;
    out[2].subslot = 0x8001;
    out[2].module_ident = 1;
    out[2].submodule_ident = 3;
    out[3].slot = 1;
    out[3].subslot = 1;
    out[3].module_ident = 0x10;
    out[3].submodule_ident = 0x11;
    out[3].in_len = in_len;
    out[3].out_len = out_len;
    *n = 4;
}

static size_t put_im0(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    uint8_t im[54];
    memset(im, 0, sizeof(im));
    pn_wr_be16(im, s->cfg.vendor_id);
    memcpy(im + 2, "FB-ARCH-PN-DEV     ", 20);
    memcpy(im + 22, "SN00000000000001", 16);
    pn_wr_be16(im + 38, 0x0001);
    im[40] = 'V';
    im[41] = 1;
    im[42] = 0;
    im[43] = 0;
    pn_wr_be16(im + 44, 0);
    pn_wr_be16(im + 46, 0xF600);
    pn_wr_be16(im + 48, 0x0001);
    pn_wr_be16(im + 50, 0x0101);
    pn_wr_be16(im + 52, 0x001E);
    return rec_block(out, cap, PN_BLOCK_IM0, im, sizeof(im));
}

static int sub_wanted(const pn_submod_t *sm, uint16_t index, uint16_t slot,
                      uint16_t subslot)
{
    if (index == PN_INDEX_REALIDENT_SUB) {
        return sm->slot == slot && sm->subslot == subslot;
    }
    if (index == PN_INDEX_REALIDENT_SLOT) {
        return sm->slot == slot;
    }
    return 1;
}

static size_t put_realident(const pn_stack_t *s, uint16_t slot, uint16_t subslot,
                            uint16_t index, uint8_t *out, size_t cap)
{
    pn_submod_t tmp[PN_SUBMOD_MAX];
    const pn_submod_t *subs = s->ar.sub;
    int n = s->ar.n_sub;
    if (n <= 0) {
        gsdml_subs(tmp, &n, s->cfg.input_len, s->cfg.output_len);
        subs = tmp;
    }

    uint8_t body[512];
    size_t off = 2; /* NumberOfAPIs filled later */
    uint16_t napis = 1;
    pn_wr_be32(body + off, 0); /* API 0 */
    off += 4;
    size_t nmod_at = off;
    pn_wr_be16(body + off, 0);
    off += 2;
    uint16_t nmod = 0;
    int i = 0;
    while (i < n) {
        if (!sub_wanted(&subs[i], index, slot, subslot)) {
            i++;
            continue;
        }
        uint16_t sl = subs[i].slot;
        uint32_t mid = subs[i].module_ident
                           ? subs[i].module_ident
                           : default_mod_ident(sl);
        size_t nsub_at;
        uint16_t nsub = 0;
        if (off + 8 > sizeof(body)) {
            break;
        }
        pn_wr_be16(body + off, sl);
        pn_wr_be32(body + off + 2, mid);
        nsub_at = off + 6;
        pn_wr_be16(body + nsub_at, 0);
        off += 8;
        nmod++;
        while (i < n && subs[i].slot == sl) {
            if (!sub_wanted(&subs[i], index, slot, subslot)) {
                i++;
                continue;
            }
            if (off + 6 > sizeof(body)) {
                break;
            }
            uint32_t sid = subs[i].submodule_ident
                               ? subs[i].submodule_ident
                               : default_sub_ident(subs[i].slot, subs[i].subslot);
            pn_wr_be16(body + off, subs[i].subslot);
            pn_wr_be32(body + off + 2, sid);
            off += 6;
            nsub++;
            i++;
        }
        pn_wr_be16(body + nsub_at, nsub);
    }
    pn_wr_be16(body, napis);
    pn_wr_be16(body + nmod_at, nmod);
    return rec_block(out, cap, PN_BLOCK_REALIDENT, body, (uint16_t)off);
}

static size_t put_pdport_real(uint16_t slot, uint16_t subslot, uint8_t *out,
                              size_t cap)
{
    static const char port[] = "port-001";
    uint8_t body[64];
    memset(body, 0, sizeof(body));
    size_t off = 0;
    off += 2; /* align4 after BlockHeader */
    pn_wr_be16(body + off, slot);
    off += 2;
    pn_wr_be16(body + off, subslot);
    off += 2;
    body[off++] = (uint8_t)(sizeof(port) - 1);
    memcpy(body + off, port, sizeof(port) - 1);
    off += sizeof(port) - 1;
    body[off++] = 0; /* NumberOfPeers */
    while ((6u + off) & 3u) {
        body[off++] = 0;
    }
    pn_wr_be16(body + off, 0x0010); /* 100BaseTXFD, GSDML MAUTypes=16 */
    off += 2;
    off += 2; /* pad */
    pn_wr_be32(body + off, 0);
    off += 4; /* DomainBoundary */
    pn_wr_be32(body + off, 0);
    off += 4; /* MulticastBoundary */
    pn_wr_be16(body + off, 0x0001); /* Link UP */
    off += 2;
    off += 2; /* pad */
    pn_wr_be32(body + off, 0); /* MediaType copper/unknown */
    off += 4;
    return rec_block(out, cap, PN_BLOCK_PDPORT_REAL, body, (uint16_t)off);
}

static size_t put_pdif_real(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    const char *name = s->cfg.station_name;
    size_t nlen = strlen(name);
    if (nlen > 64) {
        nlen = 64;
    }
    uint8_t body[128];
    memset(body, 0, sizeof(body));
    size_t off = 0;
    body[off++] = (uint8_t)nlen;
    memcpy(body + off, name, nlen);
    off += nlen;
    while ((6u + off) & 3u) {
        body[off++] = 0;
    }
    memcpy(body + off, s->cfg.mac, 6);
    off += 6;
    off += 2; /* pad */
    pn_wr_be32(body + off, s->cfg.ip);
    off += 4;
    pn_wr_be32(body + off, s->cfg.netmask);
    off += 4;
    pn_wr_be32(body + off, s->cfg.gateway);
    off += 4;
    return rec_block(out, cap, PN_BLOCK_PDIF_REAL, body, (uint16_t)off);
}

static size_t put_im_block(uint8_t *out, size_t cap, uint16_t type,
                           const void *body, uint16_t blen)
{
    return rec_block(out, cap, type, (const uint8_t *)body, blen);
}

static size_t put_im1(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    uint8_t im[54];
    memcpy(im, s->im1_function, 32);
    memcpy(im + 32, s->im1_location, 22);
    return put_im_block(out, cap, PN_BLOCK_IM1, im, sizeof(im));
}

static size_t put_im2(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    return put_im_block(out, cap, PN_BLOCK_IM2, s->im2_date, 16);
}

static size_t put_im3(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    return put_im_block(out, cap, PN_BLOCK_IM3, s->im3_desc, 54);
}

static size_t put_im4(const pn_stack_t *s, uint8_t *out, size_t cap)
{
    return put_im_block(out, cap, PN_BLOCK_IM4, s->im4_sig, 54);
}

static size_t put_pd_stat(const pn_stack_t *s, uint8_t *out, size_t cap,
                          uint16_t btype)
{
    uint8_t body[28];
    memset(body, 0, sizeof(body));
    size_t off = 2;
    pn_wr_be32(body + off, s->if_in_octets);
    off += 4;
    pn_wr_be32(body + off, s->if_out_octets);
    off += 4;
    pn_wr_be32(body + off, s->if_in_discards);
    off += 4;
    pn_wr_be32(body + off, s->if_out_discards);
    off += 4;
    pn_wr_be32(body + off, s->if_in_errors);
    off += 4;
    pn_wr_be32(body + off, s->if_out_errors);
    off += 4;
    return rec_block(out, cap, btype, body, (uint16_t)off);
}

static size_t put_stored(uint8_t *out, size_t cap, const uint8_t *data,
                         uint16_t n)
{
    if (n == 0 || n > cap) {
        return 0;
    }
    memcpy(out, data, n);
    return n;
}

void pn_diag_arm_default(pn_stack_t *s)
{
    if (!s || s->n_diag > 0) {
        return;
    }
    s->diag_present = 1;
    s->diag[0].slot = 0;
    s->diag[0].subslot = 0x8001;
    s->diag[0].channel = 0x8000;
    s->diag[0].properties = 0x0800; /* appears */
    s->diag[0].error_type = 0x0010;
    s->diag[0].present = 1;
    s->diag[1].slot = 0;
    s->diag[1].subslot = 0x8001;
    s->diag[1].channel = 0x0000;
    s->diag[1].properties = 0x0C00; /* appears + maintenance demanded */
    s->diag[1].error_type = 0x0007;
    s->diag[1].qualified = 0x00008000u;
    s->diag[1].present = 1;
    s->n_diag = 2;
}

static void put_channel_diag(uint8_t *p, const pn_diag_ch_t *d)
{
    pn_wr_be16(p, d->channel);
    pn_wr_be16(p + 2, d->properties);
    pn_wr_be16(p + 4, d->error_type);
}

static size_t put_diagnosis(const pn_stack_t *s, uint8_t *out, size_t cap,
                            int ext, int qual)
{
    uint8_t body[96];
    memset(body, 0, sizeof(body));
    size_t off = 0;
    off += 2;
    pn_wr_be16(body + off, 0);
    off += 2;
    pn_wr_be16(body + off, 0x8001);
    off += 2;
    int n = s->n_diag > 0 ? s->n_diag : 0;
    if (n == 0) {
        pn_diag_ch_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        tmp.channel = 0x8000;
        tmp.properties = 0x0800;
        tmp.error_type = 0x0010;
        put_channel_diag(body + off, &tmp);
        off += 6;
        if (ext || qual) {
            pn_wr_be16(body + off, 0);
            off += 2;
            pn_wr_be32(body + off, 0);
            off += 4;
        }
        if (qual) {
            pn_wr_be32(body + off, 0);
            off += 4;
        }
        return rec_block(out, cap, PN_BLOCK_DIAGNOSIS, body, (uint16_t)off);
    }
    for (int i = 0; i < n; i++) {
        if (!s->diag[i].present) {
            continue;
        }
        if (off + 16 > sizeof(body)) {
            break;
        }
        put_channel_diag(body + off, &s->diag[i]);
        off += 6;
        if (ext || qual) {
            pn_wr_be16(body + off, s->diag[i].ext_error);
            off += 2;
            pn_wr_be32(body + off, s->diag[i].ext_add);
            off += 4;
        }
        if (qual) {
            pn_wr_be32(body + off, s->diag[i].qualified);
            off += 4;
        }
    }
    return rec_block(out, cap, PN_BLOCK_DIAGNOSIS, body, (uint16_t)off);
}

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    if (index == PN_INDEX_IM0) {
        n = put_im0(s, out, cap);
    } else if (index == PN_INDEX_IM1) {
        n = put_im1(s, out, cap);
    } else if (index == PN_INDEX_IM2) {
        n = put_im2(s, out, cap);
    } else if (index == PN_INDEX_IM3) {
        n = put_im3(s, out, cap);
    } else if (index == PN_INDEX_IM4) {
        n = put_im4(s, out, cap);
    } else if (index == PN_INDEX_REALIDENT_API ||
               index == PN_INDEX_REALIDENT_AR || index == PN_INDEX_EXPIDENT_AR ||
               index == PN_INDEX_REALIDENT_SLOT ||
               index == PN_INDEX_REALIDENT_SUB) {
        n = put_realident(s, slot, subslot, index, out, cap);
    } else if (index == PN_INDEX_PDPORT_REAL) {
        n = put_pdport_real(slot, subslot ? subslot : (uint16_t)0x8001, out,
                            cap);
    } else if (index == PN_INDEX_PDIF_REAL) {
        n = put_pdif_real(s, out, cap);
    } else if (index == PN_INDEX_PDPORT_STAT) {
        n = put_pd_stat(s, out, cap, PN_BLOCK_PDPORT_STAT);
    } else if (index == PN_INDEX_PDIF_STAT) {
        n = put_pd_stat(s, out, cap, PN_BLOCK_PDIF_STAT);
    } else if (index == PN_INDEX_PDPORT_ADJUST) {
        n = put_stored(out, cap, s->pdport_adjust, s->pdport_adjust_len);
        if (n == 0) {
            *out_len = 0;
            return 0;
        }
    } else if (index == PN_INDEX_PDPORT_CHECK) {
        n = put_stored(out, cap, s->pdport_check, s->pdport_check_len);
        if (n == 0) {
            *out_len = 0;
            return 0;
        }
    } else if (index == PN_INDEX_PDIF_ADJUST) {
        n = put_stored(out, cap, s->pdif_adjust, s->pdif_adjust_len);
        if (n == 0) {
            *out_len = 0;
            return 0;
        }
    } else if (index == PN_INDEX_CHAN_DIAG || index == PN_INDEX_EXT_CHAN_DIAG ||
               index == PN_INDEX_QUAL_CHAN_DIAG ||
               index == PN_INDEX_DIAG_DATA || index == PN_INDEX_DIAG_AR) {
        if (!s->diag_present) {
            *out_len = 0;
            return 0;
        }
        n = put_diagnosis(s, out, cap, index != PN_INDEX_CHAN_DIAG,
                          index == PN_INDEX_QUAL_CHAN_DIAG ||
                              index == PN_INDEX_DIAG_DATA);
    } else {
        /* Unknown index: empty success. Controllers treat a PNIO error as
         * fatal; TIA and others skip optional records if the length is 0. */
        *out_len = 0;
        return 0;
    }
    if (n == 0) {
        return -1;
    }
    *out_len = n;
    return 0;
}

static const uint8_t *skip_block_hdr(const uint8_t *data, uint32_t *len,
                                     uint16_t expect)
{
    if (*len >= 6 && pn_rd_be16(data) == expect) {
        uint16_t bl = pn_rd_be16(data + 2);
        uint32_t body = (bl >= 2) ? (uint32_t)(bl - 2) : 0;
        if (6u + body <= *len) {
            *len = body;
            return data + 6;
        }
    }
    return data;
}

static void store_pdev(uint8_t *dst, uint16_t *n, const uint8_t *data,
                       uint32_t len)
{
    if (len > PN_PDEV_STORE) {
        len = PN_PDEV_STORE;
    }
    memcpy(dst, data, len);
    *n = (uint16_t)len;
}

int pn_record_write(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    uint16_t index, const uint8_t *data, uint32_t len)
{
    (void)slot;
    (void)subslot;
    if (!s || !data) {
        return 0;
    }
    if (index == PN_INDEX_IM1) {
        uint32_t n = len;
        const uint8_t *p = skip_block_hdr(data, &n, PN_BLOCK_IM1);
        if (n >= 54) {
            memcpy(s->im1_function, p, 32);
            memcpy(s->im1_location, p + 32, 22);
        } else if (n >= 32) {
            memcpy(s->im1_function, p, 32);
            if (n > 32) {
                size_t loc = n - 32;
                if (loc > 22) {
                    loc = 22;
                }
                memcpy(s->im1_location, p + 32, loc);
            }
        }
        return 0;
    }
    if (index == PN_INDEX_IM2) {
        uint32_t n = len;
        const uint8_t *p = skip_block_hdr(data, &n, PN_BLOCK_IM2);
        memset(s->im2_date, ' ', 16);
        memcpy(s->im2_date, p, n < 16 ? n : 16);
        return 0;
    }
    if (index == PN_INDEX_IM3) {
        uint32_t n = len;
        const uint8_t *p = skip_block_hdr(data, &n, PN_BLOCK_IM3);
        memset(s->im3_desc, ' ', 54);
        memcpy(s->im3_desc, p, n < 54 ? n : 54);
        return 0;
    }
    if (index == PN_INDEX_IM4) {
        uint32_t n = len;
        const uint8_t *p = skip_block_hdr(data, &n, PN_BLOCK_IM4);
        memset(s->im4_sig, 0, 54);
        memcpy(s->im4_sig, p, n < 54 ? n : 54);
        return 0;
    }
    if (index == PN_INDEX_PDPORT_ADJUST && len >= 6) {
        store_pdev(s->pdport_adjust, &s->pdport_adjust_len, data, len);
        return 0;
    }
    if (index == PN_INDEX_PDPORT_CHECK && len >= 6) {
        store_pdev(s->pdport_check, &s->pdport_check_len, data, len);
        return 0;
    }
    if (index == PN_INDEX_PDIF_ADJUST && len >= 6) {
        store_pdev(s->pdif_adjust, &s->pdif_adjust_len, data, len);
        return 0;
    }
    /* Short dummy writes (WriteMultiple 4-byte padding) are ACK'd and ignored. */
    return 0;
}
