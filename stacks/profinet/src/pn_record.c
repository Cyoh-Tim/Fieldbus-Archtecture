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

static void put_channel_diag(uint8_t *p)
{
    pn_wr_be16(p, 0x8000);
    pn_wr_be16(p + 2, 0x0800);
    pn_wr_be16(p + 4, 0x0010);
}

static size_t put_diagnosis(uint8_t *out, size_t cap, int ext)
{
    uint8_t body[24];
    memset(body, 0, sizeof(body));
    size_t off = 0;
    off += 2; /* align */
    pn_wr_be16(body + off, 0); /* slot */
    off += 2;
    pn_wr_be16(body + off, 0x8001);
    off += 2;
    put_channel_diag(body + off);
    off += 6;
    if (ext) {
        pn_wr_be16(body + off, 0); /* ExtChannelErrorType */
        off += 2;
        pn_wr_be32(body + off, 0); /* ExtChannelAddValue */
        off += 4;
    }
    return rec_block(out, cap, PN_BLOCK_DIAGNOSIS, body, (uint16_t)off);
}

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len)
{
    size_t n = 0;
    if (index == PN_INDEX_IM0) {
        n = put_im0(s, out, cap);
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
    } else if (index == PN_INDEX_CHAN_DIAG || index == PN_INDEX_EXT_CHAN_DIAG ||
               index == PN_INDEX_DIAG_AR) {
        if (!s->diag_present) {
            *out_len = 0;
            return 0;
        }
        n = put_diagnosis(out, cap, index == PN_INDEX_EXT_CHAN_DIAG);
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
