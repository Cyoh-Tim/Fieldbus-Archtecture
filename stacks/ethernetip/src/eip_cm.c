#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include <string.h>

static size_t cm_err(uint8_t *resp, size_t cap, uint8_t service, uint8_t status,
                     uint16_t ext)
{
    if (cap < 6) {
        return 0;
    }
    resp[0] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[1] = 0;
    resp[2] = status;
    resp[3] = 1;
    eip_wr_le16(resp + 4, ext);
    return 6;
}

static eip_class1_conn_t *alloc_conn(eip_stack_t *s)
{
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        if (!s->class1[i].in_use) {
            memset(&s->class1[i], 0, sizeof(s->class1[i]));
            s->class1[i].in_use = 1;
            return &s->class1[i];
        }
    }
    return NULL;
}

static uint16_t conn_size_from_net(uint32_t net_params, int large)
{
    if (large) {
        return (uint16_t)(net_params & 0xffff);
    }
    return (uint16_t)(net_params & 0x1ff);
}

int eip_cm_forward_open(eip_stack_t *s, const uint8_t *data, size_t len,
                        int large, uint8_t *resp, size_t resp_cap,
                        size_t *resp_len)
{
    uint8_t service =
        large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    /* Minimum Forward Open body (no connection path) ~36 bytes + path */
    size_t min_len = large ? 40 : 36;
    if (len < min_len) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_INVALID_PARAM, 0);
        return 0;
    }

    size_t off = 0;
    /* priority/tick + timeout ticks */
    off += 2;
    uint32_t o2t_id = eip_rd_le32(data + off);
    off += 4;
    uint32_t t2o_id = eip_rd_le32(data + off);
    off += 4;
    uint16_t conn_serial = eip_rd_le16(data + off);
    off += 2;
    uint16_t orig_vendor = eip_rd_le16(data + off);
    off += 2;
    uint32_t orig_serial = eip_rd_le32(data + off);
    off += 4;
    uint8_t timeout_mult = data[off];
    off += 1; /* timeout multiplier */
    off += 3; /* reserved */
    uint32_t o2t_rpi = eip_rd_le32(data + off);
    off += 4;
    uint32_t o2t_params;
    if (large) {
        o2t_params = eip_rd_le32(data + off);
        off += 4;
    } else {
        o2t_params = eip_rd_le16(data + off);
        off += 2;
    }
    uint32_t t2o_rpi = eip_rd_le32(data + off);
    off += 4;
    uint32_t t2o_params;
    if (large) {
        t2o_params = eip_rd_le32(data + off);
        off += 4;
    } else {
        t2o_params = eip_rd_le16(data + off);
        off += 2;
    }
    off += 1; /* transport type/trigger */
    if (off >= len) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_INVALID_PARAM, 0);
        return 0;
    }
    uint8_t path_words = data[off++];
    size_t path_bytes = (size_t)path_words * 2u;
    if (off + path_bytes > len) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_PATH_SEGMENT, 0);
        return 0;
    }

    uint16_t o2t_size = conn_size_from_net(o2t_params, large);
    uint16_t t2o_size = conn_size_from_net(t2o_params, large);

    /* Accept if sizes fit configured assemblies (allow seq count + data).
     * Originators often include 2-byte sequence in connected data size. */
    uint16_t need_out = s->output_size;
    uint16_t need_in = s->input_size;
    if (o2t_size < need_out || t2o_size < need_in) {
        /* Still accept if they match with +2 seq overhead or equal raw */
        if (!(o2t_size == need_out + 2 || o2t_size == need_out) ||
            !(t2o_size == need_in + 2 || t2o_size == need_in)) {
            /* Be permissive for scanners that negotiate different sizes:
             * clamp to our assembly sizes. */
            if (o2t_size > EIP_ASSEMBLY_SIZE_MAX ||
                t2o_size > EIP_ASSEMBLY_SIZE_MAX) {
                *resp_len =
                    cm_err(resp, resp_cap, service, CIP_STATUS_INVALID_PARAM, 0x109);
                return 0;
            }
        }
    }

    eip_class1_conn_t *c = alloc_conn(s);
    if (!c) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
        return 0;
    }

    if (o2t_id == 0) {
        o2t_id = s->next_conn_id++;
    }
    if (t2o_id == 0) {
        t2o_id = s->next_conn_id++;
    }
    c->o2t_conn_id = o2t_id;
    c->t2o_conn_id = t2o_id;
    c->o2t_size = o2t_size;
    c->t2o_size = t2o_size;
    c->o2t_rpi_us = o2t_rpi;
    c->t2o_rpi_us = t2o_rpi;
    c->conn_serial = conn_serial;
    c->vendor_id = orig_vendor;
    c->originator_serial = orig_serial;
    c->timeout_multiplier = timeout_mult;
    {
        uint32_t rpi = o2t_rpi ? o2t_rpi : s->cfg.rpi_us;
        if (rpi == 0) {
            rpi = 8000;
        }
        c->watchdog_us =
            rpi * 4u *
            (uint32_t)((timeout_mult ? timeout_mult
                                     : EIP_CLASS1_TIMEOUT_MULT_DEFAULT) +
                       1u);
    }
    c->last_rx_ns = 0; /* arm after first IO */
    c->last_tx_ns = 0;
    (void)path_bytes;

    /* Success reply */
    size_t need = large ? 30 : 26;
    if (resp_cap < need) {
        c->in_use = 0;
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
        return 0;
    }
    size_t r = 0;
    resp[r++] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[r++] = 0;
    resp[r++] = CIP_STATUS_SUCCESS;
    resp[r++] = 0;
    eip_wr_le32(resp + r, o2t_id);
    r += 4;
    eip_wr_le32(resp + r, t2o_id);
    r += 4;
    eip_wr_le16(resp + r, conn_serial);
    r += 2;
    eip_wr_le16(resp + r, orig_vendor);
    r += 2;
    eip_wr_le32(resp + r, orig_serial);
    r += 4;
    eip_wr_le32(resp + r, o2t_rpi);
    r += 4;
    eip_wr_le32(resp + r, t2o_rpi);
    r += 4;
    resp[r++] = 0; /* application reply size */
    resp[r++] = 0; /* reserved */
    *resp_len = r;
    return 0;
}

int eip_cm_forward_close(eip_stack_t *s, const uint8_t *data, size_t len,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    uint8_t service = CIP_SVC_FORWARD_CLOSE;
    if (len < 10) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_INVALID_PARAM, 0);
        return 0;
    }
    /* priority/tick + timeout, then serial/vendor/serial */
    uint16_t conn_serial = eip_rd_le16(data + 2);
    uint16_t vendor = eip_rd_le16(data + 4);
    uint32_t orig_serial = eip_rd_le32(data + 6);

    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (!c->in_use) {
            continue;
        }
        if (c->conn_serial == conn_serial && c->vendor_id == vendor &&
            c->originator_serial == orig_serial) {
            c->in_use = 0;
            break;
        }
    }

    if (resp_cap < 14) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_STATUS_RESOURCE, 0);
        return 0;
    }
    size_t r = 0;
    resp[r++] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[r++] = 0;
    resp[r++] = CIP_STATUS_SUCCESS;
    resp[r++] = 0;
    eip_wr_le16(resp + r, conn_serial);
    r += 2;
    eip_wr_le16(resp + r, vendor);
    r += 2;
    eip_wr_le32(resp + r, orig_serial);
    r += 4;
    resp[r++] = 0; /* app reply size */
    resp[r++] = 0;
    *resp_len = r;
    return 0;
}
