#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include "logger.h"
#include <string.h>

/* Unsuccessful Connection Manager reply.
 * General Status is always 0x01, then `add_words` of additional status,
 * then Connection Serial, Originator Vendor, Originator Serial, and a
 * trailing USINT + reserved (10 bytes). Forward Open uses that USINT as
 * Remaining Path Size; Forward Close uses it as Application Reply Size.
 * A target that is not a router sets the size byte to 0.
 */
static size_t cm_fail(uint8_t *resp, size_t cap, uint8_t service,
                      const uint8_t *add, uint8_t add_words,
                      uint16_t conn_serial, uint16_t vendor,
                      uint32_t orig_serial, uint8_t size_byte)
{
    size_t add_bytes = (size_t)add_words * 2u;
    size_t need = 4u + add_bytes + 10u;
    if (!resp || cap < need || (add_bytes > 0 && !add)) {
        return 0;
    }
    resp[0] = (uint8_t)(service | CIP_SVC_REPLY);
    resp[1] = 0;
    resp[2] = CIP_STATUS_CONN_FAILURE;
    resp[3] = add_words;
    if (add_bytes > 0) {
        memcpy(resp + 4, add, add_bytes);
    }
    size_t tail = 4u + add_bytes;
    eip_wr_le16(resp + tail, conn_serial);
    eip_wr_le16(resp + tail + 2, vendor);
    eip_wr_le32(resp + tail + 4, orig_serial);
    resp[tail + 8] = size_byte;
    resp[tail + 9] = 0;
    return need;
}

static size_t cm_err(uint8_t *resp, size_t cap, uint8_t service, uint16_t ext,
                     uint16_t conn_serial, uint16_t vendor, uint32_t orig_serial,
                     uint8_t size_byte)
{
    uint8_t add[2];
    eip_wr_le16(add, ext);
    return cm_fail(resp, cap, service, add, 1, conn_serial, vendor, orig_serial,
                   size_byte);
}

/* CIP Vol 1 extended status 0x0112: RPI type 2 = minimum acceptable RPI. */
#define EIP_RPI_TYPE_MINIMUM 2u

/* Additional status is 6 words: 0x0112, O->T type + T->O type, both RPIs.
 * Both directions report type 2 and the configured minimum. The tail is
 * the same triad + Remaining Path Size that cm_err writes.
 */
static size_t cm_err_rpi(uint8_t *resp, size_t cap, uint8_t service,
                         uint16_t conn_serial, uint16_t vendor,
                         uint32_t orig_serial, uint32_t min_us)
{
    uint8_t add[12];
    eip_wr_le16(add, CIP_EXT_RPI_NOT_ACCEPTABLE);
    add[2] = EIP_RPI_TYPE_MINIMUM;
    add[3] = EIP_RPI_TYPE_MINIMUM;
    eip_wr_le32(add + 4, min_us);
    eip_wr_le32(add + 8, min_us);
    return cm_fail(resp, cap, service, add, 6, conn_serial, vendor, orig_serial,
                   0);
}

/* 0 when `requested` can be produced at a multiple of `min_us`.
 * *api is `requested` rounded up to that multiple. -1 when `requested`
 * is shorter than the minimum, or the rounded value does not fit in a UDINT.
 */
static int rpi_actual_us(uint32_t requested, uint32_t min_us, uint32_t *api)
{
    if (min_us == 0 || requested < min_us) {
        return -1;
    }
    if ((requested % min_us) == 0u) {
        *api = requested;
        return 0;
    }
    uint64_t units = ((uint64_t)requested / (uint64_t)min_us) + 1ull;
    uint64_t v = units * (uint64_t)min_us;
    if (v > 0xffffffffull) {
        return -1;
    }
    *api = (uint32_t)v;
    return 0;
}

/* Triad starts after priority, timeout, and the two connection IDs (10 bytes). */
static void fo_triad_or_zero(const uint8_t *data, size_t len, uint16_t *serial,
                             uint16_t *vendor, uint32_t *orig_serial)
{
    *serial = 0;
    *vendor = 0;
    *orig_serial = 0;
    if (data && len >= 18) {
        *serial = eip_rd_le16(data + 10);
        *vendor = eip_rd_le16(data + 12);
        *orig_serial = eip_rd_le32(data + 14);
    }
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

/* 0 Null, 1 Multicast, 2 Point-to-point, 3 Reserved.
 * Forward Open stores the type in 16-bit NCP bits 13-14.
 * Large Forward Open stores it in 32-bit NCP bits 29-30.
 */
static unsigned ncp_conn_type(uint32_t net_params, int large)
{
    if (large) {
        return (unsigned)((net_params >> 29) & 3u);
    }
    return (unsigned)((net_params >> 13) & 3u);
}

/* Class 1 size is assembly data plus a 2-byte sequence, and O->T may add
 * the 4-byte Run/Idle header (data+6). T->O stays modeless (data or data+2).
 */
static int o2t_size_ok(uint16_t net, uint16_t asm_sz, int *run_idle)
{
    *run_idle = 0;
    if (net == asm_sz || net == (uint16_t)(asm_sz + 2u)) {
        return 1;
    }
    if (net == (uint16_t)(asm_sz + 6u)) {
        *run_idle = 1;
        return 1;
    }
    return 0;
}

static int t2o_size_ok(uint16_t net, uint16_t asm_sz)
{
    return net == asm_sz || net == (uint16_t)(asm_sz + 2u);
}

static eip_class1_conn_t *find_dup_triad(eip_stack_t *s, uint16_t serial,
                                         uint16_t vendor, uint32_t orig_serial)
{
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (c->in_use && c->conn_serial == serial && c->vendor_id == vendor &&
            c->originator_serial == orig_serial) {
            return c;
        }
    }
    return NULL;
}

/* True when an Exclusive Owner of the output assembly is already open. */
static int exclusive_owner_active(const eip_stack_t *s)
{
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        const eip_class1_conn_t *c = &s->class1[i];
        if (c->in_use && c->exclusive_owner) {
            return 1;
        }
    }
    return 0;
}

/* Exclusive-owner path: Assembly class + config inst + O->T + T->O points. */
static int parse_fo_path(const uint8_t *path, size_t path_bytes,
                         uint16_t *insts, int *n_insts, int insts_cap)
{
    size_t i = 0;
    *n_insts = 0;
    while (i < path_bytes) {
        uint8_t seg = path[i++];
        uint16_t val = 0;
        int is_inst = 0;
        if (seg == 0x20 && i < path_bytes) {
            i += 1; /* class 8-bit */
        } else if (seg == 0x21 && i + 2 < path_bytes) {
            i += 3; /* pad + class 16 */
        } else if ((seg == 0x24 || seg == 0x2C) && i < path_bytes) {
            val = path[i++];
            is_inst = 1;
        } else if ((seg == 0x25 || seg == 0x2D) && i + 2 < path_bytes) {
            i += 1; /* pad */
            val = eip_rd_le16(path + i);
            i += 2;
            is_inst = 1;
        } else if (seg == 0x34 && i < path_bytes) {
            /* Electronic key: key format in low nibble of next, then 8 bytes. */
            uint8_t key_fmt = path[i++];
            size_t key_len = (key_fmt == 4) ? 8u : 8u;
            if (i + key_len > path_bytes) {
                return -EINVAL;
            }
            i += key_len;
        } else if (seg == 0x01 && i < path_bytes) {
            /* Port segment — skip remaining of this word. */
            i += 1;
        } else {
            return -EINVAL;
        }
        if (is_inst) {
            if (*n_insts >= insts_cap) {
                return -EINVAL;
            }
            insts[(*n_insts)++] = val;
        }
    }
    return 0;
}

/* 1 when the path names both configured assemblies.
 * Otherwise *ext is 0x0315 (segment not understood) or 0x0117
 * (produced/consumed application path does not match).
 */
static int fo_path_ok(eip_stack_t *s, const uint8_t *path, size_t path_bytes,
                      uint16_t *ext)
{
    uint16_t insts[8];
    int n = 0;
    if (path_bytes == 0) {
        *ext = CIP_EXT_INVALID_APP_PATH;
        return 0;
    }
    if (parse_fo_path(path, path_bytes, insts, &n, 8) != 0) {
        *ext = CIP_EXT_INVALID_SEGMENT;
        return 0;
    }
    int saw_out = 0;
    int saw_in = 0;
    for (int i = 0; i < n; i++) {
        if (insts[i] == s->cfg.output_assembly) {
            saw_out = 1;
        }
        if (insts[i] == s->cfg.input_assembly) {
            saw_in = 1;
        }
    }
    if (!saw_out || !saw_in) {
        *ext = CIP_EXT_INVALID_APP_PATH;
        return 0;
    }
    return 1;
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
        uint16_t cs = 0;
        uint16_t vend = 0;
        uint32_t os = 0;
        fo_triad_or_zero(data, len, &cs, &vend, &os);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_PARAM_ERROR, cs,
                           vend, os, 0);
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
    /* Transport type/trigger (ethernetip.md 5.6.5): bits 0-3 class,
     * bits 4-6 trigger, bit 7 direction. Read before the path.
     */
    uint8_t transport = data[off];
    off += 1;
    if (off >= len) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_PARAM_ERROR,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }
    uint8_t path_words = data[off++];
    size_t path_bytes = (size_t)path_words * 2u;
    if (off + path_bytes > len) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_PARAM_ERROR,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    /* Only Class 1 cyclic I/O is produced. Class 3 (and COS / Class 0)
     * would otherwise be installed in a Class 1 slot, while SendUnitData
     * (0x70) is not implemented. Direction is not this combination.
     * Unsupported class/trigger → 0x01 / 0x0103 (ethernetip.md M5, 6.3).
     */
    if ((transport & 0x0Fu) != 1u || ((transport >> 4) & 0x07u) != 0u) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: transport class/trigger 0x%02x "
                 "serial=0x%04x vendor=0x%04x orig=0x%08x",
                 transport, conn_serial, orig_vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_TRANSPORT_TRIGGER,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    uint16_t path_ext = 0;
    if (!fo_path_ok(s, data + off, path_bytes, &path_ext)) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: connection path ext=0x%04x in=%u "
                 "out=%u",
                 path_ext, s->cfg.input_assembly, s->cfg.output_assembly);
        *resp_len = cm_err(resp, resp_cap, service, path_ext, conn_serial,
                           orig_vendor, orig_serial, 0);
        return 0;
    }

    /* Minimum packet interval is cfg.rpi_us (the device cycle). A shorter
     * request in either direction is 0x01/0x0112 with the minimum in the
     * additional status. A longer request that is not a multiple of the
     * cycle is accepted at the next multiple; that value is the API.
     */
    uint32_t min_us = s->cfg.rpi_us ? s->cfg.rpi_us : 8000u;
    uint32_t o2t_api = 0;
    uint32_t t2o_api = 0;
    if (rpi_actual_us(o2t_rpi, min_us, &o2t_api) != 0 ||
        rpi_actual_us(t2o_rpi, min_us, &t2o_api) != 0) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: RPI O->T=%u T->O=%u not acceptable "
                 "(minimum %u) serial=0x%04x vendor=0x%04x orig=0x%08x",
                 o2t_rpi, t2o_rpi, min_us, conn_serial, orig_vendor,
                 orig_serial);
        *resp_len = cm_err_rpi(resp, resp_cap, service, conn_serial,
                               orig_vendor, orig_serial, min_us);
        return 0;
    }

    /* Multicast (1) and Reserved (3) are not produced. Null (0) stays
     * accepted: CTT and the unit tests put only a size in the NCP.
     * Point-to-point (2) is accepted. O->T is checked first because that
     * field comes before T->O. A path that does not name both assemblies
     * is already 0x0117 above.
     */
    unsigned o2t_type = ncp_conn_type(o2t_params, large);
    unsigned t2o_type = ncp_conn_type(t2o_params, large);
    if (o2t_type == 1u || o2t_type == 3u) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: O->T connection type %u "
                 "serial=0x%04x vendor=0x%04x orig=0x%08x",
                 o2t_type, conn_serial, orig_vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_INVALID_O2T_TYPE,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }
    if (t2o_type == 1u || t2o_type == 3u) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: T->O connection type %u "
                 "serial=0x%04x vendor=0x%04x orig=0x%08x",
                 t2o_type, conn_serial, orig_vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_INVALID_T2O_TYPE,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    uint16_t o2t_size = conn_size_from_net(o2t_params, large);
    uint16_t t2o_size = conn_size_from_net(t2o_params, large);
    int o2t_run_idle = 0;
    if (!o2t_size_ok(o2t_size, s->output_size, &o2t_run_idle) ||
        !t2o_size_ok(t2o_size, s->input_size)) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: size o2t=%u (need %u, %u+2, or "
                 "%u+6 run/idle) t2o=%u (need %u[+2])",
                 o2t_size, s->output_size, s->output_size, s->output_size,
                 t2o_size, s->input_size);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_CONN_SIZE,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    if (find_dup_triad(s, conn_serial, orig_vendor, orig_serial)) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: duplicate triad serial=0x%04x "
                 "vendor=0x%04x orig=0x%08x",
                 conn_serial, orig_vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_CONN_IN_USE,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    /* fo_path_ok requires the configured output assembly, so every
     * connection accepted here is an Exclusive Owner of that assembly.
     * A second owner (different triad) must not be installed: both would
     * write the same output image. CIP: 0x01 / 0x0106 ownership conflict.
     * Input Only and Listen Only do not own the output; they are not
     * accepted by fo_path_ok.
     */
    if (exclusive_owner_active(s)) {
        LOG_WARN("ethernetip",
                 "Forward Open rejected: ownership conflict serial=0x%04x "
                 "vendor=0x%04x orig=0x%08x",
                 conn_serial, orig_vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_OWNERSHIP_CONFLICT,
                           conn_serial, orig_vendor, orig_serial, 0);
        return 0;
    }

    eip_class1_conn_t *c = alloc_conn(s);
    if (!c) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_OUT_OF_CONNECTIONS,
                           conn_serial, orig_vendor, orig_serial, 0);
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
    c->o2t_run_idle = o2t_run_idle ? 1u : 0u;
    c->o2t_rpi_us = o2t_api;
    c->t2o_rpi_us = t2o_api;
    c->conn_serial = conn_serial;
    c->vendor_id = orig_vendor;
    c->originator_serial = orig_serial;
    c->timeout_multiplier = timeout_mult;
    c->exclusive_owner = 1;
    c->watchdog_us = eip_class1_watchdog_us(o2t_api, timeout_mult);
    /* Arm watchdog at Forward Open so a connection without IO is reclaimed. */
    c->last_rx_ns = eip_now_ns();
    c->last_tx_ns = 0;

    /* Success reply */
    size_t need = large ? 30 : 26;
    if (resp_cap < need) {
        c->in_use = 0;
        c->exclusive_owner = 0;
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_NO_BUFFER,
                           conn_serial, orig_vendor, orig_serial, 0);
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
    eip_wr_le32(resp + r, o2t_api);
    r += 4;
    eip_wr_le32(resp + r, t2o_api);
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
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_PARAM_ERROR, 0, 0,
                           0, 0);
        return 0;
    }
    /* priority/tick + timeout, then serial/vendor/serial */
    uint16_t conn_serial = eip_rd_le16(data + 2);
    uint16_t vendor = eip_rd_le16(data + 4);
    uint32_t orig_serial = eip_rd_le32(data + 6);

    int found = 0;
    for (int i = 0; i < EIP_CLASS1_CONN_MAX; i++) {
        eip_class1_conn_t *c = &s->class1[i];
        if (!c->in_use) {
            continue;
        }
        if (c->conn_serial == conn_serial && c->vendor_id == vendor &&
            c->originator_serial == orig_serial) {
            c->in_use = 0;
            found = 1;
            break;
        }
    }
    if (!found) {
        LOG_WARN("ethernetip",
                 "Forward Close rejected: connection not found serial=0x%04x "
                 "vendor=0x%04x orig=0x%08x",
                 conn_serial, vendor, orig_serial);
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_CONN_NOT_FOUND,
                           conn_serial, vendor, orig_serial, 0);
        return 0;
    }

    if (resp_cap < 14) {
        *resp_len = cm_err(resp, resp_cap, service, CIP_EXT_NO_BUFFER,
                           conn_serial, vendor, orig_serial, 0);
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
