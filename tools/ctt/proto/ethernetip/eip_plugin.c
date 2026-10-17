#include "ctt.h"
#include "cycle_clock.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "eip_crypto.h"
#include "eip_endian.h"
#include "eip_sec.h"
#include "eip_stack.h"
#include "logger.h"

typedef struct {
    eip_stack_t *stack;
    uint32_t session;
    uint32_t o2t_conn_id;
    uint32_t t2o_conn_id;
    uint16_t conn_serial;
    uint16_t orig_vendor;
    uint32_t orig_serial;
    uint8_t psk[EIP_PSK_LEN];
    int psk_set;
    uint8_t last_resp[2048];
    size_t last_resp_len;
} eip_priv_t;

static void sleep_us(unsigned us)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(us / 1000000u);
    ts.tv_nsec = (long)(us % 1000000u) * 1000L;
    nanosleep(&ts, NULL);
}

static int parse_hex_bytes(const char *s, uint8_t *out, size_t out_len)
{
    if (!s || strlen(s) != out_len * 2u) {
        return -1;
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned v = 0;
        if (sscanf(s + i * 2, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int parse_hex_buf(const char *s, uint8_t *out, size_t cap, size_t *n)
{
    if (!s || !out || !n) {
        return -1;
    }
    size_t sl = strlen(s);
    if (sl == 0 || (sl % 2u) != 0) {
        return -1;
    }
    size_t bytes = sl / 2u;
    if (bytes > cap) {
        return -1;
    }
    for (size_t i = 0; i < bytes; i++) {
        unsigned v = 0;
        if (sscanf(s + i * 2, "%2x", &v) != 1) {
            return -1;
        }
        out[i] = (uint8_t)v;
    }
    *n = bytes;
    return 0;
}

static int parse_integrity(const yaml_node_t *step, int *integrity,
                           int *integrity_bad)
{
    const char *s = yaml_cstr(step, "integrity", "false");
    *integrity = 0;
    *integrity_bad = 0;
    if (!s) {
        return 0;
    }
    if (strcmp(s, "true") == 0 || strcmp(s, "True") == 0 ||
        strcmp(s, "yes") == 0 || strcmp(s, "1") == 0) {
        *integrity = 1;
        return 0;
    }
    if (strcmp(s, "bad") == 0 || strcmp(s, "invalid") == 0) {
        *integrity = 1;
        *integrity_bad = 1;
        return 0;
    }
    return 0;
}

static int contains(const uint8_t *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m == 0 || m > n) {
        return 0;
    }
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, needle, m) == 0) {
            return 1;
        }
    }
    return 0;
}

static int find_le16(const uint8_t *buf, size_t n, uint16_t want)
{
    for (size_t i = 0; i + 2 <= n; i++) {
        if (eip_rd_le16(buf + i) == want) {
            return 1;
        }
    }
    return 0;
}

static int eip_tcp_send(void *ctx, const uint8_t *data, size_t len)
{
    ctt_run_t *run = ctx;
    return ctt_ring_push(&run->mock.to_ctl, data, len, ctt_now_ns());
}

static int eip_udp_send(void *ctx, const uint8_t *data, size_t len,
                        uint32_t dst_ip_be, uint16_t dst_port)
{
    ctt_run_t *run = ctx;
    (void)dst_ip_be;
    (void)dst_port;
    return ctt_ring_push(&run->mock.to_ctl, data, len, ctt_now_ns());
}

static void pump(eip_priv_t *priv)
{
    eip_stack_poll(priv->stack);
}

static size_t append_cpf_item(uint8_t *p, uint16_t type, const uint8_t *data,
                              uint16_t dlen)
{
    eip_wr_le16(p, type);
    eip_wr_le16(p + 2, dlen);
    if (dlen && data) {
        memcpy(p + 4, data, dlen);
    }
    return 4u + dlen;
}

static int inject_encap(ctt_run_t *run, eip_priv_t *priv, const uint8_t *req,
                        size_t req_len);

static int ensure_session(ctt_run_t *run, eip_priv_t *priv)
{
    if (priv->session != 0) {
        return 0;
    }
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    int rc = inject_encap(run, priv, req, sizeof(req));
    if (rc != 0 || priv->last_resp_len < 8) {
        return rc != 0 ? rc : -EINVAL;
    }
    priv->session = eip_rd_le32(priv->last_resp + 4);
    if (priv->session == 0) {
        return -EINVAL;
    }
    return 0;
}

static int inject_encap(ctt_run_t *run, eip_priv_t *priv, const uint8_t *req,
                        size_t req_len)
{
    size_t n = 0;
    int rc = eip_stack_handle_encap(priv->stack, req, req_len, priv->last_resp,
                                    sizeof(priv->last_resp), &n);
    priv->last_resp_len = (rc == 0) ? n : 0;
    if (rc == 0 && n > 0) {
        (void)ctt_ring_push(&run->mock.to_ctl, priv->last_resp, n,
                            ctt_now_ns());
    }
    pump(priv);
    return rc;
}

static int parse_unconnected_cip(const uint8_t *resp, size_t resp_len,
                                 const uint8_t **cip, size_t *cip_len)
{
    if (!resp || resp_len < EIP_ENCAP_HDR_SIZE + 8) {
        return -1;
    }
    const uint8_t *b = resp + EIP_ENCAP_HDR_SIZE;
    size_t bl = resp_len - EIP_ENCAP_HDR_SIZE;
    if (bl < 8) {
        return -1;
    }
    size_t off = 6;
    uint16_t items = eip_rd_le16(b + off);
    off += 2;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > bl) {
            return -1;
        }
        uint16_t type = eip_rd_le16(b + off);
        uint16_t length = eip_rd_le16(b + off + 2);
        off += 4;
        if (off + length > bl) {
            return -1;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA) {
            *cip = b + off;
            *cip_len = length;
            return 0;
        }
        off += length;
    }
    return -1;
}

static uint8_t cip_status(const uint8_t *cip, size_t cip_len)
{
    if (!cip || cip_len < 3) {
        return 0xFF;
    }
    return cip[2];
}

static const uint8_t *cip_data(const uint8_t *cip, size_t cip_len, size_t *n)
{
    if (!cip || cip_len < 4) {
        *n = 0;
        return NULL;
    }
    uint8_t extra = cip[3];
    size_t skip = 4u + (size_t)extra * 2u;
    if (skip > cip_len) {
        *n = 0;
        return NULL;
    }
    *n = cip_len - skip;
    return cip + skip;
}

static int sendrr_cip(ctt_run_t *run, eip_priv_t *priv, const uint8_t *cip,
                      size_t cip_len, int integrity, int integrity_bad)
{
    if (ensure_session(run, priv) != 0) {
        return -EINVAL;
    }
    uint8_t mac[EIP_HMAC_LEN];
    int mac_set = 0;
    if (integrity) {
        if (!priv->psk_set) {
            LOG_ERROR("ctt_eip", "integrity Forward Open requires device.psk_hex");
            return -EINVAL;
        }
        uint8_t material[4 + 256];
        eip_wr_le32(material, priv->session);
        memcpy(material + 4, cip, cip_len);
        eip_hmac_sha256(priv->psk, EIP_PSK_LEN, material, 4 + cip_len, mac);
        if (integrity_bad) {
            mac[0] ^= 0xFF;
        }
        mac_set = 1;
    }

    uint8_t body[512];
    size_t boff = 0;
    eip_wr_le32(body + boff, 0);
    boff += 4;
    eip_wr_le16(body + boff, 0);
    boff += 2;
    eip_wr_le16(body + boff, (uint16_t)(mac_set ? 3 : 2));
    boff += 2;
    boff += append_cpf_item(body + boff, EIP_ITEM_NULL_ADDR, NULL, 0);
    boff += append_cpf_item(body + boff, EIP_ITEM_UNCONNECTED_DATA, cip,
                            (uint16_t)cip_len);
    if (mac_set) {
        boff += append_cpf_item(body + boff, EIP_SEC_ITEM_INTEGRITY, mac,
                                EIP_HMAC_LEN);
    }

    uint8_t req[EIP_ENCAP_HDR_SIZE + 512];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)boff);
    eip_wr_le32(req + 4, priv->session);
    memcpy(req + EIP_ENCAP_HDR_SIZE, body, boff);
    return inject_encap(run, priv, req, EIP_ENCAP_HDR_SIZE + boff);
}

static size_t build_get_attr_path(uint8_t *path, uint16_t class_id,
                                  uint16_t instance, uint16_t attribute)
{
    size_t pu = 0;
    if (class_id > 0xff) {
        path[pu++] = 0x21;
        path[pu++] = 0x00;
        eip_wr_le16(path + pu, class_id);
        pu += 2;
    } else {
        path[pu++] = 0x20;
        path[pu++] = (uint8_t)class_id;
    }
    if (instance > 0xff) {
        path[pu++] = 0x25;
        path[pu++] = 0x00;
        eip_wr_le16(path + pu, instance);
        pu += 2;
    } else {
        path[pu++] = 0x24;
        path[pu++] = (uint8_t)instance;
    }
    if (attribute > 0xff) {
        path[pu++] = 0x31;
        path[pu++] = 0x00;
        eip_wr_le16(path + pu, attribute);
        pu += 2;
    } else {
        path[pu++] = 0x30;
        path[pu++] = (uint8_t)attribute;
    }
    return pu;
}

static int check_encap_expect(ctt_run_t *run, eip_priv_t *priv, int idx,
                              const char *action, const yaml_node_t *expect,
                              int encap_rc)
{
    int out = 0;
    if (expect && yaml_has(expect, "encap_ok")) {
        int want = yaml_bool(expect, "encap_ok", 1);
        out |= ctt_check(run, idx, action, (encap_rc == 0) == want,
                         "encap_ok expect=%s actual rc=%d",
                         want ? "true" : "false", encap_rc);
    } else {
        out |= ctt_check(run, idx, action, encap_rc == 0,
                         "handle_encap failed rc=%d", encap_rc);
    }
    if (encap_rc != 0) {
        if (expect && yaml_has(expect, "class1")) {
            const char *c1 = yaml_cstr(expect, "class1", "");
            int up = eip_stack_class1_up(priv->stack);
            if (strcmp(c1, "up") == 0) {
                out |= ctt_check(run, idx, action, up,
                                 "class1 expect=up actual=down");
            } else if (strcmp(c1, "down") == 0 ||
                       strcmp(c1, "rejected") == 0) {
                out |= ctt_check(run, idx, action, !up,
                                 "class1 expect=down actual=up");
            }
        }
        return out;
    }

    if (expect && yaml_has(expect, "cmd")) {
        unsigned long want = yaml_ulong(expect, "cmd", 0);
        uint16_t got = (priv->last_resp_len >= 2)
                           ? eip_rd_le16(priv->last_resp)
                           : 0;
        out |= ctt_check(run, idx, action, got == (uint16_t)want,
                         "cmd expect=0x%04lx actual=0x%04x", want, got);
    }
    if (expect && yaml_has(expect, "encap_status")) {
        unsigned long want = yaml_ulong(expect, "encap_status", 0);
        uint32_t got = (priv->last_resp_len >= 12)
                           ? eip_rd_le32(priv->last_resp + 8)
                           : 0xFFFFFFFFu;
        out |= ctt_check(run, idx, action, got == (uint32_t)want,
                         "encap_status expect=%lu actual=%u", want, got);
    }
    if (expect && yaml_has(expect, "session_handle")) {
        const char *s = yaml_cstr(expect, "session_handle", "");
        uint32_t h = (priv->last_resp_len >= 8)
                         ? eip_rd_le32(priv->last_resp + 4)
                         : 0;
        if (strcmp(s, "nonzero") == 0) {
            out |= ctt_check(run, idx, action, h != 0,
                             "session_handle expect=nonzero actual=%u", h);
        } else if (s[0]) {
            unsigned long want = yaml_ulong(expect, "session_handle", 0);
            out |= ctt_check(run, idx, action, h == (uint32_t)want,
                             "session_handle expect=%lu actual=%u", want, h);
        }
        if (h) {
            priv->session = h;
        }
    }

    const uint8_t *cip = NULL;
    size_t cip_len = 0;
    int have_cip =
        parse_unconnected_cip(priv->last_resp, priv->last_resp_len, &cip,
                              &cip_len) == 0;

    if (expect && yaml_has(expect, "cip_status")) {
        unsigned long want = yaml_ulong(expect, "cip_status", 0);
        uint8_t st = have_cip ? cip_status(cip, cip_len) : 0xFF;
        out |= ctt_check(run, idx, action, have_cip && st == (uint8_t)want,
                         "cip_status expect=0x%02lx actual=0x%02x have_cip=%d",
                         want, st, have_cip);
    }
    /* Optional extended-status word. A missing key keeps the previous check. */
    if (expect && yaml_has(expect, "ext_status")) {
        unsigned long want = yaml_ulong(expect, "ext_status", 0);
        uint16_t got = 0;
        int ok = 0;
        if (have_cip && cip_len >= 6 && cip[3] >= 1) {
            got = eip_rd_le16(cip + 4);
            ok = got == (uint16_t)want;
        }
        out |= ctt_check(run, idx, action, ok,
                         "ext_status expect=0x%04lx actual=0x%04x have_cip=%d",
                         want, got, have_cip);
    }
    if (expect && yaml_has(expect, "privilege")) {
        int want = yaml_bool(expect, "privilege", 1);
        int saw = 0;
        for (size_t i = EIP_ENCAP_HDR_SIZE; i + 3 < priv->last_resp_len; i++) {
            uint8_t svc = priv->last_resp[i] & 0x7f;
            if ((svc == CIP_SVC_FORWARD_OPEN ||
                 svc == CIP_SVC_LARGE_FORWARD_OPEN) &&
                (priv->last_resp[i] & 0x80) &&
                priv->last_resp[i + 2] == CIP_STATUS_PRIVILEGE) {
                saw = 1;
                break;
            }
        }
        out |= ctt_check(run, idx, action, saw == want,
                         "privilege-denied FO reply expect=%s actual=%s",
                         want ? "true" : "false", saw ? "true" : "false");
    }

    size_t dlen = 0;
    const uint8_t *data =
        have_cip ? cip_data(cip, cip_len, &dlen) : NULL;

    if (expect && yaml_has(expect, "vendor_id")) {
        unsigned long want = yaml_ulong(expect, "vendor_id", 0);
        int found = find_le16(priv->last_resp, priv->last_resp_len,
                              (uint16_t)want);
        if (!found && data && dlen >= 2) {
            found = eip_rd_le16(data) == (uint16_t)want;
        }
        out |= ctt_check(run, idx, action, found,
                         "vendor_id 0x%04lx not in reply (len=%zu)", want,
                         priv->last_resp_len);
    }
    if (expect && yaml_has(expect, "u8")) {
        unsigned long want = yaml_ulong(expect, "u8", 0);
        int ok = data && dlen >= 1 && data[0] == (uint8_t)want;
        out |= ctt_check(run, idx, action, ok,
                         "u8 expect=0x%02lx actual=%s0x%02x dlen=%zu", want,
                         data && dlen ? "" : "(none) ",
                         data && dlen ? data[0] : 0, dlen);
    }
    if (expect && yaml_has(expect, "u16")) {
        unsigned long want = yaml_ulong(expect, "u16", 0);
        int ok = data && dlen >= 2 && eip_rd_le16(data) == (uint16_t)want;
        out |= ctt_check(run, idx, action, ok,
                         "u16 expect=0x%04lx actual=0x%04x", want,
                         data && dlen >= 2 ? eip_rd_le16(data) : 0);
    }
    if (expect && yaml_has(expect, "u32")) {
        unsigned long want = yaml_ulong(expect, "u32", 0);
        int ok = data && dlen >= 4 && eip_rd_le32(data) == (uint32_t)want;
        out |= ctt_check(run, idx, action, ok,
                         "u32 expect=0x%08lx actual=0x%08x", want,
                         data && dlen >= 4 ? eip_rd_le32(data) : 0);
    }
    if (expect && yaml_has(expect, "product_name")) {
        const char *name = yaml_cstr(expect, "product_name", "");
        out |= ctt_check(run, idx, action,
                         contains(priv->last_resp, priv->last_resp_len, name),
                         "product_name '%s' not in reply", name);
    }
    if (expect && yaml_has(expect, "contains")) {
        const char *needle = yaml_cstr(expect, "contains", "");
        out |= ctt_check(run, idx, action,
                         contains(priv->last_resp, priv->last_resp_len, needle),
                         "contains '%s' not in reply", needle);
    }

    if (expect && yaml_has(expect, "class1")) {
        const char *c1 = yaml_cstr(expect, "class1", "");
        int up = eip_stack_class1_up(priv->stack);
        if (strcmp(c1, "up") == 0) {
            out |= ctt_check(run, idx, action, up,
                             "class1 expect=up actual=down");
        } else if (strcmp(c1, "down") == 0 || strcmp(c1, "rejected") == 0) {
            out |= ctt_check(run, idx, action, !up,
                             "class1 expect=down actual=up");
        }
    }
    return out;
}

static int step_register_session(ctt_run_t *run, eip_priv_t *priv,
                                 const yaml_node_t *step, int idx)
{
    const char *action = "register_session";
    uint8_t req[EIP_ENCAP_HDR_SIZE + 4];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req + 0, EIP_CMD_REGISTERSESSION);
    eip_wr_le16(req + 2, 4);
    eip_wr_le16(req + 24, 1);
    int rc = inject_encap(run, priv, req, sizeof(req));
    if (rc == 0 && priv->last_resp_len >= 8) {
        priv->session = eip_rd_le32(priv->last_resp + 4);
    }
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static int step_list_identity(ctt_run_t *run, eip_priv_t *priv,
                              const yaml_node_t *step, int idx)
{
    const char *action = "list_identity";
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTIDENTITY);
    int rc = inject_encap(run, priv, req, sizeof(req));
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static int step_list_services(ctt_run_t *run, eip_priv_t *priv,
                              const yaml_node_t *step, int idx)
{
    const char *action = "list_services";
    uint8_t req[EIP_ENCAP_HDR_SIZE];
    memset(req, 0, sizeof(req));
    eip_wr_le16(req, EIP_CMD_LISTSERVICES);
    int rc = inject_encap(run, priv, req, sizeof(req));
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static int step_get_attr(ctt_run_t *run, eip_priv_t *priv,
                         const yaml_node_t *step, int idx)
{
    const char *action = "get_attr";
    uint16_t class_id = (uint16_t)yaml_ulong(step, "class_id",
                                             yaml_ulong(step, "class", 1));
    uint16_t instance = (uint16_t)yaml_ulong(step, "instance", 1);
    uint16_t attribute = (uint16_t)yaml_ulong(step, "attribute", 1);

    uint8_t path[16];
    size_t pu = build_get_attr_path(path, class_id, instance, attribute);
    uint8_t cip[32];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = (uint8_t)((pu + 1) / 2);
    memcpy(cip + 2, path, pu);
    int rc = sendrr_cip(run, priv, cip, 2 + pu, 0, 0);
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static int step_write_input(ctt_run_t *run, eip_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "write_input";
    const char *ascii = yaml_cstr(step, "data", NULL);
    const char *hex = yaml_cstr(step, "data_hex", NULL);
    uint8_t buf[EIP_ASSEMBLY_SIZE_MAX];
    size_t n = 0;
    if (ascii && ascii[0]) {
        n = strlen(ascii);
        if (n > sizeof(buf)) {
            n = sizeof(buf);
        }
        memcpy(buf, ascii, n);
    } else if (hex && hex[0]) {
        n = strlen(hex) / 2;
        if (n > sizeof(buf) || parse_hex_bytes(hex, buf, n) != 0) {
            ctt_failf(run, idx, action, "bad data_hex");
            return -1;
        }
    } else {
        ctt_failf(run, idx, action, "missing data or data_hex");
        return -1;
    }
    int wr = eip_stack_write_input(priv->stack, 0, buf, n);
    return ctt_check(run, idx, action, wr > 0, "write_input rc=%d n=%zu", wr,
                     n);
}

static int step_read_output(ctt_run_t *run, eip_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "read_output";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    size_t n = (size_t)yaml_ulong(step, "length", 8);
    if (n > EIP_ASSEMBLY_SIZE_MAX) {
        n = EIP_ASSEMBLY_SIZE_MAX;
    }
    uint8_t buf[EIP_ASSEMBLY_SIZE_MAX];
    int rd = eip_stack_read_output(priv->stack, 0, buf, n);
    int out = ctt_check(run, idx, action, rd > 0, "read_output rc=%d", rd);
    if (expect && yaml_has(expect, "u8")) {
        unsigned long want = yaml_ulong(expect, "u8", 0);
        out |= ctt_check(run, idx, action, rd > 0 && buf[0] == (uint8_t)want,
                         "output[0] expect=0x%02lx actual=0x%02x", want,
                         rd > 0 ? buf[0] : 0);
    }
    if (expect && yaml_has(expect, "data")) {
        const char *s = yaml_cstr(expect, "data", "");
        out |= ctt_check(run, idx, action,
                         rd > 0 && (size_t)rd >= strlen(s) &&
                             memcmp(buf, s, strlen(s)) == 0,
                         "output data mismatch");
    }
    return out;
}

static int step_read_input(ctt_run_t *run, eip_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "read_input";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    size_t n = (size_t)yaml_ulong(step, "length", 32);
    if (n > EIP_ASSEMBLY_SIZE_MAX) {
        n = EIP_ASSEMBLY_SIZE_MAX;
    }
    uint8_t buf[EIP_ASSEMBLY_SIZE_MAX];
    int rd = eip_stack_read_input(priv->stack, 0, buf, n);
    int out = ctt_check(run, idx, action, rd > 0, "read_input rc=%d", rd);
    if (expect && yaml_has(expect, "data")) {
        const char *s = yaml_cstr(expect, "data", "");
        out |= ctt_check(run, idx, action,
                         rd > 0 && contains(buf, (size_t)rd, s),
                         "input data '%s' mismatch", s);
    }
    return out;
}

static size_t build_forward_open_body(uint8_t *fo, uint16_t serial,
                                      uint16_t orig_vendor, uint32_t orig_serial,
                                      uint32_t o2t_rpi,
                                      uint32_t t2o_rpi, uint16_t o2t_size,
                                      uint16_t t2o_size, uint8_t timeout_mult,
                                      int large, uint16_t cfg_asm,
                                      uint16_t out_asm, uint16_t in_asm)
{
    size_t off = 0;
    fo[off++] = 0x0A;
    fo[off++] = 0x05;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le32(fo + off, 0);
    off += 4;
    eip_wr_le16(fo + off, serial);
    off += 2;
    eip_wr_le16(fo + off, orig_vendor);
    off += 2;
    eip_wr_le32(fo + off, orig_serial);
    off += 4;
    fo[off++] = timeout_mult;
    fo[off++] = 0;
    fo[off++] = 0;
    fo[off++] = 0;
    eip_wr_le32(fo + off, o2t_rpi);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, o2t_size);
        off += 4;
    } else {
        eip_wr_le16(fo + off, o2t_size);
        off += 2;
    }
    eip_wr_le32(fo + off, t2o_rpi);
    off += 4;
    if (large) {
        eip_wr_le32(fo + off, t2o_size);
        off += 4;
    } else {
        eip_wr_le16(fo + off, t2o_size);
        off += 2;
    }
    fo[off++] = 0x01; /* transport class 1 */
    fo[off++] = 4;    /* path size words */
    fo[off++] = 0x20;
    fo[off++] = CIP_CLASS_ASSEMBLY;
    fo[off++] = 0x24;
    fo[off++] = (uint8_t)cfg_asm;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)out_asm;
    fo[off++] = 0x2C;
    fo[off++] = (uint8_t)in_asm;
    return off;
}

static int fo_reply_at(const uint8_t *resp, size_t n, size_t i)
{
    if (i + 12 >= n) {
        return 0;
    }
    uint8_t svc = resp[i];
    if (resp[i + 2] != 0) {
        return 0;
    }
    return svc == (uint8_t)(CIP_SVC_FORWARD_OPEN | CIP_SVC_REPLY) ||
           svc == (uint8_t)(CIP_SVC_LARGE_FORWARD_OPEN | CIP_SVC_REPLY);
}

static uint32_t parse_fo_o2t(const uint8_t *resp, size_t n)
{
    size_t start = n > EIP_ENCAP_HDR_SIZE ? EIP_ENCAP_HDR_SIZE : n;
    for (size_t i = start; i + 12 < n; i++) {
        if (fo_reply_at(resp, n, i)) {
            return eip_rd_le32(resp + i + 4);
        }
    }
    return 0;
}

static uint32_t parse_fo_t2o(const uint8_t *resp, size_t n)
{
    size_t start = n > EIP_ENCAP_HDR_SIZE ? EIP_ENCAP_HDR_SIZE : n;
    for (size_t i = start; i + 12 < n; i++) {
        if (fo_reply_at(resp, n, i)) {
            return eip_rd_le32(resp + i + 8);
        }
    }
    return 0;
}

static int step_forward_open(ctt_run_t *run, eip_priv_t *priv,
                             const yaml_node_t *step, int idx)
{
    const char *action = "forward_open";
    int integrity = 0;
    int integrity_bad = 0;
    parse_integrity(step, &integrity, &integrity_bad);
    uint16_t serial = (uint16_t)yaml_ulong(step, "serial", 0x1234);
    uint16_t orig_vendor = (uint16_t)yaml_ulong(step, "orig_vendor", 1);
    uint32_t orig_serial = (uint32_t)yaml_ulong(step, "orig_serial", 0x99);
    uint32_t rpi = (uint32_t)yaml_ulong(step, "rpi_us", 8000);
    uint16_t o2t_size =
        (uint16_t)yaml_ulong(step, "o2t_size",
                             eip_stack_cfg(priv->stack)->output_size);
    uint16_t t2o_size =
        (uint16_t)yaml_ulong(step, "t2o_size",
                             eip_stack_cfg(priv->stack)->input_size);
    uint8_t tmo = (uint8_t)yaml_ulong(step, "timeout_mult", 0);
    int large = yaml_bool(step, "large", 0);

    uint8_t fo[80];
    const eip_cfg_t *cfg = eip_stack_cfg(priv->stack);
    size_t off =
        build_forward_open_body(fo, serial, orig_vendor, orig_serial, rpi, rpi,
                                o2t_size, t2o_size, tmo, large,
                                cfg->config_assembly, cfg->output_assembly,
                                cfg->input_assembly);
    uint8_t cip[2 + 8 + 64];
    cip[0] = large ? CIP_SVC_LARGE_FORWARD_OPEN : CIP_SVC_FORWARD_OPEN;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fo, off);
    int rc = sendrr_cip(run, priv, cip, 6 + off, integrity, integrity_bad);
    if (rc == 0) {
        uint32_t o2t = parse_fo_o2t(priv->last_resp, priv->last_resp_len);
        uint32_t t2o = parse_fo_t2o(priv->last_resp, priv->last_resp_len);
        if (o2t) {
            priv->o2t_conn_id = o2t;
            priv->conn_serial = serial;
            priv->orig_vendor = orig_vendor;
            priv->orig_serial = orig_serial;
        }
        if (t2o) {
            priv->t2o_conn_id = t2o;
        }
    }
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static int step_forward_close(ctt_run_t *run, eip_priv_t *priv,
                              const yaml_node_t *step, int idx)
{
    const char *action = "forward_close";
    int integrity = 0;
    int integrity_bad = 0;
    parse_integrity(step, &integrity, &integrity_bad);
    uint16_t serial =
        (uint16_t)yaml_ulong(step, "serial", priv->conn_serial);
    uint16_t orig_vendor =
        (uint16_t)yaml_ulong(step, "orig_vendor",
                             priv->orig_vendor ? priv->orig_vendor : 1);
    uint32_t orig_serial =
        (uint32_t)yaml_ulong(step, "orig_serial", priv->orig_serial);

    uint8_t fc[16];
    memset(fc, 0, sizeof(fc));
    fc[0] = 0x0A;
    fc[1] = 0x05;
    eip_wr_le16(fc + 2, serial);
    eip_wr_le16(fc + 4, orig_vendor);
    eip_wr_le32(fc + 6, orig_serial);
    fc[10] = 0;
    fc[11] = 0;

    uint8_t cip[2 + 8 + 16];
    cip[0] = CIP_SVC_FORWARD_CLOSE;
    cip[1] = 2;
    cip[2] = 0x20;
    cip[3] = CIP_CLASS_CONN_MANAGER;
    cip[4] = 0x24;
    cip[5] = 1;
    memcpy(cip + 6, fc, 12);
    int rc = sendrr_cip(run, priv, cip, 6 + 12, integrity, integrity_bad);
    int out = check_encap_expect(run, priv, idx, action,
                                 yaml_map_get(step, "expect"), rc);
    if (rc == 0 && serial == priv->conn_serial &&
        orig_serial == priv->orig_serial) {
        priv->o2t_conn_id = 0;
        priv->t2o_conn_id = 0;
    }
    return out;
}

static int step_encap_inject(ctt_run_t *run, eip_priv_t *priv,
                             const yaml_node_t *step, int idx)
{
    const char *action = "encap_inject";
    uint8_t req[512];
    size_t req_len = 0;
    const char *hex = yaml_cstr(step, "pdu_hex", NULL);
    if (hex && hex[0]) {
        if (parse_hex_buf(hex, req, sizeof(req), &req_len) != 0) {
            ctt_failf(run, idx, action, "bad pdu_hex");
            return -1;
        }
    } else if (yaml_has(step, "cmd")) {
        uint16_t cmd = (uint16_t)yaml_ulong(step, "cmd", 0);
        memset(req, 0, EIP_ENCAP_HDR_SIZE);
        eip_wr_le16(req, cmd);
        eip_wr_le32(req + 4, priv->session);
        req_len = EIP_ENCAP_HDR_SIZE;
    } else {
        ctt_failf(run, idx, action, "need pdu_hex or cmd");
        return -1;
    }
    int rc = inject_encap(run, priv, req, req_len);
    return check_encap_expect(run, priv, idx, action,
                              yaml_map_get(step, "expect"), rc);
}

static size_t build_class1_io(uint8_t *io, uint32_t o2t, uint32_t seq,
                              const uint8_t *payload, uint16_t plen)
{
    size_t ioff = 0;
    eip_wr_le16(io + ioff, 2);
    ioff += 2;
    eip_wr_le16(io + ioff, EIP_ITEM_SEQ_ADDR);
    ioff += 2;
    eip_wr_le16(io + ioff, 8);
    ioff += 2;
    eip_wr_le32(io + ioff, o2t);
    ioff += 4;
    eip_wr_le32(io + ioff, seq);
    ioff += 4;
    eip_wr_le16(io + ioff, EIP_ITEM_CONNECTED_DATA);
    ioff += 2;
    eip_wr_le16(io + ioff, (uint16_t)(2 + plen));
    ioff += 2;
    eip_wr_le16(io + ioff, (uint16_t)(seq & 0xffff));
    ioff += 2;
    memcpy(io + ioff, payload, plen);
    ioff += plen;
    return ioff;
}

static int step_require_class1(const yaml_node_t *step)
{
    if (yaml_has(step, "require_class1")) {
        return yaml_bool(step, "require_class1", 1);
    }
    if (yaml_has(step, "require_ar")) {
        return yaml_bool(step, "require_ar", 1);
    }
    return 1;
}

static int check_cyclic_expect(ctt_run_t *run, const ctt_metrics_t *before,
                               const yaml_node_t *expect, int idx,
                               const char *action, unsigned got)
{
    if (!expect) {
        return 0;
    }
    int rc = 0;
    unsigned late = run->metrics.late_cycles - before->late_cycles;
    unsigned missed = run->metrics.missed_cycles - before->missed_cycles;
    unsigned samples = run->metrics.period_samples - before->period_samples;

    if (yaml_has(expect, "max_frames")) {
        unsigned maxf = (unsigned)yaml_ulong(expect, "max_frames", got);
        rc |= ctt_check(run, idx, action, got <= maxf,
                        "max_frames expect<=%u actual=%u", maxf, got);
    }
    if (yaml_has(expect, "max_late")) {
        unsigned want = (unsigned)yaml_ulong(expect, "max_late", 0);
        rc |= ctt_check(run, idx, action, late <= want,
                        "max_late expect<=%u actual=%u (dt > 1.5 * rpi/cycle_us)",
                        want, late);
    }
    if (yaml_has(expect, "max_missed")) {
        unsigned want = (unsigned)yaml_ulong(expect, "max_missed", 0);
        rc |= ctt_check(run, idx, action, missed <= want,
                        "max_missed expect<=%u actual=%u (dt > 2.5 * rpi/cycle_us)",
                        want, missed);
    }
    if (yaml_has(expect, "jitter_max_ms")) {
        long want = yaml_long(expect, "jitter_max_ms", 0);
        long actual = (long)(run->metrics.jitter_max_ns / 1000000ull);
        rc |= ctt_check(run, idx, action, actual <= want,
                        "jitter_max_ms expect<=%ld actual=%ld (max |dt - cycle|)",
                        want, actual);
    }
    if (yaml_has(expect, "min_period_samples")) {
        unsigned want = (unsigned)yaml_ulong(expect, "min_period_samples", 0);
        rc |= ctt_check(run, idx, action, samples >= want,
                        "min_period_samples expect>=%u actual=%u", want,
                        samples);
    }
    return rc;
}

static int step_class1_io(ctt_run_t *run, eip_priv_t *priv,
                          const yaml_node_t *step, int idx)
{
    const char *action = "class1_io";
    const eip_cfg_t *cfg = eip_stack_cfg(priv->stack);
    uint16_t plen = (uint16_t)yaml_ulong(step, "length", cfg->output_size);
    uint8_t fill = (uint8_t)yaml_ulong(step, "fill", 0x5A);
    uint32_t seq = (uint32_t)yaml_ulong(step, "seq", 1);
    int require_c1 = step_require_class1(step);
    uint8_t payload[EIP_ASSEMBLY_SIZE_MAX];
    memset(payload, fill, plen);
    uint32_t o2t = priv->o2t_conn_id;
    if (o2t == 0) {
        if (require_c1) {
            ctt_failf(run, idx, action, "no O->T conn id (forward_open first)");
            return -1;
        }
        o2t = 0xDEADBEEFu;
    }
    uint8_t io[16 + EIP_ASSEMBLY_SIZE_MAX];
    size_t ioff = build_class1_io(io, o2t, seq, payload, plen);
    int rc = eip_stack_handle_io(priv->stack, io, ioff);
    pump(priv);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int out = 0;
    if (expect && yaml_has(expect, "io_ok")) {
        int want = yaml_bool(expect, "io_ok", 1);
        out |= ctt_check(run, idx, action, (rc == 0) == want,
                         "io_ok expect=%s actual rc=%d",
                         want ? "true" : "false", rc);
    } else if (require_c1) {
        out |= ctt_check(run, idx, action, rc == 0, "handle_io rc=%d", rc);
    }
    if (expect && yaml_has(expect, "u8")) {
        uint8_t buf[EIP_ASSEMBLY_SIZE_MAX];
        int rd = eip_stack_read_output(priv->stack, 0, buf, plen);
        unsigned long want = yaml_ulong(expect, "u8", 0);
        out |= ctt_check(run, idx, action, rd > 0 && buf[0] == (uint8_t)want,
                         "consumed output[0] expect=0x%02lx actual=0x%02x",
                         want, rd > 0 ? buf[0] : 0);
    }
    if (expect && yaml_has(expect, "class1")) {
        const char *c1 = yaml_cstr(expect, "class1", "");
        int up = eip_stack_class1_up(priv->stack);
        out |= ctt_check(run, idx, action,
                         (strcmp(c1, "up") == 0) ? up : !up,
                         "class1 expect=%s actual=%s", c1,
                         up ? "up" : "down");
    }
    return out;
}

static int step_class1_cyclic(ctt_run_t *run, eip_priv_t *priv,
                              const yaml_node_t *step, int idx,
                              const char *action)
{
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    unsigned duration_s = 0;
    if (strcmp(action, "soak") == 0 || yaml_has(step, "duration_s")) {
        duration_s = ctt_step_duration_s(run, step);
    }
    unsigned count = (unsigned)yaml_ulong(step, "count", 0);
    if (!duration_s && !count) {
        count = 8;
    }
    unsigned cycle_ms;
    if (yaml_has(step, "cycle_ms")) {
        cycle_ms = (unsigned)yaml_ulong(step, "cycle_ms", 8);
    } else if (run->metrics.cycle_ns >= 1000000ull) {
        cycle_ms = (unsigned)(run->metrics.cycle_ns / 1000000ull);
    } else {
        cycle_ms = 8;
    }
    int require_c1 = step_require_class1(step);
    const eip_cfg_t *cfg = eip_stack_cfg(priv->stack);
    uint16_t plen = cfg->output_size;
    uint8_t payload[EIP_ASSEMBLY_SIZE_MAX];
    memset(payload, 0x5A, plen);

    uint32_t o2t = priv->o2t_conn_id;
    if (o2t == 0) {
        if (require_c1) {
            ctt_failf(run, idx, action, "no O->T conn id");
            return -1;
        }
        o2t = 0xDEADBEEFu;
    }

    unsigned min_frames;
    if (expect && yaml_has(expect, "min_frames")) {
        min_frames = (unsigned)yaml_ulong(expect, "min_frames", 0);
    } else if (!require_c1) {
        min_frames = 0;
    } else if (duration_s) {
        min_frames = 1;
    } else {
        min_frames = count;
    }
    long period_max_ms =
        expect ? yaml_long(expect, "period_max_ms", 20) : 20;
    int has_period_max = expect && yaml_has(expect, "period_max_ms");
    unsigned want_unexp =
        expect && yaml_has(expect, "unexpected_frames")
            ? (unsigned)yaml_ulong(expect, "unexpected_frames", 0)
            : 0;
    int has_unexp = expect && yaml_has(expect, "unexpected_frames");

    ctt_metrics_t before = run->metrics;
    unsigned unexp_before = run->metrics.unexpected_frames;
    ctt_ring_clear(&run->mock.to_ctl);
    unsigned produced = 0;
    uint64_t prev_ns = 0;
    uint64_t start = ctt_now_ns();
    uint64_t deadline =
        duration_s ? start + (uint64_t)duration_s * 1000000000ull : 0;
    uint8_t io[16 + EIP_ASSEMBLY_SIZE_MAX];
    uint8_t buf[CTT_FRAME_MAX];
    ctt_cycle_clock_t clk;
    ctt_cycle_clock_init(&clk, (uint64_t)cycle_ms * 1000000ull);
    uint32_t seq = 0;
    while (1) {
        if (duration_s) {
            if (ctt_now_ns() >= deadline) {
                break;
            }
        } else if (seq >= count) {
            break;
        }
        seq++;
        size_t ioff = build_class1_io(io, o2t, seq, payload, plen);
        int iorc = eip_stack_handle_io(priv->stack, io, ioff);
        if (iorc != 0 && require_c1) {
            run->metrics.unexpected_frames++;
        }
        pump(priv);
        int n;
        while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) >
               0) {
            if (n >= 6 && eip_rd_le16(buf + 2) == EIP_ITEM_SEQ_ADDR) {
                produced++;
                run->metrics.rtc1_frames++;
                uint64_t now = ctt_now_ns();
                if (prev_ns) {
                    ctt_metrics_note_period(&run->metrics, now - prev_ns);
                }
                prev_ns = now;
            }
        }
        if (cycle_ms) {
            ctt_cycle_clock_wait(&clk);
        }
    }
    int out = 0;
    out |= ctt_check(run, idx, action, produced >= min_frames,
                     "produced Class1 frames %u < min_frames %u duration_s=%u",
                     produced, min_frames, duration_s);
    unsigned samples = run->metrics.period_samples - before.period_samples;
    if (has_period_max && samples > 0) {
        long max_ms = (long)(run->metrics.period_max_ns / 1000000ull);
        out |= ctt_check(run, idx, action, max_ms <= period_max_ms,
                         "period_max_ms expect<=%ld actual=%ld (mock soft bound)",
                         period_max_ms, max_ms);
    }
    if (expect && yaml_has(expect, "class1")) {
        int up = eip_stack_class1_up(priv->stack);
        const char *c1 = yaml_cstr(expect, "class1", "up");
        out |= ctt_check(run, idx, action,
                         (strcmp(c1, "up") == 0) ? up : !up,
                         "class1 expect=%s actual=%s", c1,
                         up ? "up" : "down");
    }
    if (require_c1 && !eip_stack_class1_up(priv->stack)) {
        run->metrics.ar_drops++;
    }
    if (has_unexp) {
        unsigned unexp = run->metrics.unexpected_frames - unexp_before;
        out |= ctt_check(run, idx, action, unexp <= want_unexp,
                         "unexpected_frames expect<=%u actual=%u", want_unexp,
                         unexp);
    }
    out |= check_cyclic_expect(run, &before, expect, idx, action, produced);
    return out;
}

static int step_io_cycle(ctt_run_t *run, eip_priv_t *priv,
                         const yaml_node_t *step, int idx)
{
    return step_class1_cyclic(run, priv, step, idx, "io_cycle");
}

static int step_soak(ctt_run_t *run, eip_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    return step_class1_cyclic(run, priv, step, idx, "soak");
}

static int step_acd_conflict(ctt_run_t *run, eip_priv_t *priv,
                             const yaml_node_t *step, int idx)
{
    const char *action = "acd_conflict";
    int conflict = yaml_bool(step, "conflict", 1);
    int rc = eip_stack_acd_conflict(priv->stack, conflict);
    return ctt_check(run, idx, action, rc == 0, "acd_conflict(%d) rc=%d",
                     conflict, rc);
}

static int step_lldp(ctt_run_t *run, eip_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    const char *action = "lldp";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    pump(priv);
    uint8_t frame[512];
    int flen = eip_stack_lldp_frame(priv->stack, frame, sizeof(frame));
    int out = ctt_check(run, idx, action, flen > 14, "lldp frame len=%d", flen);
    if (flen > 14) {
        (void)ctt_capture_step_frame(run, idx, action, frame, (size_t)flen);
        (void)ctt_ring_push(&run->mock.to_ctl, frame, (size_t)flen,
                            ctt_now_ns());
    }
    if (expect && yaml_has(expect, "ethertype")) {
        unsigned long want = yaml_ulong(expect, "ethertype", 0x88CC);
        uint16_t et = (flen > 14) ? ((uint16_t)frame[12] << 8) | frame[13] : 0;
        out |= ctt_check(run, idx, action, et == (uint16_t)want,
                         "ethertype expect=0x%04lx actual=0x%04x", want, et);
    }
    if (expect && yaml_has(expect, "product_name")) {
        const char *name = yaml_cstr(expect, "product_name", "");
        out |= ctt_check(run, idx, action,
                         flen > 14 && contains(frame, (size_t)flen, name),
                         "product_name '%s' not in LLDP", name);
    }
    return out;
}

static int step_watchdog(ctt_run_t *run, eip_priv_t *priv,
                         const yaml_node_t *step, int idx)
{
    const char *action = "watchdog";
    unsigned us = (unsigned)yaml_ulong(step, "sleep_us", 2000);
    sleep_us(us);
    pump(priv);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int out = 0;
    if (expect && yaml_has(expect, "class1")) {
        const char *c1 = yaml_cstr(expect, "class1", "down");
        int up = eip_stack_class1_up(priv->stack);
        out |= ctt_check(run, idx, action,
                         (strcmp(c1, "up") == 0) ? up : !up,
                         "class1 expect=%s actual=%s after %uus", c1,
                         up ? "up" : "down", us);
        if (!up) {
            run->metrics.ar_drops++;
        }
    }
    uint64_t last = 0, max = 0;
    uint32_t tos = 0;
    eip_stack_rt_stats(priv->stack, &last, &max, &tos);
    if (expect && yaml_has(expect, "timeouts_min")) {
        unsigned long want = yaml_ulong(expect, "timeouts_min", 1);
        out |= ctt_check(run, idx, action, tos >= (uint32_t)want,
                         "class1_timeouts %u < %lu", tos, want);
    }
    if (expect && yaml_bool(expect, "rt_stats", 0)) {
        out |= ctt_check(run, idx, action, last > 0 || max > 0,
                         "rt_stats last=%llu max=%llu",
                         (unsigned long long)last, (unsigned long long)max);
    }
    return out;
}

static int step_poll(ctt_run_t *run, eip_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    (void)run;
    (void)idx;
    unsigned n = (unsigned)yaml_ulong(step, "count", 1);
    unsigned us = (unsigned)yaml_ulong(step, "sleep_us", 0);
    for (unsigned i = 0; i < n; i++) {
        if (us) {
            sleep_us(us);
        }
        pump(priv);
    }
    return 0;
}

static int eip_setup(ctt_run_t *run)
{
    const yaml_node_t *dev = yaml_map_get(run->root, "device");
    eip_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.role = EIP_ROLE_ADAPTER;
    cfg.mock = 1;
    cfg.input_size = (uint16_t)(dev ? yaml_ulong(dev, "input_size", 32) : 32);
    cfg.output_size =
        (uint16_t)(dev ? yaml_ulong(dev, "output_size", 8) : 8);
    cfg.config_size =
        (uint16_t)(dev ? yaml_ulong(dev, "config_size", 1) : 1);
    cfg.input_assembly =
        (uint16_t)(dev ? yaml_ulong(dev, "input_assembly", 150) : 150);
    cfg.output_assembly =
        (uint16_t)(dev ? yaml_ulong(dev, "output_assembly", 101) : 101);
    cfg.config_assembly =
        (uint16_t)(dev ? yaml_ulong(dev, "config_assembly", 100) : 100);
    cfg.vendor_id =
        (uint16_t)(dev ? yaml_ulong(dev, "vendor_id", 0xABCD) : 0xABCD);
    cfg.device_type =
        (uint16_t)(dev ? yaml_ulong(dev, "device_type", 12) : 12);
    cfg.product_code =
        (uint16_t)(dev ? yaml_ulong(dev, "product_code", 1) : 1);
    cfg.major_rev = (uint8_t)(dev ? yaml_ulong(dev, "major_rev", 1) : 1);
    cfg.minor_rev = (uint8_t)(dev ? yaml_ulong(dev, "minor_rev", 0) : 0);
    cfg.serial_number =
        (uint32_t)(dev ? yaml_ulong(dev, "serial_number", 0x12345678)
                       : 0x12345678);
    cfg.rpi_us = (uint32_t)(dev ? yaml_ulong(dev, "rpi_us", 8000) : 8000);
    if (dev && yaml_has(dev, "cycle_us")) {
        cfg.rpi_us = (uint32_t)yaml_ulong(dev, "cycle_us", cfg.rpi_us);
    }
    cfg.security_class =
        (int)(dev ? yaml_long(dev, "security_class", 0) : 0);
    cfg.protection_mode =
        (uint32_t)(dev ? yaml_ulong(dev, "protection_mode", 0) : 0);
    cfg.lldp_enable = dev ? yaml_bool(dev, "lldp_enable", 0) : 0;
    cfg.acd_enable = dev ? yaml_bool(dev, "acd_enable", 0) : 0;
    cfg.lldp_tx_interval_sec =
        (uint16_t)(dev ? yaml_ulong(dev, "lldp_tx_interval_sec", 30) : 30);
    const char *pname =
        dev ? yaml_cstr(dev, "product_name", "FieldbusEIP") : "FieldbusEIP";
    snprintf(cfg.product_name, sizeof(cfg.product_name), "%s", pname);
    const char *iface = dev ? yaml_cstr(dev, "iface", "mock") : "mock";
    snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface);

    eip_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -ENOMEM;
    }

    const char *psk_hex = dev ? yaml_cstr(dev, "psk_hex", NULL) : NULL;
    if (psk_hex) {
        if (parse_hex_bytes(psk_hex, priv->psk, EIP_PSK_LEN) != 0) {
            LOG_ERROR("ctt_eip", "device.psk_hex must be %d hex chars",
                      EIP_PSK_LEN * 2);
            free(priv);
            return -EINVAL;
        }
        memcpy(cfg.psk, priv->psk, EIP_PSK_LEN);
        cfg.psk_set = 1;
        priv->psk_set = 1;
    }

    eip_stack_t *s = eip_stack_create(&cfg);
    if (!s) {
        LOG_ERROR("ctt_eip", "eip_stack_create failed (self stack DUT)");
        free(priv);
        return -ENOMEM;
    }
    priv->stack = s;
    run->priv = priv;

    eip_transport_ops_t ops = {.tcp_send = eip_tcp_send,
                               .udp_send = eip_udp_send,
                               .ctx = run};
    eip_stack_set_transport_ops(s, ops);

    if (eip_stack_start(s) != 0) {
        LOG_ERROR("ctt_eip", "eip_stack_start failed (mock=%d)", cfg.mock);
        return -EIO;
    }
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        LOG_WARN("ctt_eip",
                 "ethernetip CTT DUT is eip_cfg_t.mock inject "
                 "(handle_encap/handle_io); AF_PACKET is not wired for CIP TCP");
    }
    LOG_INFO("ctt_eip",
             "DUT=stacks/ethernetip (self stack) mock=1 product=%s "
             "sec_class=%d",
             cfg.product_name, cfg.security_class);
    if (cfg.rpi_us) {
        ctt_metrics_set_cycle_ns(&run->metrics, (uint64_t)cfg.rpi_us * 1000ull);
    }
    return 0;
}

static void eip_teardown(ctt_run_t *run)
{
    eip_priv_t *priv = run->priv;
    if (priv) {
        if (priv->stack) {
            eip_stack_destroy(priv->stack);
        }
        free(priv);
        run->priv = NULL;
    }
}

static int eip_step(ctt_run_t *run, const yaml_node_t *step, int index)
{
    eip_priv_t *priv = run->priv;
    const char *action = yaml_cstr(step, "action", "");
    if (strcmp(action, "register_session") == 0) {
        return step_register_session(run, priv, step, index);
    }
    if (strcmp(action, "list_identity") == 0) {
        return step_list_identity(run, priv, step, index);
    }
    if (strcmp(action, "list_services") == 0) {
        return step_list_services(run, priv, step, index);
    }
    if (strcmp(action, "get_attr") == 0) {
        return step_get_attr(run, priv, step, index);
    }
    if (strcmp(action, "write_input") == 0) {
        return step_write_input(run, priv, step, index);
    }
    if (strcmp(action, "read_input") == 0) {
        return step_read_input(run, priv, step, index);
    }
    if (strcmp(action, "read_output") == 0) {
        return step_read_output(run, priv, step, index);
    }
    if (strcmp(action, "forward_open") == 0) {
        return step_forward_open(run, priv, step, index);
    }
    if (strcmp(action, "forward_close") == 0) {
        return step_forward_close(run, priv, step, index);
    }
    if (strcmp(action, "encap_inject") == 0) {
        return step_encap_inject(run, priv, step, index);
    }
    if (strcmp(action, "class1_io") == 0) {
        return step_class1_io(run, priv, step, index);
    }
    if (strcmp(action, "io_cycle") == 0) {
        return step_io_cycle(run, priv, step, index);
    }
    if (strcmp(action, "soak") == 0) {
        return step_soak(run, priv, step, index);
    }
    if (strcmp(action, "acd_conflict") == 0) {
        return step_acd_conflict(run, priv, step, index);
    }
    if (strcmp(action, "lldp") == 0) {
        return step_lldp(run, priv, step, index);
    }
    if (strcmp(action, "watchdog") == 0) {
        return step_watchdog(run, priv, step, index);
    }
    if (strcmp(action, "poll") == 0) {
        return step_poll(run, priv, step, index);
    }
    ctt_failf(run, index, action,
              "unknown action (ethernetip: register_session, list_identity, "
              "list_services, get_attr, write_input, read_input, read_output, "
              "forward_open, forward_close, encap_inject, class1_io, io_cycle, "
              "soak, acd_conflict, lldp, watchdog, poll)");
    return -1;
}

const ctt_plugin_t ctt_plugin_ethernetip = {
    .name = "ethernetip",
    .setup = eip_setup,
    .step = eip_step,
    .teardown = eip_teardown,
};
