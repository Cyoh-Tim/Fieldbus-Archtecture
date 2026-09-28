#include "eip_endian.h"
#include "eip_internal.h"
#include "eip_sec.h"

#include <errno.h>
#include <string.h>

static void encap_hdr(uint8_t *out, uint16_t cmd, uint16_t length,
                      uint32_t session, uint32_t status, const uint8_t ctx[8])
{
    eip_wr_le16(out + 0, cmd);
    eip_wr_le16(out + 2, length);
    eip_wr_le32(out + 4, session);
    eip_wr_le32(out + 8, status);
    if (ctx) {
        memcpy(out + 12, ctx, 8);
    } else {
        memset(out + 12, 0, 8);
    }
    eip_wr_le32(out + 20, 0);
}

static int build_list_identity(eip_stack_t *s, uint8_t *payload, size_t cap,
                               size_t *out_len)
{
    /* CPF: 1 item — Identity */
    if (cap < 60) {
        return -ENOSPC;
    }
    size_t off = 0;
    eip_wr_le16(payload + off, 1);
    off += 2;
    eip_wr_le16(payload + off, 0x000C); /* ListIdentity response item */
    off += 2;
    size_t len_at = off;
    off += 2; /* fill later */

    eip_wr_le16(payload + off, 1); /* encap protocol version */
    off += 2;
    /* sockaddr stub (16 bytes) — zeros ok for unit tests */
    memset(payload + off, 0, 16);
    off += 16;
    eip_wr_le16(payload + off, s->cfg.vendor_id);
    off += 2;
    eip_wr_le16(payload + off, s->cfg.device_type);
    off += 2;
    eip_wr_le16(payload + off, s->cfg.product_code);
    off += 2;
    payload[off++] = s->cfg.major_rev;
    payload[off++] = s->cfg.minor_rev;
    eip_wr_le16(payload + off, 0); /* status */
    off += 2;
    eip_wr_le32(payload + off, s->cfg.serial_number);
    off += 4;
    size_t n = strlen(s->cfg.product_name);
    if (n > 32) {
        n = 32;
    }
    payload[off++] = (uint8_t)n;
    memcpy(payload + off, s->cfg.product_name, n);
    off += n;
    payload[off++] = 0xFF; /* state */

    eip_wr_le16(payload + len_at, (uint16_t)(off - (len_at + 2)));
    *out_len = off;
    return 0;
}

static int session_find(const eip_stack_t *s, uint32_t session)
{
    if (session == 0) {
        return -1;
    }
    for (int i = 0; i < s->n_sessions && i < EIP_CLASS3_SESSIONS_MAX; i++) {
        if (s->sessions[i].handle == session) {
            return i;
        }
    }
    return -1;
}

static int session_owned(const eip_stack_t *s, uint32_t session,
                         uint32_t owner_id)
{
    int i = session_find(s, session);
    if (i < 0) {
        return 0;
    }
    return s->sessions[i].owner_id == owner_id;
}

static uint32_t session_handle_for_owner(const eip_stack_t *s, uint32_t owner_id)
{
    if (owner_id == 0) {
        return 0;
    }
    for (int i = 0; i < s->n_sessions && i < EIP_CLASS3_SESSIONS_MAX; i++) {
        if (s->sessions[i].owner_id == owner_id) {
            return s->sessions[i].handle;
        }
    }
    return 0;
}

static uint32_t session_new_handle(eip_stack_t *s)
{
    for (int n = 0; n < EIP_CLASS3_SESSIONS_MAX + 8; n++) {
        uint32_t seq = s->next_session++;
        if (seq == 0) {
            seq = s->next_session++;
        }
        uint32_t h = seq ^ s->session_secret;
        if (h != 0 && session_find(s, h) < 0) {
            return h;
        }
    }
    return 0;
}

static uint32_t session_alloc(eip_stack_t *s, uint32_t owner_id)
{
    if (owner_id == 0) {
        return 0;
    }
    uint32_t existing = session_handle_for_owner(s, owner_id);
    if (existing != 0) {
        return existing;
    }
    if (s->n_sessions >= EIP_CLASS3_SESSIONS_MAX) {
        return 0;
    }
    uint32_t h = session_new_handle(s);
    if (h == 0) {
        return 0;
    }
    s->sessions[s->n_sessions].handle = h;
    s->sessions[s->n_sessions].owner_id = owner_id;
    s->n_sessions++;
    return h;
}

static void session_drop(eip_stack_t *s, uint32_t session, uint32_t owner_id)
{
    int i = session_find(s, session);
    if (i < 0 || s->sessions[i].owner_id != owner_id) {
        return;
    }
    s->sessions[i] = s->sessions[s->n_sessions - 1];
    s->n_sessions--;
}

void eip_encap_drop_owner(eip_stack_t *s, uint32_t owner_id)
{
    if (!s || owner_id == 0) {
        return;
    }
    int i = 0;
    while (i < s->n_sessions) {
        if (s->sessions[i].owner_id == owner_id) {
            s->sessions[i] = s->sessions[s->n_sessions - 1];
            s->n_sessions--;
            continue;
        }
        i++;
    }
}

static int handle_sendrr(eip_stack_t *s, uint32_t session, uint32_t owner_id,
                         const uint8_t *body, size_t body_len,
                         uint8_t *resp_body, size_t resp_cap, size_t *resp_len,
                         uint32_t *encap_status)
{
    /* interface handle(4) + timeout(2) + CPF */
    if (body_len < 6) {
        return -EINVAL;
    }
    if (!session_owned(s, session, owner_id)) {
        if (encap_status) {
            *encap_status = EIP_ENCAP_STATUS_INVALID_SESSION;
        }
        return -EINVAL;
    }
    size_t off = 6;
    if (off + 2 > body_len) {
        return -EINVAL;
    }
    uint16_t items = eip_rd_le16(body + off);
    off += 2;
    const uint8_t *cip = NULL;
    size_t cip_len = 0;
    const uint8_t *mac = NULL;
    size_t mac_len = 0;
    for (uint16_t i = 0; i < items; i++) {
        if (off + 4 > body_len) {
            return -EINVAL;
        }
        uint16_t type = eip_rd_le16(body + off);
        uint16_t length = eip_rd_le16(body + off + 2);
        off += 4;
        if (off + length > body_len) {
            return -EINVAL;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA) {
            cip = body + off;
            cip_len = length;
        } else if (type == EIP_SEC_ITEM_INTEGRITY) {
            mac = body + off;
            mac_len = length;
        }
        off += length;
    }
    if (!cip || cip_len < 2) {
        return -EINVAL;
    }

    if (eip_sec_check_ucmm(s, session, cip, cip_len, mac, mac_len) != 0) {
        /* Privilege / security failure as CIP-shaped bare reply via empty */
        uint8_t err[6];
        err[0] = (uint8_t)(cip[0] | CIP_SVC_REPLY);
        err[1] = 0;
        err[2] = CIP_STATUS_PRIVILEGE;
        err[3] = 0;
        size_t r = 0;
        eip_wr_le32(resp_body + r, 0);
        r += 4;
        eip_wr_le16(resp_body + r, 0);
        r += 2;
        eip_wr_le16(resp_body + r, 2);
        r += 2;
        eip_wr_le16(resp_body + r, EIP_ITEM_NULL_ADDR);
        r += 2;
        eip_wr_le16(resp_body + r, 0);
        r += 2;
        eip_wr_le16(resp_body + r, EIP_ITEM_UNCONNECTED_DATA);
        r += 2;
        eip_wr_le16(resp_body + r, 4);
        r += 2;
        memcpy(resp_body + r, err, 4);
        r += 4;
        *resp_len = r;
        return 0;
    }

    uint8_t cip_resp[EIP_EXPLICIT_DATA_MAX + 64];
    size_t cip_resp_len = 0;
    /* Session ownership was checked above. Class 0 is lab-open; class ≥1
     * mutating UCMM already passed eip_sec_check_ucmm (HMAC). */
    eip_cip_route_auth(s, EIP_CIP_AUTH_SESSION | EIP_CIP_AUTH_SECURE, cip,
                       cip_len, cip_resp, sizeof(cip_resp), &cip_resp_len);

    size_t mac_item_len = 0;
    uint8_t mac_item[4 + EIP_HMAC_LEN];
    if (eip_sec_required(s) && eip_sec_service_needs_mac(cip[0])) {
        mac_item_len = eip_sec_append_mac_item(s, session, cip_resp,
                                               cip_resp_len, mac_item,
                                               sizeof(mac_item));
    }

    uint16_t item_count = mac_item_len ? 3 : 2;
    if (resp_cap < 6 + 2 + 8 + cip_resp_len + mac_item_len) {
        return -ENOSPC;
    }
    size_t r = 0;
    eip_wr_le32(resp_body + r, 0);
    r += 4;
    eip_wr_le16(resp_body + r, 0);
    r += 2;
    eip_wr_le16(resp_body + r, item_count);
    r += 2;
    eip_wr_le16(resp_body + r, EIP_ITEM_NULL_ADDR);
    r += 2;
    eip_wr_le16(resp_body + r, 0);
    r += 2;
    eip_wr_le16(resp_body + r, EIP_ITEM_UNCONNECTED_DATA);
    r += 2;
    eip_wr_le16(resp_body + r, (uint16_t)cip_resp_len);
    r += 2;
    memcpy(resp_body + r, cip_resp, cip_resp_len);
    r += cip_resp_len;
    if (mac_item_len) {
        memcpy(resp_body + r, mac_item, mac_item_len);
        r += mac_item_len;
    }
    *resp_len = r;
    return 0;
}

int eip_encap_process(eip_stack_t *s, const uint8_t *req, size_t req_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len,
                      uint32_t owner_id)
{
    if (resp_len) {
        *resp_len = 0;
    }
    if (!req || req_len < EIP_ENCAP_HDR_SIZE || !resp || !resp_len) {
        return -EINVAL;
    }
    if (resp_cap < EIP_ENCAP_HDR_SIZE) {
        return -ENOSPC;
    }

    uint16_t cmd = eip_rd_le16(req + 0);
    uint16_t length = eip_rd_le16(req + 2);
    uint32_t session = eip_rd_le32(req + 4);
    const uint8_t *ctx = req + 12;
    const uint8_t *body = req + EIP_ENCAP_HDR_SIZE;
    /* Fail closed: claimed Encaps length must fit the received buffer.
     * Do not clamp and process a truncated PDU. */
    if ((size_t)EIP_ENCAP_HDR_SIZE + (size_t)length > req_len) {
        return -EINVAL;
    }

    uint8_t body_resp[EIP_TCP_BUF_MAX];
    size_t body_len = 0;
    uint32_t status = EIP_ENCAP_STATUS_SUCCESS;
    uint32_t out_session = session;

    switch (cmd) {
    case EIP_CMD_NOP:
        encap_hdr(resp, cmd, 0, session, 0, ctx);
        *resp_len = EIP_ENCAP_HDR_SIZE;
        return 0;

    case EIP_CMD_REGISTERSESSION:
        out_session = session_alloc(s, owner_id);
        if (out_session == 0) {
            status = EIP_ENCAP_STATUS_INVALID_CMD;
            body_len = 0;
            break;
        }
        /* protocol version + options echo */
        if (length >= 4 && sizeof(body_resp) >= 4) {
            memcpy(body_resp, body, 4);
            body_len = 4;
        } else {
            eip_wr_le16(body_resp, 1);
            eip_wr_le16(body_resp + 2, 0);
            body_len = 4;
        }
        break;

    case EIP_CMD_UNREGISTERSESSION:
        if (!session_owned(s, session, owner_id)) {
            encap_hdr(resp, cmd, 0, session, EIP_ENCAP_STATUS_INVALID_SESSION,
                      ctx);
            *resp_len = EIP_ENCAP_HDR_SIZE;
            return 0;
        }
        session_drop(s, session, owner_id);
        encap_hdr(resp, cmd, 0, session, 0, ctx);
        *resp_len = EIP_ENCAP_HDR_SIZE;
        return 0;

    case EIP_CMD_LISTIDENTITY:
        if (build_list_identity(s, body_resp, sizeof(body_resp), &body_len) !=
            0) {
            status = EIP_ENCAP_STATUS_INVALID_CMD;
            body_len = 0;
        }
        break;

    case EIP_CMD_LISTSERVICES:
        /* one service: Communications */
        eip_wr_le16(body_resp, 1);
        eip_wr_le16(body_resp + 2, 0x0100);
        eip_wr_le16(body_resp + 4, 20);
        eip_wr_le16(body_resp + 6, 1); /* version */
        eip_wr_le16(body_resp + 8, 0x0120); /* TCP + UDP caps */
        memset(body_resp + 10, 0, 16);
        memcpy(body_resp + 10, "Communications", 14);
        body_len = 26;
        break;

    case EIP_CMD_SENDRRDATA: {
        uint32_t sendrr_st = EIP_ENCAP_STATUS_INVALID_CMD;
        if (handle_sendrr(s, session, owner_id, body, length, body_resp,
                          sizeof(body_resp), &body_len, &sendrr_st) != 0) {
            status = sendrr_st;
            body_len = 0;
        }
        break;
    }

    default:
        status = EIP_ENCAP_STATUS_INVALID_CMD;
        body_len = 0;
        break;
    }

    if (EIP_ENCAP_HDR_SIZE + body_len > resp_cap) {
        return -ENOSPC;
    }
    encap_hdr(resp, cmd, (uint16_t)body_len, out_session, status, ctx);
    if (body_len) {
        memcpy(resp + EIP_ENCAP_HDR_SIZE, body_resp, body_len);
    }
    *resp_len = EIP_ENCAP_HDR_SIZE + body_len;
    return 0;
}
