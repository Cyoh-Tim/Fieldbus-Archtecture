#include "eip_endian.h"
#include "eip_internal.h"

#include <errno.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int wait_recv(int fd, uint8_t *buf, size_t cap, int timeout_ms)
{
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (rc <= 0) {
        return rc == 0 ? -ETIMEDOUT : -errno;
    }
    ssize_t n = recv(fd, buf, cap, 0);
    if (n <= 0) {
        return -EIO;
    }
    return (int)n;
}

static int build_cia_path(uint8_t *path, size_t cap, size_t *used,
                          uint16_t class_id, uint16_t instance,
                          uint16_t attribute, int with_attr)
{
    *used = 0;
    if (eip_path_append_class(path, cap, used, class_id) != 0) {
        return -ENOSPC;
    }
    if (eip_path_append_instance(path, cap, used, instance) != 0) {
        return -ENOSPC;
    }
    if (with_attr) {
        if (eip_path_append_attribute(path, cap, used, attribute) != 0) {
            return -ENOSPC;
        }
    }
    return 0;
}

static int originator_sendrr(eip_stack_t *s, const uint8_t *cip, size_t cip_len,
                             uint8_t *cip_resp, size_t cip_resp_cap,
                             size_t *cip_resp_len)
{
    if (!s || s->originator_fd < 0 || !s->clients[0].session) {
        return -ENOTCONN;
    }
    uint8_t req[EIP_TCP_BUF_MAX];
    size_t off = EIP_ENCAP_HDR_SIZE;
    eip_wr_le32(req + off, 0);
    off += 4;
    eip_wr_le16(req + off, 10); /* timeout ticks-ish */
    off += 2;
    eip_wr_le16(req + off, 2);
    off += 2;
    eip_wr_le16(req + off, EIP_ITEM_NULL_ADDR);
    off += 2;
    eip_wr_le16(req + off, 0);
    off += 2;
    eip_wr_le16(req + off, EIP_ITEM_UNCONNECTED_DATA);
    off += 2;
    eip_wr_le16(req + off, (uint16_t)cip_len);
    off += 2;
    if (off + cip_len > sizeof(req)) {
        return -ENOSPC;
    }
    memcpy(req + off, cip, cip_len);
    off += cip_len;

    memset(req, 0, EIP_ENCAP_HDR_SIZE);
    eip_wr_le16(req + 0, EIP_CMD_SENDRRDATA);
    eip_wr_le16(req + 2, (uint16_t)(off - EIP_ENCAP_HDR_SIZE));
    eip_wr_le32(req + 4, s->clients[0].session);

    if (send(s->originator_fd, req, off, MSG_NOSIGNAL) < 0) {
        int e = errno;
        if ((e == EPIPE || e == ECONNRESET) &&
            s->clients[0].fd == s->originator_fd) {
            eip_tcp_client_drop(s, &s->clients[0]);
        }
        return -e;
    }

    uint8_t resp[EIP_TCP_BUF_MAX];
    int n = wait_recv(s->originator_fd, resp, sizeof(resp), 2000);
    if (n < EIP_ENCAP_HDR_SIZE) {
        return n < 0 ? n : -EIO;
    }
    uint16_t body_len = eip_rd_le16(resp + 2);
    if ((size_t)n < (size_t)EIP_ENCAP_HDR_SIZE + (size_t)body_len) {
        return -EIO;
    }
    const uint8_t *body = resp + EIP_ENCAP_HDR_SIZE;
    size_t boff = 6; /* iface + timeout */
    if (boff + 2 > body_len) {
        return -EIO;
    }
    uint16_t items = eip_rd_le16(body + boff);
    boff += 2;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    for (uint16_t i = 0; i < items; i++) {
        if (boff + 4 > body_len) {
            return -EIO;
        }
        uint16_t type = eip_rd_le16(body + boff);
        uint16_t length = eip_rd_le16(body + boff + 2);
        boff += 4;
        if (boff + length > body_len) {
            return -EIO;
        }
        if (type == EIP_ITEM_UNCONNECTED_DATA) {
            payload = body + boff;
            payload_len = length;
        }
        boff += length;
    }
    if (!payload || payload_len < 4) {
        return -EIO;
    }
    if (payload[2] != CIP_STATUS_SUCCESS) {
        return -EPROTO;
    }
    size_t data_off = 4;
    if (payload[3] > 0) {
        data_off += 2u * payload[3];
    }
    if (data_off > payload_len) {
        return -EIO;
    }
    size_t copy = payload_len - data_off;
    if (copy > cip_resp_cap) {
        copy = cip_resp_cap;
    }
    memcpy(cip_resp, payload + data_off, copy);
    *cip_resp_len = copy;
    return 0;
}

int eip_stack_explicit_get(eip_stack_t *s, uint16_t class_id, uint16_t instance,
                           uint16_t attribute, uint8_t *out, size_t *inout_len)
{
    if (!s || !out || !inout_len) {
        return -EINVAL;
    }
    if (s->cfg.mock) {
        /* Local loopback against our own objects */
        uint8_t path[EIP_PATH_MAX];
        size_t path_used = 0;
        if (build_cia_path(path, sizeof(path), &path_used, class_id, instance,
                           attribute, 1) != 0) {
            return -EINVAL;
        }
        uint8_t req[2 + EIP_PATH_MAX];
        req[0] = CIP_SVC_GET_ATTR_SINGLE;
        req[1] = (uint8_t)((path_used + 1) / 2);
        memcpy(req + 2, path, path_used);
        uint8_t resp[EIP_EXPLICIT_DATA_MAX + 8];
        size_t resp_len = 0;
        pthread_mutex_lock(&s->lock);
        eip_cip_route(s, req, 2 + path_used, resp, sizeof(resp), &resp_len);
        pthread_mutex_unlock(&s->lock);
        if (resp_len < 4 || resp[2] != CIP_STATUS_SUCCESS) {
            return -EIO;
        }
        size_t data_off = 4;
        size_t n = resp_len - data_off;
        if (n > *inout_len) {
            n = *inout_len;
        }
        memcpy(out, resp + data_off, n);
        *inout_len = n;
        return 0;
    }

    uint8_t path[EIP_PATH_MAX];
    size_t path_used = 0;
    if (build_cia_path(path, sizeof(path), &path_used, class_id, instance,
                       attribute, 1) != 0) {
        return -EINVAL;
    }
    uint8_t cip[2 + EIP_PATH_MAX];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = (uint8_t)((path_used + 1) / 2);
    memcpy(cip + 2, path, path_used);
    return originator_sendrr(s, cip, 2 + path_used, out, *inout_len, inout_len);
}

int eip_stack_explicit_set(eip_stack_t *s, uint16_t class_id, uint16_t instance,
                           uint16_t attribute, const uint8_t *data, size_t len)
{
    if (!s || !data) {
        return -EINVAL;
    }
    uint8_t path[EIP_PATH_MAX];
    size_t path_used = 0;
    if (build_cia_path(path, sizeof(path), &path_used, class_id, instance,
                       attribute, 1) != 0) {
        return -EINVAL;
    }
    uint8_t cip[2 + EIP_PATH_MAX + EIP_EXPLICIT_DATA_MAX];
    size_t cip_len = 0;
    cip[cip_len++] = CIP_SVC_SET_ATTR_SINGLE;
    cip[cip_len++] = (uint8_t)((path_used + 1) / 2);
    memcpy(cip + cip_len, path, path_used);
    cip_len += path_used;
    if (cip_len + len > sizeof(cip)) {
        return -ENOSPC;
    }
    memcpy(cip + cip_len, data, len);
    cip_len += len;

    if (s->cfg.mock) {
        uint8_t resp[64];
        size_t resp_len = 0;
        pthread_mutex_lock(&s->lock);
        eip_cip_route_auth(s, EIP_CIP_AUTH_SESSION | EIP_CIP_AUTH_SECURE, cip,
                           cip_len, resp, sizeof(resp), &resp_len);
        pthread_mutex_unlock(&s->lock);
        return (resp_len >= 4 && resp[2] == CIP_STATUS_SUCCESS) ? 0 : -EIO;
    }
    uint8_t out[8];
    size_t out_len = sizeof(out);
    return originator_sendrr(s, cip, cip_len, out, out_len, &out_len);
}

int eip_stack_tag_read(eip_stack_t *s, const char *tag, uint8_t *out,
                       size_t *inout_len)
{
    if (!s || !tag || !out || !inout_len) {
        return -EINVAL;
    }
    /* Prefer CIP symbolic path; map locally to input assembly when adapter. */
    uint8_t path[EIP_PATH_MAX];
    size_t path_used = 0;
    if (eip_path_append_ansi_tag(path, sizeof(path), &path_used, tag) != 0) {
        return -EINVAL;
    }
    uint8_t cip[2 + EIP_PATH_MAX];
    cip[0] = CIP_SVC_GET_ATTR_SINGLE;
    cip[1] = (uint8_t)((path_used + 1) / 2);
    memcpy(cip + 2, path, path_used);

    if (s->cfg.mock || s->cfg.role == EIP_ROLE_ADAPTER) {
        uint8_t resp[EIP_EXPLICIT_DATA_MAX + 8];
        size_t resp_len = 0;
        pthread_mutex_lock(&s->lock);
        eip_cip_route(s, cip, 2 + path_used, resp, sizeof(resp), &resp_len);
        pthread_mutex_unlock(&s->lock);
        if (resp_len < 4 || resp[2] != CIP_STATUS_SUCCESS) {
            return -EIO;
        }
        size_t n = resp_len - 4;
        if (n > *inout_len) {
            n = *inout_len;
        }
        memcpy(out, resp + 4, n);
        *inout_len = n;
        return 0;
    }
    return originator_sendrr(s, cip, 2 + path_used, out, *inout_len, inout_len);
}

int eip_stack_tag_write(eip_stack_t *s, const char *tag, const uint8_t *data,
                        size_t len)
{
    if (!s || !tag || !data) {
        return -EINVAL;
    }
    uint8_t path[EIP_PATH_MAX];
    size_t path_used = 0;
    if (eip_path_append_ansi_tag(path, sizeof(path), &path_used, tag) != 0) {
        return -EINVAL;
    }
    uint8_t cip[2 + EIP_PATH_MAX + EIP_EXPLICIT_DATA_MAX];
    size_t cip_len = 0;
    cip[cip_len++] = CIP_SVC_SET_ATTR_SINGLE;
    cip[cip_len++] = (uint8_t)((path_used + 1) / 2);
    memcpy(cip + cip_len, path, path_used);
    cip_len += path_used;
    if (cip_len + len > sizeof(cip)) {
        return -ENOSPC;
    }
    memcpy(cip + cip_len, data, len);
    cip_len += len;

    if (s->cfg.mock || s->cfg.role == EIP_ROLE_ADAPTER) {
        uint8_t resp[64];
        size_t resp_len = 0;
        pthread_mutex_lock(&s->lock);
        eip_cip_route_auth(s, EIP_CIP_AUTH_SESSION | EIP_CIP_AUTH_SECURE, cip,
                           cip_len, resp, sizeof(resp), &resp_len);
        pthread_mutex_unlock(&s->lock);
        return (resp_len >= 4 && resp[2] == CIP_STATUS_SUCCESS) ? 0 : -EIO;
    }
    uint8_t out[8];
    size_t out_len = sizeof(out);
    return originator_sendrr(s, cip, cip_len, out, out_len, &out_len);
}
