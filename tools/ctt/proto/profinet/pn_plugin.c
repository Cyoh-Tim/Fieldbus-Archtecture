#include "ctt.h"
#include "cycle_clock.h"
#include "transport.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "logger.h"
#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

typedef struct {
    pn_stack_t *stack;
    uint8_t ctl_mac[6];
    uint8_t psk[PN_PSK_LEN];
    int psk_set;
    int udp_rpc;
    int udp_rpc_listen; /* UDP 34964: Device-originated ApplicationReady */
    int udp_snmp;
    uint32_t dut_ip; /* host order; 0 = mock handle_rpc / handle_snmp */
} pn_priv_t;

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
static const uint8_t k_lldp_mc[6] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E};

#define RPC_OP_CONNECT 0
#define RPC_OP_RELEASE 1
#define RPC_OP_READ    2
#define RPC_OP_WRITE   3
#define RPC_OP_CONTROL 4

static void sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    nanosleep(&ts, NULL);
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

static int parse_ipv4(const char *s, uint32_t *out)
{
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!s || !out) {
        return -1;
    }
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 || a > 255 || b > 255 ||
        c > 255 || d > 255) {
        return -1;
    }
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return 0;
}

static int parse_hex_buf(const char *s, uint8_t *out, size_t cap, size_t *n)
{
    if (!s || !out || !n) {
        return -1;
    }
    size_t sl = strlen(s);
    if (sl < 2 || (sl & 1u) || sl / 2 > cap) {
        return -1;
    }
    *n = sl / 2;
    return parse_hex_bytes(s, out, *n);
}

static int fd_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) {
        return -errno;
    }
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0 ? 0 : -errno;
}

static int udp_ephemeral(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    fd_nonblock(fd);
    return fd;
}

static int udp_bind_port(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }
    int yes = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int e = errno;
        close(fd);
        return -e;
    }
    fd_nonblock(fd);
    return fd;
}

static size_t append_dcp_block(uint8_t *p, uint8_t opt, uint8_t sub,
                               const uint8_t *data, uint16_t dlen)
{
    p[0] = opt;
    p[1] = sub;
    pn_wr_be16(p + 2, dlen);
    memcpy(p + 4, data, dlen);
    size_t n = 4u + dlen;
    if (dlen & 1u) {
        p[n++] = 0;
    }
    return n;
}

static size_t wr_pn_block(uint8_t *p, uint16_t type, const uint8_t *body,
                          uint16_t body_len)
{
    uint16_t blen = (uint16_t)(2 + body_len);
    pn_wr_be16(p, type);
    pn_wr_be16(p + 2, blen);
    p[4] = 1;
    p[5] = 0;
    memcpy(p + 6, body, body_len);
    size_t n = 4u + blen;
    if (n & 1u) {
        p[n++] = 0;
    }
    return n;
}

static void fill_connect_aruuid(uint8_t *dst)
{
    for (int i = 0; i < 16; i++) {
        dst[i] = (uint8_t)(0xA0 + i);
    }
}

static void pump(ctt_run_t *run, pn_priv_t *priv)
{
    pn_stack_poll(priv->stack);
    ctt_ctl_harvest(run);
}

static void inject_eth(ctt_run_t *run, pn_priv_t *priv, const uint8_t *frame,
                       size_t len)
{
    (void)ctt_ctl_send(run, frame, len);
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        for (int i = 0; i < 40; i++) {
            pump(run, priv);
            if (run->mock.to_ctl.count > 0) {
                break;
            }
            sleep_ms(2);
        }
    } else {
        pump(run, priv);
    }
}

static int udp_transact(ctt_run_t *run, pn_priv_t *priv, int fd, uint16_t port,
                        const uint8_t *req, size_t req_len, uint8_t *resp,
                        size_t cap, size_t *rlen)
{
    if (fd < 0 || priv->dut_ip == 0) {
        return -ENOTCONN;
    }
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    dst.sin_addr.s_addr = htonl(priv->dut_ip);
    if (sendto(fd, req, req_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        return -errno;
    }
    *rlen = 0;
    for (int i = 0; i < 50; i++) {
        pump(run, priv);
        struct sockaddr_in src;
        socklen_t sl = sizeof(src);
        ssize_t n = recvfrom(fd, resp, cap, MSG_DONTWAIT,
                             (struct sockaddr *)&src, &sl);
        if (n > 0) {
            *rlen = (size_t)n;
            return 0;
        }
        sleep_ms(2);
    }
    return -ETIMEDOUT;
}

static int rpc_transact(ctt_run_t *run, pn_priv_t *priv, const uint8_t *pdu,
                        size_t plen, uint8_t *resp, size_t cap, size_t *rlen)
{
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET && priv->udp_rpc >= 0 &&
        priv->dut_ip != 0) {
        int rc = udp_transact(run, priv, priv->udp_rpc, PN_RPC_PORT, pdu, plen,
                              resp, cap, rlen);
        if (rc != 0) {
            LOG_WARN("ctt_pn", "UDP CM %d failed rc=%d (lab)", PN_RPC_PORT, rc);
        }
        return rc;
    }
    return pn_stack_handle_rpc(priv->stack, pdu, plen, resp, cap, rlen);
}

static int snmp_transact(ctt_run_t *run, pn_priv_t *priv, const uint8_t *req,
                         size_t req_len, uint8_t *resp, size_t cap, size_t *rlen)
{
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET && priv->udp_snmp >= 0 &&
        priv->dut_ip != 0) {
        int rc = udp_transact(run, priv, priv->udp_snmp, PN_SNMP_PORT, req,
                              req_len, resp, cap, rlen);
        if (rc != 0) {
            LOG_WARN("ctt_pn", "UDP SNMP %d failed rc=%d (lab)", PN_SNMP_PORT,
                     rc);
        }
        return rc;
    }
    return pn_stack_handle_snmp(priv->stack, req, req_len, resp, cap, rlen);
}

static int finish_eth_step(ctt_run_t *run, const yaml_node_t *step, int idx,
                           const char *action, int found, const uint8_t *frame,
                           size_t n)
{
    int rc = 0;
    if (found && n > 0) {
        (void)ctt_capture_step_frame(run, idx, action, frame, n);
        const char *g = yaml_cstr(step, "golden", NULL);
        if (g && g[0]) {
            rc |= ctt_golden_check(run, idx, action, frame, n, g);
        }
    } else if (yaml_cstr(step, "golden", NULL) &&
               run->opts.transport == CTT_TRANSPORT_MOCK) {
        ctt_failf(run, idx, action, "golden: set but no matching frame");
        rc = -1;
    }
    return rc;
}

static uint8_t dcp_status_from_str(const char *s)
{
    if (!s) {
        return 0xFF;
    }
    if (strcmp(s, "success") == 0) {
        return PN_DCP_RESP_SUCCESS;
    }
    if (strcmp(s, "unsupported") == 0 || strcmp(s, "reject") == 0) {
        return PN_DCP_RESP_UNSUP;
    }
    return 0xFF;
}

static uint8_t dcp_service_from_str(const char *s)
{
    if (!s) {
        return 0xFF;
    }
    if (strcmp(s, "identify") == 0) {
        return PN_DCP_IDENTIFY;
    }
    if (strcmp(s, "set") == 0) {
        return PN_DCP_SET;
    }
    if (strcmp(s, "get") == 0) {
        return PN_DCP_GET;
    }
    if (strcmp(s, "hello") == 0) {
        return PN_DCP_HELLO;
    }
    return 0xFF;
}

static int step_dcp_identify(ctt_run_t *run, pn_priv_t *priv,
                             const yaml_node_t *step, int idx)
{
    const char *action = "dcp_identify";
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0x11223344ul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");

    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_ID_REQ);
    pay[2] = PN_DCP_IDENTIFY;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), k_dcp_mc, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, 16);

    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);

    unsigned long want_et =
        expect ? yaml_ulong(expect, "ethertype", PN_ETHTYPE_PN) : PN_ETHTYPE_PN;
    unsigned long want_fid =
        expect ? yaml_ulong(expect, "frame_id", PN_FRAMEID_DCP_ID_RES)
               : PN_FRAMEID_DCP_ID_RES;
    uint8_t want_svc = dcp_service_from_str(
        expect ? yaml_cstr(expect, "service", "identify") : "identify");
    uint8_t want_st = dcp_status_from_str(
        expect ? yaml_cstr(expect, "status", "success") : "success");
    const char *want_name =
        expect ? yaml_cstr(expect, "name_of_station", NULL) : NULL;

    int found = 0;
    uint8_t buf[CTT_FRAME_MAX];
    int n = 0;
    int last_n = 0;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) > 0) {
        last_n = n;
        if (n < 18) {
            continue;
        }
        uint16_t et = pn_rd_be16(buf + 12);
        uint16_t fid = pn_rd_be16(buf + 14);
        uint8_t sid = buf[16];
        uint8_t st = buf[17];
        if (et == (uint16_t)want_et && fid == (uint16_t)want_fid &&
            sid == want_svc && st == want_st &&
            (!want_name || contains(buf, (size_t)n, want_name))) {
            found = 1;
            last_n = n;
            break;
        }
    }
    int rc = ctt_check(run, idx, action, found,
                       "expect Identify.Res et=0x%04lx fid=0x%04lx service=%s "
                       "status=%s name=%s (TX FrameID=0xFEFE multicast "
                       "01:0E:CF:00:00:00)",
                       want_et, want_fid,
                       expect ? yaml_cstr(expect, "service", "identify")
                              : "identify",
                       expect ? yaml_cstr(expect, "status", "success") : "success",
                       want_name ? want_name : "(any)");
    rc |= finish_eth_step(run, step, idx, action, found, buf, (size_t)last_n);
    return rc;
}

static int step_dcp_set(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                        int idx)
{
    const char *action = "dcp_set";
    int signed_req = yaml_bool(step, "signed", 0);
    const char *new_name = yaml_cstr(step, "name_of_station", NULL);
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0xAABBCCDDul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    char generated[512];
    if (yaml_has(step, "name_len")) {
        int nwant = (int)yaml_long(step, "name_len", 0);
        if (nwant < 1 || nwant >= (int)sizeof(generated)) {
            ctt_failf(run, idx, action, "name_len out of range");
            return -1;
        }
        const char *fill_s = yaml_cstr(step, "name_fill", "a");
        char fill = (fill_s && fill_s[0]) ? fill_s[0] : 'a';
        if (yaml_bool(step, "name_dns", 0)) {
            int pos = 0;
            while (pos < nwant) {
                int remain = nwant - pos;
                if (pos > 0) {
                    generated[pos++] = '.';
                    remain = nwant - pos;
                }
                int lab = remain;
                if (lab > 63) {
                    lab = 63;
                    if (remain - 63 == 1) {
                        lab = 62; /* avoid a 1-byte leftover that becomes '.' */
                    }
                }
                for (int i = 0; i < lab && pos < nwant; i++) {
                    generated[pos++] = fill;
                }
            }
            generated[nwant] = '\0';
            if (nwant > 0 && generated[nwant - 1] == '.') {
                generated[nwant - 1] = fill;
            }
        } else {
            memset(generated, fill, (size_t)nwant);
            generated[nwant] = '\0';
        }
        new_name = generated;
    }
    if (!new_name) {
        ctt_failf(run, idx, action, "missing name_of_station or name_len");
        return -1;
    }

    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    size_t nlen = strlen(new_name);
    uint8_t nameblk[2 + 512];
    if (nlen > sizeof(nameblk) - 2) {
        nlen = sizeof(nameblk) - 2;
    }
    pn_wr_be16(nameblk, 1);
    memcpy(nameblk + 2, new_name, nlen);

    uint8_t blocks[768];
    size_t bn = 0;
    bn += append_dcp_block(blocks + bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                           nameblk, (uint16_t)(2 + nlen));

    uint8_t pay[PN_FRAME_MAX];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);
    size_t plen = 12 + bn;

    if (signed_req) {
        if (!cfg->psk_set && !priv->psk_set) {
            ctt_failf(run, idx, action, "signed Set requires device.psk_hex");
            return -1;
        }
        const uint8_t *psk = cfg->psk_set ? cfg->psk : priv->psk;
        uint8_t mac[PN_HMAC_LEN];
        pn_hmac_sha256(psk, PN_PSK_LEN, pay, plen, mac);
        bn += append_dcp_block(blocks + bn, PN_DCP_OPT_SEC, PN_DCP_SUB_SEC_HMAC,
                               mac, PN_HMAC_LEN);
        pn_wr_be16(pay + 10, (uint16_t)bn);
        memcpy(pay + 12, blocks, bn);
        plen = 12 + bn;
    }

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, plen);

    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);

    const char *want_result = expect ? yaml_cstr(expect, "result", NULL) : NULL;
    const char *want_sta =
        expect ? yaml_cstr(expect, "station_name", NULL) : NULL;
    const char *got_sta = pn_stack_cfg(priv->stack)->station_name;

    int rc = 0;
    if (want_sta) {
        rc |= ctt_check(run, idx, action, strcmp(got_sta, want_sta) == 0,
                        "station_name expect=%s actual=%s (signed=%s)", want_sta,
                        got_sta, signed_req ? "true" : "false");
    }
    if (expect && yaml_has(expect, "station_name_len")) {
        unsigned long want_n = yaml_ulong(expect, "station_name_len", 0);
        size_t got_n = strlen(got_sta);
        rc |= ctt_check(run, idx, action, got_n == (size_t)want_n,
                        "station_name_len expect=%lu actual=%zu (max %d)",
                        want_n, got_n, PN_STATION_NAME_MAX);
    }
    if (want_result) {
        int accept = strcmp(want_result, "accept") == 0;
        int reject = strcmp(want_result, "reject") == 0;
        int ok = 0;
        uint8_t buf[CTT_FRAME_MAX];
        uint8_t match[CTT_FRAME_MAX];
        int n = 0;
        size_t match_n = 0;
        while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) >
               0) {
            if (n < 18) {
                continue;
            }
            uint16_t et = pn_rd_be16(buf + 12);
            uint16_t fid = pn_rd_be16(buf + 14);
            uint8_t sid = buf[16];
            uint8_t st = buf[17];
            if (et == PN_ETHTYPE_PN && fid == PN_FRAMEID_DCP_GETSET &&
                sid == PN_DCP_SET) {
                if (accept && st == PN_DCP_RESP_SUCCESS) {
                    ok = 1;
                    memcpy(match, buf, (size_t)n);
                    match_n = (size_t)n;
                }
                if (reject && st == PN_DCP_RESP_UNSUP) {
                    ok = 1;
                    memcpy(match, buf, (size_t)n);
                    match_n = (size_t)n;
                }
            }
        }
        /* DUT cfg is the source of truth used by the migrated unit test. */
        if (!ok && want_sta) {
            ok = (strcmp(got_sta, want_sta) == 0);
        }
        rc |= ctt_check(run, idx, action, ok,
                        "result expect=%s station_name=%s signed=%s",
                        want_result, got_sta, signed_req ? "true" : "false");
        rc |= finish_eth_step(run, step, idx, action, ok, match, match_n);
    } else {
        rc |= finish_eth_step(run, step, idx, action, 0, NULL, 0);
    }
    return rc;
}

static int pop_dcp_match(ctt_run_t *run, uint16_t want_fid, uint8_t want_svc,
                         uint8_t want_st, const char *want_name, uint8_t *out,
                         size_t *out_n)
{
    uint8_t buf[CTT_FRAME_MAX];
    int n = 0;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) > 0) {
        if (n < 18) {
            continue;
        }
        uint16_t et = pn_rd_be16(buf + 12);
        uint16_t fid = pn_rd_be16(buf + 14);
        uint8_t sid = buf[16];
        uint8_t st = buf[17];
        if (et == PN_ETHTYPE_PN && fid == want_fid && sid == want_svc &&
            (want_st == 0xFF || st == want_st) &&
            (!want_name || contains(buf, (size_t)n, want_name))) {
            memcpy(out, buf, (size_t)n);
            *out_n = (size_t)n;
            return 1;
        }
    }
    return 0;
}

static int step_dcp_get(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                        int idx)
{
    const char *action = "dcp_get";
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0x55667788ul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);

    uint8_t pay[16];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_GET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, 4);
    pay[12] = PN_DCP_OPT_ALL;
    pay[13] = 0xFF;
    pn_wr_be16(pay + 14, 0);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, 16);
    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);

    unsigned long want_fid =
        expect ? yaml_ulong(expect, "frame_id", PN_FRAMEID_DCP_GETSET)
               : PN_FRAMEID_DCP_GETSET;
    uint8_t want_svc = dcp_service_from_str(
        expect ? yaml_cstr(expect, "service", "get") : "get");
    uint8_t want_st = dcp_status_from_str(
        expect ? yaml_cstr(expect, "status", "success") : "success");
    const char *want_name =
        expect ? yaml_cstr(expect, "name_of_station", cfg->station_name)
               : cfg->station_name;

    uint8_t match[CTT_FRAME_MAX];
    size_t match_n = 0;
    int found = pop_dcp_match(run, (uint16_t)want_fid, want_svc, want_st,
                              want_name, match, &match_n);
    int rc = ctt_check(run, idx, action, found,
                       "expect Get.Res fid=0x%04lx service=get name=%s",
                       want_fid, want_name ? want_name : "(any)");
    rc |= finish_eth_step(run, step, idx, action, found, match, match_n);
    return rc;
}

static int step_dcp_set_ip(ctt_run_t *run, pn_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "dcp_set_ip";
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0x01020304ul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *ip_s = yaml_cstr(step, "ip", NULL);
    const char *nm_s = yaml_cstr(step, "netmask", "255.255.255.0");
    const char *gw_s = yaml_cstr(step, "gateway", "0.0.0.0");
    if (!ip_s) {
        ctt_failf(run, idx, action, "missing ip");
        return -1;
    }
    uint32_t ip = 0, nm = 0, gw = 0;
    if (parse_ipv4(ip_s, &ip) != 0 || parse_ipv4(nm_s, &nm) != 0 ||
        parse_ipv4(gw_s, &gw) != 0) {
        ctt_failf(run, idx, action, "bad ip/netmask/gateway");
        return -1;
    }

    uint8_t ipblk[14];
    pn_wr_be16(ipblk, 1); /* BlockQualifier */
    pn_wr_be32(ipblk + 2, ip);
    pn_wr_be32(ipblk + 6, nm);
    pn_wr_be32(ipblk + 10, gw);

    uint8_t blocks[32];
    size_t bn = append_dcp_block(blocks, PN_DCP_OPT_IP, PN_DCP_SUB_IP_PARAM,
                                 ipblk, 14);

    uint8_t pay[512];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);

    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, 12 + bn);
    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);
    /* Hello is sent after Set.Res; extra poll for lab timing. */
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        for (int i = 0; i < 20; i++) {
            pump(run, priv);
            sleep_ms(2);
        }
    } else {
        pump(run, priv);
    }

    uint32_t got_ip = pn_stack_cfg(priv->stack)->ip;
    int ip_ok = (got_ip == ip);
    int rc = ctt_check(run, idx, action, ip_ok,
                       "cfg.ip expect=%s actual=%u.%u.%u.%u", ip_s,
                       (got_ip >> 24) & 0xff, (got_ip >> 16) & 0xff,
                       (got_ip >> 8) & 0xff, got_ip & 0xff);

    uint8_t frames[8][CTT_FRAME_MAX];
    size_t flens[8] = {0};
    int nf = 0;
    uint8_t tmp[CTT_FRAME_MAX];
    int tn = 0;
    while (nf < 8 &&
           (tn = ctt_ring_pop(&run->mock.to_ctl, tmp, sizeof(tmp), NULL)) > 0) {
        memcpy(frames[nf], tmp, (size_t)tn);
        flens[nf] = (size_t)tn;
        nf++;
    }

    int set_ok = 0;
    int hello_ok = 0;
    size_t set_i = 0, hello_i = 0;
    for (int i = 0; i < nf; i++) {
        if (flens[i] < 18) {
            continue;
        }
        uint16_t et = pn_rd_be16(frames[i] + 12);
        uint16_t fid = pn_rd_be16(frames[i] + 14);
        uint8_t sid = frames[i][16];
        uint8_t st = frames[i][17];
        if (et != PN_ETHTYPE_PN) {
            continue;
        }
        if (fid == PN_FRAMEID_DCP_GETSET && sid == PN_DCP_SET &&
            st == PN_DCP_RESP_SUCCESS) {
            set_ok = 1;
            set_i = (size_t)i;
        }
        if (fid == PN_FRAMEID_DCP_HELLO && sid == PN_DCP_HELLO &&
            contains(frames[i], flens[i],
                     pn_stack_cfg(priv->stack)->station_name)) {
            hello_ok = 1;
            hello_i = (size_t)i;
        }
    }
    rc |= ctt_check(run, idx, action, set_ok, "expect Set.Res success for IP");

    int want_hello = !expect || yaml_bool(expect, "hello", 1);
    if (want_hello) {
        rc |= ctt_check(run, idx, action, hello_ok,
                        "expect DCP Hello FrameID=0xFEFC after Set IP");
    }
    if (want_hello && hello_ok) {
        rc |= finish_eth_step(run, step, idx, action, 1, frames[hello_i],
                              flens[hello_i]);
    } else if (set_ok) {
        rc |= finish_eth_step(run, step, idx, action, 1, frames[set_i],
                              flens[set_i]);
    } else {
        /* No matching Set.Res: do not pass uninitialized frames[0]/flens[0]. */
        rc |= finish_eth_step(run, step, idx, action, 0, NULL, 0);
    }
    return rc;
}

static int step_dcp_signal(ctt_run_t *run, pn_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "dcp_signal";
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0xA1B2C3D4ul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);

    uint8_t sig[4];
    pn_wr_be16(sig, 1);      /* BlockQualifier */
    pn_wr_be16(sig + 2, 0x0100); /* Flash Once-ish */
    uint8_t blocks[16];
    size_t bn = append_dcp_block(blocks, PN_DCP_OPT_CTRL, PN_DCP_SUB_CTRL_SIGNAL,
                                 sig, 4);

    uint8_t pay[64];
    pn_wr_be16(pay, PN_FRAMEID_DCP_GETSET);
    pay[2] = PN_DCP_SET;
    pay[3] = PN_DCP_REQ;
    pn_wr_be32(pay + 4, xid);
    pn_wr_be16(pay + 8, 0);
    pn_wr_be16(pay + 10, (uint16_t)bn);
    memcpy(pay + 12, blocks, bn);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, 12 + bn);
    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);

    const char *want_result = expect ? yaml_cstr(expect, "result", "accept")
                                     : "accept";
    int accept = strcmp(want_result, "accept") == 0;
    uint8_t match[CTT_FRAME_MAX];
    size_t match_n = 0;
    int ok = pop_dcp_match(run, PN_FRAMEID_DCP_GETSET, PN_DCP_SET,
                           accept ? PN_DCP_RESP_SUCCESS : PN_DCP_RESP_UNSUP,
                           NULL, match, &match_n);
    int rc = ctt_check(run, idx, action, ok,
                       "expect Signal Set.Res result=%s", want_result);
    rc |= finish_eth_step(run, step, idx, action, ok, match, match_n);
    return rc;
}

static int step_dcp_hello(ctt_run_t *run, pn_priv_t *priv,
                          const yaml_node_t *step, int idx)
{
    const char *action = "dcp_hello";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *want_name =
        expect ? yaml_cstr(expect, "name_of_station",
                           pn_stack_cfg(priv->stack)->station_name)
               : pn_stack_cfg(priv->stack)->station_name;

    ctt_ctl_clear_rx(run);
    pn_stack_send_hello(priv->stack);
    pump(run, priv);
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        for (int i = 0; i < 20; i++) {
            pump(run, priv);
            if (run->mock.to_ctl.count > 0) {
                break;
            }
            sleep_ms(2);
        }
    }

    uint8_t match[CTT_FRAME_MAX];
    size_t match_n = 0;
    int found = pop_dcp_match(run, PN_FRAMEID_DCP_HELLO, PN_DCP_HELLO, PN_DCP_REQ,
                              want_name, match, &match_n);
    int mc = found && match_n >= 6 && match[0] == 0x01 && match[1] == 0x0E &&
             match[2] == 0xCF;
    int rc = ctt_check(run, idx, action, found && mc,
                       "expect Hello FrameID=0xFEFC dst=01:0E:CF:00:00:00 name=%s",
                       want_name ? want_name : "(any)");
    rc |= finish_eth_step(run, step, idx, action, found, match, match_n);
    return rc;
}

/* CL RPC v4, LE drep, device object (instance, device, vendor) and PNIO IF.
 * CTT DUTs use the stack default vendor 0xABCD / device 0x0001. */
static void stamp_pnio_cl_req(uint8_t *pdu)
{
    static const uint8_t obj[16] = {
        0x00, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0x01, 0x00, 0x01, 0xab, 0xcd};
    static const uint8_t iface[16] = {
        0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11,
        0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d};
    pdu[0] = 4;
    pdu[1] = 0;
    pdu[4] = 0x10;
    memcpy(pdu + 8, obj, 16);
    memcpy(pdu + 24, iface, 16);
}

static size_t ndr_wrap(uint8_t *out, const uint8_t *blocks, size_t n)
{
    pn_wr_le32(out, (uint32_t)n);
    pn_wr_le32(out + 4, (uint32_t)n);
    pn_wr_le32(out + 8, (uint32_t)n);
    pn_wr_le32(out + 12, 0);
    pn_wr_le32(out + 16, (uint32_t)n);
    memcpy(out + 20, blocks, n);
    return 20 + n;
}

/* with_iocr: optional input IOCR. Absent YAML keys keep the AR-only
 * Connect (no IOCR). SCF/RR are SendClockFactor and ReductionRatio. */
static size_t build_connect_pdu(uint8_t *pdu, size_t cap, int integrity,
                                int integrity_bad, const uint8_t *psk,
                                int psk_set, const uint8_t initiator_mac[6],
                                int with_iocr, uint16_t scf, uint16_t rr)
{
    if (cap < 80 + 20 + 64) {
        return 0;
    }
    memset(pdu, 0, cap);
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, 0); /* Connect */

    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    fill_connect_aruuid(ar + 2);
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, initiator_mac, 6);
    bn += wr_pn_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    if (with_iocr) {
        uint8_t inb[18];
        memset(inb, 0, sizeof(inb));
        pn_wr_be16(inb, PN_IOCR_INPUT);
        pn_wr_be16(inb + 12, 0x8001);
        pn_wr_be16(inb + 14, scf);
        pn_wr_be16(inb + 16, rr);
        bn += wr_pn_block(blocks + bn, PN_BLOCK_IOCR_REQ, inb, sizeof(inb));
    }

    if (integrity) {
        if (!psk_set) {
            return 0;
        }
        uint8_t mac[PN_HMAC_LEN];
        pn_hmac_sha256(psk, PN_PSK_LEN, blocks, bn, mac);
        if (integrity_bad) {
            mac[0] ^= 0xFFu;
        }
        uint8_t sec[2 + PN_HMAC_LEN];
        pn_wr_be16(sec, 0x0001); /* alg id */
        memcpy(sec + 2, mac, PN_HMAC_LEN);
        bn += wr_pn_block(blocks + bn, PN_BLOCK_SEC_INT, sec, sizeof(sec));
    }

    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);
    return 80 + stub;
}

static int parse_connect_frame_ids(const uint8_t *resp, size_t rlen,
                                   uint16_t *in_fid, uint16_t *out_fid)
{
    *in_fid = 0;
    *out_fid = 0;
    if (rlen < 80 + 20) {
        return -1;
    }
    const uint8_t *stub = resp + 80;
    uint32_t actual = pn_rd_le32(stub + 16);
    const uint8_t *blocks = stub + 20;
    size_t n = actual;
    if (80 + 20 + n > rlen) {
        n = rlen - 100;
    }
    size_t off = 0;
    while (off + 6 <= n) {
        uint16_t type = pn_rd_be16(blocks + off);
        uint16_t blen = pn_rd_be16(blocks + off + 2);
        if (blen < 2 || off + 4u + blen > n) {
            break;
        }
        const uint8_t *body = blocks + off + 6;
        uint16_t body_len = (uint16_t)(blen - 2);
        if (type == PN_BLOCK_IOCR_RES && body_len >= 6) {
            uint16_t iocr_type = pn_rd_be16(body);
            uint16_t fid = pn_rd_be16(body + 4);
            if (iocr_type == PN_IOCR_INPUT) {
                *in_fid = fid;
            } else if (iocr_type == PN_IOCR_OUTPUT) {
                *out_fid = fid;
            }
        }
        off += 4u + blen;
        if (off & 1u) {
            off++;
        }
    }
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

static int step_rpc_connect(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "rpc_connect";
    int integrity = 0;
    int integrity_bad = 0;
    parse_integrity(step, &integrity, &integrity_bad);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    /* Either key adds an input IOCR. A missing partner defaults to
     * SCF 32 / RR 8 (8 ms). Neither key: AR-only, same as before. */
    int with_iocr = yaml_has(step, "send_clock_factor") ||
                    yaml_has(step, "reduction_ratio");
    uint16_t scf = (uint16_t)yaml_ulong(step, "send_clock_factor", 32);
    uint16_t rr = (uint16_t)yaml_ulong(step, "reduction_ratio", 8);

    uint8_t pdu[512];
    size_t plen = build_connect_pdu(pdu, sizeof(pdu), integrity, integrity_bad,
                                    cfg->psk, cfg->psk_set, priv->ctl_mac,
                                    with_iocr, scf, rr);
    if (plen == 0) {
        ctt_failf(run, idx, action, "failed to build Connect PDU");
        return -1;
    }

    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, plen, resp, sizeof(resp), &rlen);

    int rpc_ok = (rc == 0 && rlen > 0);
    int ar_up = pn_stack_ar_up(priv->stack);

    int out = 0;
    if (expect && yaml_has(expect, "rpc_response")) {
        int want = yaml_bool(expect, "rpc_response", 1);
        out |= ctt_check(run, idx, action, rpc_ok == want,
                         "rpc_response expect=%s actual=%s rlen=%zu rc=%d",
                         want ? "true" : "false", rpc_ok ? "true" : "false",
                         rlen, rc);
    }
    if (expect && yaml_has(expect, "ar")) {
        const char *ar = yaml_cstr(expect, "ar", "");
        int want_up = (strcmp(ar, "up") == 0);
        int want_rej = (strcmp(ar, "rejected") == 0 || strcmp(ar, "down") == 0);
        if (want_up) {
            out |= ctt_check(run, idx, action, ar_up,
                             "ar expect=up actual=%s (pn_stack_ar_up)",
                             ar_up ? "up" : "rejected");
        } else if (want_rej) {
            out |= ctt_check(run, idx, action, !ar_up,
                             "ar expect=rejected actual=%s",
                             ar_up ? "up" : "rejected");
        } else {
            ctt_failf(run, idx, action, "unknown ar expect=%s", ar);
            out = -1;
        }
    }
    if (expect && yaml_has(expect, "in_frame_id")) {
        uint16_t in_fid = 0, out_fid = 0;
        parse_connect_frame_ids(resp, rlen, &in_fid, &out_fid);
        unsigned long want_in = yaml_ulong(expect, "in_frame_id", 0x8001);
        unsigned long want_out = yaml_has(expect, "out_frame_id")
                                     ? yaml_ulong(expect, "out_frame_id", 0x8002)
                                     : 0;
        out |= ctt_check(run, idx, action, in_fid == (uint16_t)want_in,
                         "in_frame_id expect=0x%04lx actual=0x%04x", want_in,
                         in_fid);
        if (yaml_has(expect, "out_frame_id")) {
            out |= ctt_check(run, idx, action, out_fid == (uint16_t)want_out,
                             "out_frame_id expect=0x%04lx actual=0x%04x",
                             want_out, out_fid);
        }
    }
    if (expect && yaml_has(expect, "pniostatus")) {
        unsigned long want = yaml_ulong(expect, "pniostatus", 0);
        uint32_t got = 0xffffffffu;
        if (rlen >= 84) {
            got = pn_rd_le32(resp + 80);
        }
        out |= ctt_check(run, idx, action, got == (uint32_t)want,
                         "pniostatus expect=0x%08lx actual=0x%08x", want, got);
    }
    return out;
}

#define CTT_PN_OTHER  0
#define CTT_PN_RTC1   1
#define CTT_PN_LLDP   2
#define CTT_PN_ALARM  3
#define CTT_PN_DCP    4

/* EtherType at 12, or at 16 when offset 12 is TPID 0x8100.
 * *hdr is the FrameID offset: 14 untagged, 18 tagged. DCP and LLDP
 * stay untagged, so their hdr stays 14. */
static int pn_frame_hdr(const uint8_t *frame, int n, size_t *hdr, uint16_t *et)
{
    if (n < 14) {
        return -1;
    }
    uint16_t tpid = pn_rd_be16(frame + 12);
    if (tpid == PN_ETHTYPE_VLAN) {
        if (n < 18) {
            return -1;
        }
        if (hdr) {
            *hdr = 18;
        }
        if (et) {
            *et = pn_rd_be16(frame + 16);
        }
        return 0;
    }
    if (hdr) {
        *hdr = 14;
    }
    if (et) {
        *et = tpid;
    }
    return 0;
}

static int classify_pn_frame(const uint8_t *frame, int n)
{
    size_t hdr = 14;
    uint16_t et = 0;
    if (pn_frame_hdr(frame, n, &hdr, &et) != 0) {
        return CTT_PN_OTHER;
    }
    if (et == PN_ETHTYPE_LLDP) {
        return CTT_PN_LLDP;
    }
    if (et != PN_ETHTYPE_PN || n < (int)(hdr + 2)) {
        return CTT_PN_OTHER;
    }
    uint16_t fid = pn_rd_be16(frame + hdr);
    if (fid >= 0x8000u && fid <= 0xBBFFu) {
        return CTT_PN_RTC1;
    }
    if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
        return CTT_PN_ALARM;
    }
    if (fid == PN_FRAMEID_DCP_HELLO || fid == PN_FRAMEID_DCP_GETSET ||
        fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_ID_RES) {
        return CTT_PN_DCP;
    }
    return CTT_PN_OTHER;
}

static int is_rtc1(const uint8_t *frame, int n, uint16_t want_et)
{
    size_t hdr = 14;
    uint16_t et = 0;
    if (pn_frame_hdr(frame, n, &hdr, &et) != 0 || n < (int)(hdr + 2)) {
        return 0;
    }
    uint16_t fid = pn_rd_be16(frame + hdr);
    return et == want_et && fid >= 0x8000u && fid <= 0xBBFFu;
}

typedef struct {
    uint8_t last[CTT_FRAME_MAX];
    size_t last_n;
    uint16_t first_cc;
    uint16_t last_cc;
    int cc_samples;
    int cc_not_increasing;
    int contains_hits;
} rtc1_harvest_t;

static uint16_t rtc1_data_len(pn_priv_t *priv)
{
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    uint16_t n = cfg->input_len;
    return n ? n : 32;
}

static int rtc1_cycle_counter(const uint8_t *frame, int n, uint16_t data_len,
                              uint16_t *cc)
{
    /* RTC1 TX is tagged: offset 12 is TPID 0x8100 and FrameID is at 18.
     * T12-7 pads C_SDU to 36 before APDUStatus, so CycleCounter is the
     * first of the last 4 octets, not data_len + IOPS. */
    (void)data_len;
    size_t hdr = 14;
    uint16_t et = 0;
    if (n < 18 || pn_rd_be16(frame + 12) != PN_ETHTYPE_VLAN) {
        return 0;
    }
    if (pn_frame_hdr(frame, n, &hdr, &et) != 0 || et != PN_ETHTYPE_PN ||
        hdr != 18u) {
        return 0;
    }
    if (n < (int)(hdr + 2u + 4u)) {
        return 0;
    }
    *cc = pn_rd_be16(frame + (size_t)n - 4u);
    return 1;
}

static void drain_io_frames(ctt_run_t *run, int *got_rtc1, uint64_t *last_ts,
                            uint16_t want_et, int count_unexpected,
                            rtc1_harvest_t *h, uint16_t data_len,
                            const char *needle)
{
    uint8_t buf[CTT_FRAME_MAX];
    uint64_t ts = 0;
    int n;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), &ts)) > 0) {
        int kind = classify_pn_frame(buf, n);
        if (is_rtc1(buf, n, want_et) || kind == CTT_PN_RTC1) {
            if (*last_ts != 0 && ts >= *last_ts) {
                ctt_metrics_note_period(&run->metrics, ts - *last_ts);
            }
            *last_ts = ts;
            run->metrics.rtc1_frames++;
            if (got_rtc1) {
                (*got_rtc1)++;
            }
            if (h) {
                memcpy(h->last, buf, (size_t)n);
                h->last_n = (size_t)n;
                uint16_t cc = 0;
                if (rtc1_cycle_counter(buf, n, data_len, &cc)) {
                    if (h->cc_samples == 0) {
                        h->first_cc = cc;
                    } else {
                        uint16_t d = (uint16_t)(cc - h->last_cc);
                        if (d == 0 || d > 64u) {
                            h->cc_not_increasing = 1;
                        }
                    }
                    h->last_cc = cc;
                    h->cc_samples++;
                }
                if (needle && needle[0] &&
                    contains(buf, (size_t)n, needle)) {
                    h->contains_hits++;
                }
            }
        } else if (kind == CTT_PN_LLDP) {
            /* periodic CC-B neighbor; expected during soak */
        } else if (count_unexpected) {
            run->metrics.unexpected_frames++;
        }
    }
}

static int check_cyclic_expect(ctt_run_t *run, const ctt_metrics_t *before,
                               const yaml_node_t *expect, int idx,
                               const char *action, int got)
{
    if (!expect) {
        return 0;
    }
    int rc = 0;
    unsigned late = run->metrics.late_cycles - before->late_cycles;
    unsigned missed = run->metrics.missed_cycles - before->missed_cycles;
    unsigned samples = run->metrics.period_samples - before->period_samples;

    if (yaml_has(expect, "max_frames")) {
        int maxf = (int)yaml_long(expect, "max_frames", got);
        rc |= ctt_check(run, idx, action, got <= maxf,
                        "max_frames expect<=%d actual=%d", maxf, got);
    }
    if (yaml_has(expect, "max_late")) {
        unsigned want = (unsigned)yaml_ulong(expect, "max_late", 0);
        rc |= ctt_check(run, idx, action, late <= want,
                        "max_late expect<=%u actual=%u (dt > 1.5 * cycle_us)",
                        want, late);
    }
    if (yaml_has(expect, "max_missed")) {
        unsigned want = (unsigned)yaml_ulong(expect, "max_missed", 0);
        rc |= ctt_check(run, idx, action, missed <= want,
                        "max_missed expect<=%u actual=%u (dt > 2.5 * cycle_us)",
                        want, missed);
    }
    if (yaml_has(expect, "jitter_max_ms")) {
        long want = yaml_long(expect, "jitter_max_ms", 0);
        long actual = (long)(run->metrics.jitter_max_ns / 1000000ull);
        rc |= ctt_check(run, idx, action, actual <= want,
                        "jitter_max_ms expect<=%ld actual=%ld (max |dt - "
                        "cycle_us|)",
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

/* After PrmEnd the stack's data-hold watches O→T. Mock io_cycle does
 * not otherwise send cyclic output, so feed one RTC1 per poll. */
static void inject_ot_rtc1(pn_priv_t *priv)
{
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    uint16_t dlen = cfg->output_len ? cfg->output_len : 8;
    if (dlen > 128) {
        dlen = 128;
    }
    uint8_t pay[2 + 128 + 8];
    pn_wr_be16(pay, 0x8002);
    memset(pay + 2, 0, dlen);
    size_t n = 2u + dlen;
    pay[n++] = 0x80; /* IOPS good */
    pn_wr_be16(pay + n, 1);
    n += 2;
    pay[n++] = 0x35; /* DataStatus */
    pay[n++] = 0;    /* TransferStatus */
    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, n);
    if (flen) {
        (void)pn_stack_handle_eth(priv->stack, frame, flen);
    }
}

static int step_io_cycle(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                         int idx)
{
    const char *action = "io_cycle";
    int count = (int)yaml_long(step, "count", 16);
    unsigned cycle_ms = (unsigned)yaml_long(step, "cycle_ms", 8);
    int require_ar = yaml_bool(step, "require_ar", 1);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int ar_up = pn_stack_ar_up(priv->stack);

    if (require_ar && !ar_up) {
        ctt_failf(run, idx, action, "AR not up; Connect first (RTC1 / CC-B)");
        return -1;
    }

    int min_frames;
    if (expect && yaml_has(expect, "min_frames")) {
        min_frames = (int)yaml_long(expect, "min_frames", 0);
    } else if (!require_ar) {
        min_frames = 0;
    } else {
        min_frames = count;
    }
    long period_max_ms =
        expect ? yaml_long(expect, "period_max_ms", 20) : 20;
    int has_period_max = !expect || yaml_has(expect, "period_max_ms") ||
                         require_ar;
    uint16_t want_et = (uint16_t)(expect ? yaml_ulong(expect, "ethertype",
                                                      PN_ETHTYPE_PN)
                                         : PN_ETHTYPE_PN);

    ctt_metrics_t before = run->metrics;
    ctt_ctl_clear_rx(run);

    int got = 0;
    uint64_t last_ts = 0;
    uint64_t budget_ns =
        (uint64_t)count * (uint64_t)cycle_ms * 1000000ull * 4ull;
    if (budget_ns < 250000000ull) {
        budget_ns = 250000000ull;
    }
    int prove_none = (min_frames <= 0);
    int hold_for_max = expect && yaml_has(expect, "max_frames");
    if (prove_none && budget_ns > 120000000ull) {
        budget_ns = 120000000ull;
    }
    uint64_t deadline = ctt_now_ns() + budget_ns;
    rtc1_harvest_t harvest;
    memset(&harvest, 0, sizeof(harvest));
    uint16_t data_len = rtc1_data_len(priv);
    const char *needle =
        expect && yaml_has(expect, "contains")
            ? yaml_cstr(expect, "contains", NULL)
            : NULL;

    while (ctt_now_ns() < deadline) {
        if (pn_stack_app_ready(priv->stack)) {
            inject_ot_rtc1(priv);
        }
        pump(run, priv);
        drain_io_frames(run, &got, &last_ts, want_et, 0, &harvest, data_len,
                        needle);
        if (!prove_none && !hold_for_max && got >= min_frames) {
            break;
        }
        sleep_ms(1);
    }

    int rc = 0;
    if (expect && yaml_has(expect, "ar")) {
        const char *ar = yaml_cstr(expect, "ar", "");
        int want_up = (strcmp(ar, "up") == 0);
        int now_up = pn_stack_ar_up(priv->stack);
        rc |= ctt_check(run, idx, action, want_up ? now_up : !now_up,
                        "ar expect=%s actual=%s", ar, now_up ? "up" : "down");
    }
    rc |= ctt_check(run, idx, action, got >= min_frames,
                    "min_frames expect>=%d actual=%d cycle_ms=%u "
                    "ethertype=0x%04x (RTC1 CC-B, not IRT)",
                    min_frames, got, cycle_ms, want_et);
    unsigned samples = run->metrics.period_samples - before.period_samples;
    if (has_period_max && samples > 0) {
        long max_ms = (long)(run->metrics.period_max_ns / 1000000ull);
        rc |= ctt_check(run, idx, action, max_ms <= period_max_ms,
                        "period_max_ms expect<=%ld actual=%ld (mock soft bound)",
                        period_max_ms, max_ms);
    }
    rc |= check_cyclic_expect(run, &before, expect, idx, action, got);
    if (expect && yaml_has(expect, "contains")) {
        rc |= ctt_check(run, idx, action, harvest.contains_hits > 0,
                        "RTC1 payload contains '%s' hits=%d frames=%d",
                        needle ? needle : "", harvest.contains_hits, got);
    }
    if (expect && yaml_has(expect, "vlan_tci")) {
        unsigned long want_tci = yaml_ulong(expect, "vlan_tci", 0);
        uint16_t got_tci = 0;
        int tag_ok = harvest.last_n >= 18 &&
                     pn_rd_be16(harvest.last + 12) == PN_ETHTYPE_VLAN;
        if (tag_ok) {
            got_tci = pn_rd_be16(harvest.last + 14);
            tag_ok = got_tci == (uint16_t)want_tci;
        }
        rc |= ctt_check(run, idx, action, tag_ok,
                        "vlan_tci expect=0x%04lx actual=0x%04x (PCP %u VID %u)",
                        want_tci, got_tci, (unsigned)((got_tci >> 13) & 7u),
                        (unsigned)(got_tci & 0x0fffu));
    }
    if (expect && yaml_has(expect, "cycle_counter")) {
        const char *mode = yaml_cstr(expect, "cycle_counter", "increasing");
        int want_inc = (strcmp(mode, "increasing") == 0);
        int ok = want_inc && harvest.cc_samples >= 2 &&
                 !harvest.cc_not_increasing;
        rc |= ctt_check(run, idx, action, ok,
                        "cycle_counter expect=%s samples=%d first=0x%04x "
                        "last=0x%04x stall_or_jump=%d",
                        mode, harvest.cc_samples, harvest.first_cc,
                        harvest.last_cc, harvest.cc_not_increasing);
    }
    return rc;
}

static int step_rpc_release(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "rpc_release";
    const yaml_node_t *expect = yaml_map_get(step, "expect");

    uint8_t pdu[256];
    memset(pdu, 0, sizeof(pdu));
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, RPC_OP_RELEASE);
    uint8_t rel[18];
    memset(rel, 0, sizeof(rel));
    fill_connect_aruuid(rel + 2);
    uint8_t blocks[32];
    size_t bn = wr_pn_block(blocks, PN_BLOCK_AR_REQ, rel, sizeof(rel));
    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);

    uint8_t resp[512];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, 80 + stub, resp, sizeof(resp), &rlen);
    int rpc_ok = (rc == 0 && rlen > 0);
    int ar_up = pn_stack_ar_up(priv->stack);

    int out = 0;
    if (expect && yaml_has(expect, "rpc_response")) {
        int want = yaml_bool(expect, "rpc_response", 1);
        out |= ctt_check(run, idx, action, rpc_ok == want,
                         "rpc_response expect=%s actual=%s rlen=%zu rc=%d",
                         want ? "true" : "false", rpc_ok ? "true" : "false",
                         rlen, rc);
    }
    const char *ar = expect ? yaml_cstr(expect, "ar", "down") : "down";
    int want_down = (strcmp(ar, "down") == 0 || strcmp(ar, "rejected") == 0);
    if (want_down) {
        out |= ctt_check(run, idx, action, !ar_up,
                         "ar expect=down actual=%s (after Release)",
                         ar_up ? "up" : "down");
    } else if (strcmp(ar, "up") == 0) {
        out |= ctt_check(run, idx, action, ar_up, "ar expect=up actual=%s",
                         ar_up ? "up" : "down");
    }
    return out;
}

static int step_rpc_inject(ctt_run_t *run, pn_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "rpc_inject";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    uint8_t pdu[512];
    size_t plen = 0;
    const char *hex = yaml_cstr(step, "pdu_hex", NULL);

    if (hex && hex[0]) {
        if (parse_hex_buf(hex, pdu, sizeof(pdu), &plen) != 0) {
            ctt_failf(run, idx, action, "bad pdu_hex");
            return -1;
        }
    } else if (yaml_has(step, "opcode")) {
        uint16_t op = (uint16_t)yaml_ulong(step, "opcode", 0xFFFF);
        memset(pdu, 0, 80);
        stamp_pnio_cl_req(pdu);
        pn_wr_le16(pdu + 68, op);
        plen = 80;
    } else {
        ctt_failf(run, idx, action, "need pdu_hex or opcode");
        return -1;
    }

    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, plen, resp, sizeof(resp), &rlen);
    int rpc_ok = (rc == 0 && rlen > 0);
    int ar_up = pn_stack_ar_up(priv->stack);

    int out = 0;
    if (expect && yaml_has(expect, "rpc_response")) {
        int want = yaml_bool(expect, "rpc_response", 1);
        out |= ctt_check(run, idx, action, rpc_ok == want,
                         "rpc_response expect=%s actual=%s rlen=%zu rc=%d "
                         "plen=%zu (fail-closed)",
                         want ? "true" : "false", rpc_ok ? "true" : "false",
                         rlen, rc, plen);
    } else {
        out |= ctt_check(run, idx, action, !rpc_ok,
                         "malformed/unknown RPC must fail closed rc=%d rlen=%zu",
                         rc, rlen);
    }
    const char *ar = expect ? yaml_cstr(expect, "ar", "down") : "down";
    int want_down = (strcmp(ar, "down") == 0 || strcmp(ar, "rejected") == 0);
    if (want_down) {
        out |= ctt_check(run, idx, action, !ar_up,
                         "ar expect=down actual=%s (inject must not establish AR)",
                         ar_up ? "up" : "down");
    } else if (strcmp(ar, "up") == 0) {
        out |= ctt_check(run, idx, action, ar_up, "ar expect=up actual=%s",
                         ar_up ? "up" : "down");
    }
    return out;
}

static uint16_t control_cmd_from_str(const char *s)
{
    if (!s) {
        return PN_CONTROL_PRM_END;
    }
    if (strcmp(s, "parameter_end") == 0 || strcmp(s, "prm_end") == 0) {
        return PN_CONTROL_PRM_END;
    }
    if (strcmp(s, "application_ready") == 0 || strcmp(s, "app_ready") == 0) {
        return PN_CONTROL_APP_READY;
    }
    return PN_CONTROL_PRM_END;
}

static int step_rpc_write(ctt_run_t *run, pn_priv_t *priv,
                          const yaml_node_t *step, int idx)
{
    const char *action = "rpc_write";
    uint16_t index = (uint16_t)yaml_ulong(step, "index", PN_INDEX_IM1);
    uint16_t slot = (uint16_t)yaml_ulong(step, "slot", 0);
    uint16_t subslot = (uint16_t)yaml_ulong(step, "subslot", 1);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *data_hex = yaml_cstr(step, "data_hex", NULL);
    uint8_t data[128];
    size_t dlen = 0;
    if (data_hex) {
        if (parse_hex_buf(data_hex, data, sizeof(data), &dlen) != 0) {
            ctt_failf(run, idx, action, "bad data_hex");
            return -1;
        }
    } else {
        const char *ascii = yaml_cstr(step, "data", "line-A");
        dlen = strlen(ascii);
        if (dlen > sizeof(data)) {
            dlen = sizeof(data);
        }
        memcpy(data, ascii, dlen);
    }

    /* IODWriteReqHeader is 64 bytes (body 58 = fields + 24-byte RWPadding).
     * Record bytes follow the header; they are not placed in the padding. */
    uint8_t body[58];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_connect_aruuid(body + 2);
    pn_wr_be16(body + 22, slot);
    pn_wr_be16(body + 24, subslot);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, (uint32_t)dlen);

    uint8_t blocks[64 + 128];
    size_t bn = wr_pn_block(blocks, PN_BLOCK_IOD_WRITE_REQ, body, sizeof(body));
    if (dlen > 0) {
        memcpy(blocks + bn, data, dlen);
        bn += dlen;
    }

    uint8_t pdu[512];
    memset(pdu, 0, sizeof(pdu));
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, RPC_OP_WRITE);
    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);

    uint8_t resp[512];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, 80 + stub, resp, sizeof(resp), &rlen);
    int rpc_ok = (rc == 0 && rlen > 0);
    int out = 0;
    if (expect && yaml_has(expect, "rpc_response")) {
        int want = yaml_bool(expect, "rpc_response", 1);
        out |= ctt_check(run, idx, action, rpc_ok == want,
                         "rpc_response expect=%s actual=%s rlen=%zu index=0x%04x",
                         want ? "true" : "false", rpc_ok ? "true" : "false",
                         rlen, index);
    } else {
        out |= ctt_check(run, idx, action, rpc_ok,
                         "rpc Write rlen=%zu rc=%d index=0x%04x", rlen, rc,
                         index);
    }
    return out;
}

static int step_rpc_control(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "rpc_control";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    uint16_t cmd = control_cmd_from_str(yaml_cstr(step, "command", "parameter_end"));

    uint8_t body[26];
    memset(body, 0, sizeof(body));
    fill_connect_aruuid(body + 2);
    pn_wr_be16(body + 22, cmd);
    uint8_t blocks[64];
    size_t bn = wr_pn_block(blocks, PN_BLOCK_CONTROL_REQ, body, sizeof(body));

    uint8_t pdu[256];
    memset(pdu, 0, sizeof(pdu));
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, RPC_OP_CONTROL);
    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);

    uint8_t resp[512];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, 80 + stub, resp, sizeof(resp), &rlen);
    int rpc_ok = (rc == 0 && rlen > 0);
    int ar_up = pn_stack_ar_up(priv->stack);
    int app = pn_stack_app_ready(priv->stack);

    int out = 0;
    if (expect && yaml_has(expect, "rpc_response")) {
        int want = yaml_bool(expect, "rpc_response", 1);
        out |= ctt_check(run, idx, action, rpc_ok == want,
                         "rpc_response expect=%s actual=%s rlen=%zu cmd=0x%04x",
                         want ? "true" : "false", rpc_ok ? "true" : "false",
                         rlen, cmd);
    } else {
        out |= ctt_check(run, idx, action, rpc_ok, "rpc Control rlen=%zu rc=%d",
                         rlen, rc);
    }
    if (expect && yaml_has(expect, "ar")) {
        const char *ar = yaml_cstr(expect, "ar", "up");
        int want_up = (strcmp(ar, "up") == 0);
        out |= ctt_check(run, idx, action, want_up ? ar_up : !ar_up,
                         "ar expect=%s actual=%s", ar, ar_up ? "up" : "down");
    }
    if (expect && yaml_has(expect, "app_ready")) {
        int want = yaml_bool(expect, "app_ready", 1);
        out |= ctt_check(run, idx, action, app == want,
                         "app_ready expect=%s actual=%s",
                         want ? "true" : "false", app ? "true" : "false");
    }
    return out;
}

static int pdu_has_app_ready(const uint8_t *pdu, size_t n)
{
    if (n < 80 + 20) {
        return 0;
    }
    uint16_t op = pn_rd_le16(pdu + 68);
    if (op != RPC_OP_CONTROL) {
        return 0;
    }
    uint32_t actual = pn_rd_le32(pdu + 80 + 16);
    const uint8_t *blocks = pdu + 100;
    size_t blen = actual;
    if (100 + blen > n) {
        blen = n - 100;
    }
    size_t off = 0;
    while (off + 6 <= blen) {
        uint16_t type = pn_rd_be16(blocks + off);
        uint16_t bl = pn_rd_be16(blocks + off + 2);
        if (bl < 2 || off + 4u + bl > blen) {
            break;
        }
        const uint8_t *body = blocks + off + 6;
        uint16_t body_len = (uint16_t)(bl - 2);
        if (type == PN_BLOCK_APP_READY_REQ && body_len >= 24) {
            size_t cmd_off = (body_len >= 26) ? 22u : 20u;
            if (pn_rd_be16(body + cmd_off) == PN_CONTROL_APP_READY) {
                return 1;
            }
        }
        off += 4u + bl;
        if (off & 1u) {
            off++;
        }
    }
    return 0;
}

static int step_rpc_application_ready(ctt_run_t *run, pn_priv_t *priv,
                                      const yaml_node_t *step, int idx)
{
    const char *action = "rpc_application_ready";
    const yaml_node_t *expect = yaml_map_get(step, "expect");

    uint8_t pdu[1024];
    size_t plen = 0;
    int got = 0;

    int fds[2];
    int nfd = 0;
    if (priv->udp_rpc >= 0) {
        fds[nfd++] = priv->udp_rpc;
    }
    if (priv->udp_rpc_listen >= 0) {
        fds[nfd++] = priv->udp_rpc_listen;
    }
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET && nfd > 0 &&
        priv->dut_ip != 0) {
        for (int i = 0; i < 50 && !got; i++) {
            pump(run, priv);
            for (int f = 0; f < nfd && !got; f++) {
                struct sockaddr_in src;
                socklen_t sl = sizeof(src);
                ssize_t n = recvfrom(fds[f], pdu, sizeof(pdu), MSG_DONTWAIT,
                                     (struct sockaddr *)&src, &sl);
                if (n > 0) {
                    plen = (size_t)n;
                    got = pdu_has_app_ready(pdu, plen);
                }
            }
            if (got) {
                break;
            }
            sleep_ms(2);
        }
    } else {
        int rc = pn_stack_take_rpc_tx(priv->stack, pdu, sizeof(pdu), &plen);
        got = (rc == 0 && pdu_has_app_ready(pdu, plen));
    }

    int app = pn_stack_app_ready(priv->stack);
    int out = 0;
    int want_req = !expect || yaml_bool(expect, "rpc_request", 1);
    out |= ctt_check(run, idx, action, got == want_req,
                     "ApplicationReady indication expect=%s actual=%s len=%zu",
                     want_req ? "true" : "false", got ? "true" : "false", plen);
    if (expect && yaml_has(expect, "app_ready")) {
        int want = yaml_bool(expect, "app_ready", 1);
        out |= ctt_check(run, idx, action, app == want,
                         "app_ready expect=%s actual=%s",
                         want ? "true" : "false", app ? "true" : "false");
    }
    return out;
}

static int step_alarm(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                      int idx)
{
    const char *action = "alarm";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    unsigned long want_fid =
        expect ? yaml_ulong(expect, "frame_id", PN_FRAMEID_ALARM_HIGH)
               : PN_FRAMEID_ALARM_HIGH;
    unsigned long want_et =
        expect ? yaml_ulong(expect, "ethertype", PN_ETHTYPE_PN) : PN_ETHTYPE_PN;
    const char *pri = yaml_cstr(step, "priority", NULL);
    if (pri && strcmp(pri, "low") == 0) {
        want_fid = expect && yaml_has(expect, "frame_id")
                       ? want_fid
                       : PN_FRAMEID_ALARM_LOW;
    }

    if (!pn_stack_ar_up(priv->stack)) {
        if (yaml_bool(step, "require_ar", 1)) {
            ctt_failf(run, idx, action, "AR not up; Connect first");
            return -1;
        }
        ctt_ctl_clear_rx(run);
        int src = pn_stack_send_alarm_ex(priv->stack, (uint16_t)want_fid);
        int found = 0;
        uint8_t buf[CTT_FRAME_MAX];
        int n;
        pump(run, priv);
        while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) >
               0) {
            size_t hdr = 14;
            if (pn_frame_hdr(buf, n, &hdr, NULL) != 0 || n < (int)(hdr + 2)) {
                continue;
            }
            uint16_t fid = pn_rd_be16(buf + hdr);
            if (fid == (uint16_t)want_fid) {
                found = 1;
                break;
            }
        }
        int out = 0;
        if (expect && yaml_has(expect, "tx")) {
            int want_tx = yaml_bool(expect, "tx", 0);
            out |= ctt_check(run, idx, action, found == want_tx,
                             "alarm tx expect=%s actual=%s rc=%d (no AR)",
                             want_tx ? "true" : "false",
                             found ? "true" : "false", src);
        } else {
            out |= ctt_check(run, idx, action, src != 0 && !found,
                             "alarm without AR must not TX rc=%d found=%d", src,
                             found);
        }
        return out;
    }

    ctt_ctl_clear_rx(run);
    int src = pn_stack_send_alarm_ex(priv->stack, (uint16_t)want_fid);
    if (src != 0) {
        ctt_failf(run, idx, action, "pn_stack_send_alarm rc=%d", src);
        return -1;
    }
    pump(run, priv);
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        for (int i = 0; i < 20; i++) {
            pump(run, priv);
            if (run->mock.to_ctl.count > 0) {
                break;
            }
            sleep_ms(2);
        }
    }

    int found = 0;
    uint8_t buf[CTT_FRAME_MAX];
    int n = 0;
    int last_n = 0;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) > 0) {
        last_n = n;
        size_t hdr = 14;
        uint16_t et = 0;
        if (pn_frame_hdr(buf, n, &hdr, &et) != 0 || n < (int)(hdr + 2)) {
            continue;
        }
        uint16_t fid = pn_rd_be16(buf + hdr);
        if (et == (uint16_t)want_et && fid == (uint16_t)want_fid) {
            found = 1;
            last_n = n;
            break;
        }
    }
    int rc = ctt_check(run, idx, action, found,
                       "expect Alarm TX et=0x%04lx fid=0x%04lx (CC-B RTA, not IRT)",
                       want_et, want_fid);
    if (expect && yaml_has(expect, "vlan_tci")) {
        unsigned long want_tci = yaml_ulong(expect, "vlan_tci", 0);
        uint16_t got_tci = 0;
        int tag_ok = found && last_n >= 18 &&
                     pn_rd_be16(buf + 12) == PN_ETHTYPE_VLAN;
        if (tag_ok) {
            got_tci = pn_rd_be16(buf + 14);
            tag_ok = got_tci == (uint16_t)want_tci;
        }
        rc |= ctt_check(run, idx, action, tag_ok,
                        "vlan_tci expect=0x%04lx actual=0x%04x (PCP %u VID %u)",
                        want_tci, got_tci, (unsigned)((got_tci >> 13) & 7u),
                        (unsigned)(got_tci & 0x0fffu));
    }
    rc |= finish_eth_step(run, step, idx, action, found, buf, (size_t)last_n);
    return rc;
}

static int step_record_read(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "record_read";
    uint16_t index = (uint16_t)yaml_ulong(step, "index", 0xAFF0);
    uint16_t slot = (uint16_t)yaml_ulong(step, "slot", 0);
    uint16_t subslot = (uint16_t)yaml_ulong(step, "subslot", 1);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *want_order =
        expect ? yaml_cstr(expect, "order_id", "FB-ARCH-PN-DEV") : "FB-ARCH-PN-DEV";
    unsigned long want_vendor =
        expect ? yaml_ulong(expect, "vendor_id", 0xABCD) : 0xABCD;

    uint8_t body[34];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1); /* seqNumber */
    fill_connect_aruuid(body + 2);
    pn_wr_be16(body + 22, slot);
    pn_wr_be16(body + 24, subslot);
    pn_wr_be16(body + 28, index);
    pn_wr_be32(body + 30, 256);

    uint8_t blocks[64];
    size_t bn = wr_pn_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));

    uint8_t pdu[256];
    memset(pdu, 0, sizeof(pdu));
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, RPC_OP_READ);
    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);

    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = rpc_transact(run, priv, pdu, 80 + stub, resp, sizeof(resp), &rlen);
    int rpc_ok = (rc == 0 && rlen > 80 + 20);

    const uint8_t *im = NULL;
    size_t imlen = 0;
    if (rpc_ok) {
        uint32_t actual = pn_rd_le32(resp + 80 + 16);
        const uint8_t *ndr = resp + 100;
        size_t ndr_len = actual;
        if (100 + ndr_len > rlen) {
            ndr_len = rlen - 100;
        }
        im = ndr;
        imlen = ndr_len;
        /* Record bytes follow IODReadResHeader (0x8009, 64 bytes). */
        if (ndr_len >= 64 && pn_rd_be16(ndr) == PN_BLOCK_IOD_READ_RES) {
            uint16_t block_len = pn_rd_be16(ndr + 2);
            size_t hdr = 4u + (size_t)block_len;
            if (hdr <= ndr_len) {
                uint32_t rdlen = pn_rd_be32(ndr + 36);
                if (hdr + (size_t)rdlen > ndr_len) {
                    rdlen = (uint32_t)(ndr_len - hdr);
                }
                im = ndr + hdr;
                imlen = rdlen;
            }
        }
    }

    int out = 0;
    out |= ctt_check(run, idx, action, rpc_ok,
                     "rpc Read rlen=%zu rc=%d index=0x%04x", rlen, rc, index);
    if (index == PN_INDEX_IM0 && im) {
        int hdr_ok = imlen >= 8 && pn_rd_be16(im) == PN_BLOCK_IM0;
        uint16_t vendor = hdr_ok ? pn_rd_be16(im + 6) : 0;
        out |= ctt_check(run, idx, action, hdr_ok && vendor == (uint16_t)want_vendor,
                         "I&M0 vendor_id expect=0x%04lx actual=0x%04x (BlockHeader 0x0020)",
                         want_vendor, vendor);
        int has_order = contains(im, imlen, want_order);
        out |= ctt_check(run, idx, action, has_order,
                         "I&M0 order_id expect contains '%s' (index 0xAFF0)",
                         want_order);
    }
    if (expect && yaml_has(expect, "contains") && im) {
        const char *need = yaml_cstr(expect, "contains", "");
        out |= ctt_check(run, idx, action, contains(im, imlen, need),
                         "record contains '%s' index=0x%04x", need, index);
    }
    if (expect && yaml_has(expect, "min_len")) {
        unsigned long minl = yaml_ulong(expect, "min_len", 0);
        out |= ctt_check(run, idx, action, imlen >= minl,
                         "record min_len expect>=%lu actual=%zu index=0x%04x",
                         minl, imlen, index);
    }
    if (expect && yaml_has(expect, "max_len")) {
        unsigned long maxl = yaml_ulong(expect, "max_len", 0);
        out |= ctt_check(run, idx, action, imlen <= maxl,
                         "record max_len expect<=%lu actual=%zu index=0x%04x",
                         maxl, imlen, index);
    }
    if (expect && yaml_has(expect, "absent") && im) {
        const char *need = yaml_cstr(expect, "absent", "");
        out |= ctt_check(run, idx, action, !contains(im, imlen, need),
                         "record must not contain '%s' index=0x%04x", need,
                         index);
    }
    return out;
}

static int step_lldp(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    const char *action = "lldp";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    unsigned long want_et =
        expect ? yaml_ulong(expect, "ethertype", PN_ETHTYPE_LLDP)
               : PN_ETHTYPE_LLDP;
    const char *want_name = expect ? yaml_cstr(expect, "name_of_station",
                                               pn_stack_cfg(priv->stack)
                                                   ->station_name)
                                   : pn_stack_cfg(priv->stack)->station_name;

    ctt_ctl_clear_rx(run);
    pn_stack_send_lldp(priv->stack);
    pump(run, priv);

    int found = 0;
    uint8_t buf[CTT_FRAME_MAX];
    int n = 0;
    int last_n = 0;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) > 0) {
        last_n = n;
        if (n < 14) {
            continue;
        }
        uint16_t et = pn_rd_be16(buf + 12);
        int mc = memcmp(buf, k_lldp_mc, 6) == 0;
        if (et == (uint16_t)want_et && mc &&
            (!want_name || contains(buf, (size_t)n, want_name))) {
            found = 1;
            last_n = n;
            break;
        }
    }
    int rc = ctt_check(run, idx, action, found,
                       "expect LLDP et=0x%04lx dst=01:80:C2:00:00:0E name=%s",
                       want_et, want_name ? want_name : "(any)");
    rc |= finish_eth_step(run, step, idx, action, found, buf, (size_t)last_n);
    return rc;
}

static int step_snmp_get(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                         int idx)
{
    const char *action = "snmp_get";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *want_name =
        expect ? yaml_cstr(expect, "sysName",
                           pn_stack_cfg(priv->stack)->station_name)
               : pn_stack_cfg(priv->stack)->station_name;

    /* SNMPv1 GET sysName (1.3.6.1.2.1.1.5.0). DUT ignores the PDU body. */
    static const uint8_t k_get[] = {
        0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c,
        0x69, 0x63, 0xa0, 0x1a, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x00,
        0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06,
        0x01, 0x02, 0x01, 0x01, 0x05, 0x00, 0x05, 0x00};

    uint8_t resp[512];
    size_t rlen = 0;
    int rc = snmp_transact(run, priv, k_get, sizeof(k_get), resp, sizeof(resp),
                           &rlen);
    int ok = (rc == 0 && rlen > 0);
    static const uint8_t k_oid[] = {0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05,
                                    0x00};
    int has_oid = 0;
    if (ok && rlen >= sizeof(k_oid)) {
        for (size_t i = 0; i + sizeof(k_oid) <= rlen; i++) {
            if (memcmp(resp + i, k_oid, sizeof(k_oid)) == 0) {
                has_oid = 1;
                break;
            }
        }
    }
    int has_name = ok && want_name && contains(resp, rlen, want_name);
    int out = 0;
    out |= ctt_check(run, idx, action, ok, "snmp handle rc=%d rlen=%zu", rc,
                     rlen);
    out |= ctt_check(run, idx, action, has_oid,
                     "expect sysName OID 1.3.6.1.2.1.1.5.0 in GetResponse");
    out |= ctt_check(run, idx, action, has_name, "expect sysName=%s",
                     want_name ? want_name : "(any)");
    return out;
}

/* Mock soak does not send O→T. Refresh CMI with a Read so a 2 s
 * controller-activity timeout does not drop the AR. Production watchdog
 * still keys off controller RPC / O→T, not our RTC1 TX. */
static void soak_refresh_cmi(ctt_run_t *run, pn_priv_t *priv)
{
    uint8_t body[34];
    memset(body, 0, sizeof(body));
    pn_wr_be16(body, 1);
    fill_connect_aruuid(body + 2);
    pn_wr_be16(body + 22, 0);
    pn_wr_be16(body + 24, 1);
    pn_wr_be16(body + 28, PN_INDEX_IM0);
    pn_wr_be32(body + 30, 64);
    uint8_t blocks[80];
    size_t bn = wr_pn_block(blocks, PN_BLOCK_IOD_READ_REQ, body, sizeof(body));
    uint8_t pdu[256];
    memset(pdu, 0, sizeof(pdu));
    stamp_pnio_cl_req(pdu);
    pn_wr_le16(pdu + 68, RPC_OP_READ);
    size_t stub = ndr_wrap(pdu + 80, blocks, bn);
    pn_wr_le16(pdu + 74, (uint16_t)stub);
    uint8_t resp[512];
    size_t rlen = 0;
    (void)rpc_transact(run, priv, pdu, 80 + stub, resp, sizeof(resp), &rlen);
}

static int step_soak(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                     int idx)
{
    const char *action = "soak";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    unsigned duration_s = ctt_step_duration_s(run, step);
    int iterations =
        yaml_has(step, "iterations") ? (int)yaml_long(step, "iterations", 0) : 0;
    unsigned cycle_ms = (unsigned)yaml_long(step, "cycle_ms", 8);
    int min_frames = expect && yaml_has(expect, "min_frames")
                         ? (int)yaml_long(expect, "min_frames", 0)
                         : 0;
    unsigned want_unexp =
        expect ? (unsigned)yaml_ulong(expect, "unexpected_frames", 0) : 0;
    unsigned want_drops =
        expect ? (unsigned)yaml_ulong(expect, "ar_drops", 0) : 0;
    long period_max_ms =
        expect && yaml_has(expect, "period_max_ms")
            ? yaml_long(expect, "period_max_ms", 20)
            : -1;

    if (!duration_s && !iterations) {
        iterations = 32;
    }
    if (!pn_stack_ar_up(priv->stack)) {
        ctt_failf(run, idx, action, "AR not up; Connect first (RTC1 soak)");
        return -1;
    }

    ctt_ctl_clear_rx(run);
    ctt_metrics_t before = run->metrics;
    unsigned unexp_before = run->metrics.unexpected_frames;
    unsigned drops_before = run->metrics.ar_drops;
    unsigned rtc1_before = run->metrics.rtc1_frames;

    int got = 0;
    uint64_t last_ts = 0;
    uint64_t start = ctt_now_ns();
    uint64_t deadline =
        duration_s ? start + (uint64_t)duration_s * 1000000000ull
                   : start + (uint64_t)iterations * (uint64_t)cycle_ms *
                                 1000000ull * 8ull;
    if (!duration_s && deadline - start < 250000000ull) {
        deadline = start + 250000000ull;
    }

    ctt_cycle_clock_t clk;
    ctt_cycle_clock_init(&clk, (uint64_t)cycle_ms * 1000000ull);
    uint64_t last_cmi_refresh = start;
    while (ctt_now_ns() < deadline) {
        if (!duration_s && iterations > 0 && got >= iterations) {
            break;
        }
        if (ctt_now_ns() - last_cmi_refresh >= 1000000000ull) {
            soak_refresh_cmi(run, priv);
            last_cmi_refresh = ctt_now_ns();
        }
        pump(run, priv);
        drain_io_frames(run, &got, &last_ts, PN_ETHTYPE_PN, 1, NULL,
                        rtc1_data_len(priv), NULL);
        if (!pn_stack_ar_up(priv->stack)) {
            run->metrics.ar_drops++;
            break;
        }
        ctt_cycle_clock_wait(&clk);
    }
    /* catch frames that arrived on the last poll */
    pump(run, priv);
    drain_io_frames(run, &got, &last_ts, PN_ETHTYPE_PN, 1, NULL,
                    rtc1_data_len(priv), NULL);

    unsigned unexp = run->metrics.unexpected_frames - unexp_before;
    unsigned drops = run->metrics.ar_drops - drops_before;
    unsigned rtc1 = run->metrics.rtc1_frames - rtc1_before;
    if (min_frames <= 0) {
        min_frames = iterations > 0 ? iterations : 1;
    }

    int out = 0;
    out |= ctt_check(run, idx, action, rtc1 >= (unsigned)min_frames,
                     "soak rtc1 expect>=%d actual=%u duration_s=%u iterations=%d",
                     min_frames, rtc1, duration_s, iterations);
    out |= ctt_check(run, idx, action, unexp <= want_unexp,
                     "unexpected_frames expect<=%u actual=%u", want_unexp,
                     unexp);
    out |= ctt_check(run, idx, action, drops <= want_drops,
                     "ar_drops expect<=%u actual=%u", want_drops, drops);
    if (period_max_ms >= 0 && run->metrics.period_samples > before.period_samples) {
        long max_ms = (long)(run->metrics.period_max_ns / 1000000ull);
        out |= ctt_check(run, idx, action, max_ms <= period_max_ms,
                         "period_max_ms expect<=%ld actual=%ld (mock soft)",
                         period_max_ms, max_ms);
    }
    out |= check_cyclic_expect(run, &before, expect, idx, action, (int)rtc1);
    return out;
}

static int parse_data_field(const yaml_node_t *step, uint8_t *buf, size_t cap,
                            size_t *n)
{
    const char *ascii = yaml_cstr(step, "data", NULL);
    const char *hex = yaml_cstr(step, "data_hex", NULL);
    if (ascii && ascii[0]) {
        *n = strlen(ascii);
        if (*n > cap) {
            *n = cap;
        }
        memcpy(buf, ascii, *n);
        return 0;
    }
    if (hex && hex[0]) {
        return parse_hex_buf(hex, buf, cap, n);
    }
    return -1;
}

static int step_write_input(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "write_input";
    uint8_t buf[PN_IO_MAX];
    size_t n = 0;
    if (parse_data_field(step, buf, sizeof(buf), &n) != 0 || n == 0) {
        ctt_failf(run, idx, action, "missing data or data_hex");
        return -1;
    }
    size_t off = (size_t)yaml_ulong(step, "offset", 0);
    int wr = pn_stack_write_input(priv->stack, off, buf, n);
    return ctt_check(run, idx, action, wr == 0, "write_input rc=%d n=%zu off=%zu",
                     wr, n, off);
}

static int step_read_output(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "read_output";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    size_t n = (size_t)yaml_ulong(step, "length", 8);
    if (n > PN_IO_MAX) {
        n = PN_IO_MAX;
    }
    uint8_t buf[PN_IO_MAX];
    memset(buf, 0, sizeof(buf));
    int rd = pn_stack_read_output(priv->stack, 0, buf, n);
    int out = ctt_check(run, idx, action, rd == 0, "read_output rc=%d", rd);
    if (expect && yaml_has(expect, "u8")) {
        unsigned long want = yaml_ulong(expect, "u8", 0);
        out |= ctt_check(run, idx, action, rd == 0 && buf[0] == (uint8_t)want,
                         "output[0] expect=0x%02lx actual=0x%02x", want, buf[0]);
    }
    if (expect && yaml_has(expect, "data")) {
        const char *s = yaml_cstr(expect, "data", "");
        size_t sl = strlen(s);
        out |= ctt_check(run, idx, action,
                         rd == 0 && sl <= n && memcmp(buf, s, sl) == 0,
                         "output data mismatch");
    }
    return out;
}

static int step_read_input(ctt_run_t *run, pn_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "read_input";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    size_t n = (size_t)yaml_ulong(step, "length", 32);
    if (n > PN_IO_MAX) {
        n = PN_IO_MAX;
    }
    uint8_t buf[PN_IO_MAX];
    memset(buf, 0, sizeof(buf));
    int rd = pn_stack_read_input(priv->stack, 0, buf, n);
    int out = ctt_check(run, idx, action, rd == 0, "read_input rc=%d", rd);
    if (expect && yaml_has(expect, "data")) {
        const char *s = yaml_cstr(expect, "data", "");
        size_t sl = strlen(s);
        out |= ctt_check(run, idx, action,
                         rd == 0 && sl <= n && memcmp(buf, s, sl) == 0,
                         "input data mismatch");
    }
    if (expect && yaml_has(expect, "contains")) {
        const char *s = yaml_cstr(expect, "contains", "");
        out |= ctt_check(run, idx, action, rd == 0 && contains(buf, n, s),
                         "input contains '%s'", s);
    }
    return out;
}

static int step_dcp_inject(ctt_run_t *run, pn_priv_t *priv,
                           const yaml_node_t *step, int idx)
{
    const char *action = "dcp_inject";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const char *hex = yaml_cstr(step, "payload_hex", NULL);
    uint8_t pay[512];
    size_t plen = 0;
    if (!hex || parse_hex_buf(hex, pay, sizeof(pay), &plen) != 0 || plen == 0) {
        ctt_failf(run, idx, action, "need payload_hex");
        return -1;
    }
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    const char *before = cfg->station_name;
    char saved[PN_STATION_NAME_MAX + 1];
    snprintf(saved, sizeof(saved), "%s", before);

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, plen);
    ctt_ctl_clear_rx(run);
    inject_eth(run, priv, frame, flen);

    const pn_cfg_t *got = pn_stack_cfg(priv->stack);
    int out = 0;
    if (expect && yaml_has(expect, "station_name")) {
        const char *want = yaml_cstr(expect, "station_name", saved);
        out |= ctt_check(run, idx, action, strcmp(got->station_name, want) == 0,
                         "station_name expect=%s actual=%s (malformed DCP)",
                         want, got->station_name);
    } else {
        out |= ctt_check(run, idx, action,
                         strcmp(got->station_name, saved) == 0,
                         "malformed DCP must not change NameOfStation "
                         "was=%s now=%s",
                         saved, got->station_name);
    }
    if (expect && yaml_has(expect, "station_name_len")) {
        unsigned long want_n = yaml_ulong(expect, "station_name_len", 0);
        size_t got_n = strlen(got->station_name);
        out |= ctt_check(run, idx, action, got_n == (size_t)want_n,
                         "station_name_len expect=%lu actual=%zu", want_n,
                         got_n);
    }
    return out;
}

static int step_rt_output(ctt_run_t *run, pn_priv_t *priv,
                          const yaml_node_t *step, int idx)
{
    const char *action = "rt_output";
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    uint16_t data_len = cfg->output_len ? cfg->output_len : 8;
    uint8_t data[PN_IO_MAX];
    memset(data, 0x5A, sizeof(data));
    size_t n = 0;
    if (parse_data_field(step, data, sizeof(data), &n) == 0 && n > 0) {
        data_len = (uint16_t)n;
    }
    if (yaml_has(step, "fill")) {
        memset(data, (int)yaml_ulong(step, "fill", 0x5A), data_len);
    }
    uint16_t fid = (uint16_t)yaml_ulong(step, "frame_id", 0x8002);

    uint8_t pay[PN_FRAME_MAX];
    size_t pn = 0;
    pn_wr_be16(pay, fid);
    pn += 2;
    memcpy(pay + pn, data, data_len);
    pn += data_len;
    pay[pn++] = PN_IOPS_GOOD;
    pn_wr_be16(pay + pn, 1);
    pn += 2;
    pay[pn++] = (uint8_t)(PN_DATASTATUS_PRIMARY | PN_DATASTATUS_VALID |
                          PN_DATASTATUS_RUN);
    pay[pn++] = 0;

    uint8_t frame[PN_FRAME_MAX];
    size_t flen = pn_eth_build(frame, sizeof(frame), cfg->mac, priv->ctl_mac,
                               PN_ETHTYPE_PN, pay, pn);
    inject_eth(run, priv, frame, flen);

    uint8_t got[PN_IO_MAX];
    memset(got, 0, sizeof(got));
    int rd = pn_stack_read_output(priv->stack, 0, got, data_len);
    int out = 0;
    int consumed = (rd == 0 && memcmp(got, data, data_len) == 0);
    if (expect && yaml_has(expect, "consumed")) {
        int want = yaml_bool(expect, "consumed", 1);
        out |= ctt_check(run, idx, action, consumed == want,
                         "consumed expect=%s actual=%s rd=%d (AR %s)",
                         want ? "true" : "false", consumed ? "true" : "false",
                         rd, pn_stack_ar_up(priv->stack) ? "up" : "down");
    }
    if (expect && yaml_has(expect, "u8")) {
        unsigned long want = yaml_ulong(expect, "u8", 0);
        out |= ctt_check(run, idx, action, rd == 0 && got[0] == (uint8_t)want,
                         "output[0] expect=0x%02lx actual=0x%02x", want, got[0]);
    }
    if (!expect) {
        out |= ctt_check(run, idx, action, consumed,
                         "RTC1 output not consumed rd=%d", rd);
    }
    return out;
}

static int pn_setup(ctt_run_t *run)
{
    const yaml_node_t *dev = yaml_map_get(run->root, "device");
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    const char *iface = dev ? yaml_cstr(dev, "iface", "mock") : "mock";
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET) {
        if (!run->opts.iface[0] || !run->opts.dut_iface[0]) {
            LOG_ERROR("ctt_pn",
                      "transport=af_packet needs --iface and --dut-iface "
                      "(see tests/run_ctt_lab.sh)");
            return -EINVAL;
        }
        {
            size_t nlen = strlen(run->opts.dut_iface);
            if (nlen >= sizeof(cfg.iface)) {
                LOG_ERROR("ctt_pn", "dut-iface name too long for IFNAMSIZ");
                return -ENAMETOOLONG;
            }
            memcpy(cfg.iface, run->opts.dut_iface, nlen + 1);
        }
    } else {
        if (strcmp(iface, "mock") != 0) {
            LOG_ERROR("ctt_pn",
                      "iface=%s needs --transport=af_packet (CI default is mock)",
                      iface);
            return -EINVAL;
        }
        snprintf(cfg.iface, sizeof(cfg.iface), "mock");
    }

    const char *sta = dev ? yaml_cstr(dev, "station_name", NULL) : NULL;
    if (sta) {
        snprintf(cfg.station_name, sizeof(cfg.station_name), "%s", sta);
    }
    cfg.security_class = dev ? (int)yaml_long(dev, "security_class", 0) : 0;
    if (dev && yaml_has(dev, "cycle_us")) {
        cfg.cycle_us = (uint32_t)yaml_ulong(dev, "cycle_us", 8000);
    }
    if (dev && yaml_has(dev, "input_len")) {
        cfg.input_len = (uint16_t)yaml_ulong(dev, "input_len", 32);
    }
    if (dev && yaml_has(dev, "output_len")) {
        cfg.output_len = (uint16_t)yaml_ulong(dev, "output_len", 8);
    }
    if (dev && yaml_has(dev, "ip")) {
        if (parse_ipv4(yaml_cstr(dev, "ip", "0.0.0.0"), &cfg.ip) != 0) {
            LOG_ERROR("ctt_pn", "device.ip must be dotted IPv4");
            return -EINVAL;
        }
    }
    if (dev && yaml_has(dev, "netmask")) {
        (void)parse_ipv4(yaml_cstr(dev, "netmask", "255.255.255.0"),
                         &cfg.netmask);
    }
    if (dev && yaml_has(dev, "gateway")) {
        (void)parse_ipv4(yaml_cstr(dev, "gateway", "0.0.0.0"), &cfg.gateway);
    }

    pn_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -ENOMEM;
    }
    priv->udp_rpc = -1;
    priv->udp_rpc_listen = -1;
    priv->udp_snmp = -1;
    priv->dut_ip = cfg.ip;

    const char *psk_hex = dev ? yaml_cstr(dev, "psk_hex", NULL) : NULL;
    if (psk_hex) {
        if (parse_hex_bytes(psk_hex, priv->psk, PN_PSK_LEN) != 0) {
            LOG_ERROR("ctt_pn", "device.psk_hex must be %d hex chars",
                      PN_PSK_LEN * 2);
            free(priv);
            return -EINVAL;
        }
        memcpy(cfg.psk, priv->psk, PN_PSK_LEN);
        cfg.psk_set = 1;
        priv->psk_set = 1;
    }

    if (ctt_transport_open(run) != 0) {
        free(priv);
        return -EIO;
    }
    memcpy(priv->ctl_mac, run->ctl_mac, 6);

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        LOG_ERROR("ctt_pn", "pn_stack_create failed");
        ctt_transport_close(run);
        free(priv);
        return -ENOMEM;
    }
    priv->stack = s;
    run->priv = priv;

    {
        const pn_cfg_t *got = pn_stack_cfg(s);
        uint64_t cycle_ns = (uint64_t)got->cycle_us * 1000ull;
        if (cycle_ns == 0) {
            cycle_ns = 8000000ull;
        }
        ctt_metrics_set_cycle_ns(&run->metrics, cycle_ns);
    }

    if (run->opts.transport == CTT_TRANSPORT_MOCK) {
        pn_eth_ops_t ops = {.send = ctt_mock_run_send,
                            .recv = ctt_mock_run_recv,
                            .ctx = run};
        pn_stack_set_eth_ops(s, ops);
    }
    if (pn_stack_start(s) != 0) {
        LOG_ERROR("ctt_pn", "pn_stack_start failed (iface=%s)", cfg.iface);
        return -EIO;
    }
    if (run->opts.transport == CTT_TRANSPORT_AF_PACKET && priv->dut_ip != 0) {
        priv->udp_rpc = udp_ephemeral();
        priv->udp_snmp = udp_ephemeral();
        priv->udp_rpc_listen = udp_bind_port(PN_RPC_PORT);
        if (priv->udp_rpc_listen < 0) {
            LOG_WARN("ctt_pn",
                     "lab UDP %d bind failed (%d) — ApplicationReady receive "
                     "falls back to the CM client socket",
                     PN_RPC_PORT, priv->udp_rpc_listen);
            priv->udp_rpc_listen = -1;
        }
        if (priv->udp_rpc < 0 || priv->udp_snmp < 0) {
            LOG_WARN("ctt_pn",
                     "lab UDP sockets failed — CM/SNMP will not use :34964/:161");
            if (priv->udp_rpc_listen >= 0) {
                close(priv->udp_rpc_listen);
                priv->udp_rpc_listen = -1;
            }
            if (priv->udp_rpc >= 0) {
                close(priv->udp_rpc);
                priv->udp_rpc = -1;
            }
            if (priv->udp_snmp >= 0) {
                close(priv->udp_snmp);
                priv->udp_snmp = -1;
            }
        } else {
            LOG_INFO("ctt_pn",
                     "lab UDP CM/SNMP enabled dut=%u.%u.%u.%u :%d :%d",
                     (priv->dut_ip >> 24) & 0xff, (priv->dut_ip >> 16) & 0xff,
                     (priv->dut_ip >> 8) & 0xff, priv->dut_ip & 0xff,
                     PN_RPC_PORT, PN_SNMP_PORT);
        }
    }
    return 0;
}

static void pn_teardown(ctt_run_t *run)
{
    pn_priv_t *priv = run->priv;
    if (priv) {
        if (priv->udp_rpc >= 0) {
            close(priv->udp_rpc);
            priv->udp_rpc = -1;
        }
        if (priv->udp_rpc_listen >= 0) {
            close(priv->udp_rpc_listen);
            priv->udp_rpc_listen = -1;
        }
        if (priv->udp_snmp >= 0) {
            close(priv->udp_snmp);
            priv->udp_snmp = -1;
        }
        if (priv->stack) {
            pn_stack_destroy(priv->stack);
        }
        free(priv);
        run->priv = NULL;
    }
    ctt_transport_close(run);
}

static int pn_step(ctt_run_t *run, const yaml_node_t *step, int index)
{
    pn_priv_t *priv = run->priv;
    const char *action = yaml_cstr(step, "action", "");
    if (strcmp(action, "dcp_identify") == 0) {
        return step_dcp_identify(run, priv, step, index);
    }
    if (strcmp(action, "dcp_set") == 0) {
        return step_dcp_set(run, priv, step, index);
    }
    if (strcmp(action, "dcp_get") == 0) {
        return step_dcp_get(run, priv, step, index);
    }
    if (strcmp(action, "dcp_set_ip") == 0) {
        return step_dcp_set_ip(run, priv, step, index);
    }
    if (strcmp(action, "dcp_signal") == 0) {
        return step_dcp_signal(run, priv, step, index);
    }
    if (strcmp(action, "dcp_hello") == 0) {
        return step_dcp_hello(run, priv, step, index);
    }
    if (strcmp(action, "dcp_inject") == 0) {
        return step_dcp_inject(run, priv, step, index);
    }
    if (strcmp(action, "rpc_connect") == 0) {
        return step_rpc_connect(run, priv, step, index);
    }
    if (strcmp(action, "io_cycle") == 0) {
        return step_io_cycle(run, priv, step, index);
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
    if (strcmp(action, "rt_output") == 0) {
        return step_rt_output(run, priv, step, index);
    }
    if (strcmp(action, "rpc_release") == 0) {
        return step_rpc_release(run, priv, step, index);
    }
    if (strcmp(action, "rpc_inject") == 0) {
        return step_rpc_inject(run, priv, step, index);
    }
    if (strcmp(action, "rpc_write") == 0) {
        return step_rpc_write(run, priv, step, index);
    }
    if (strcmp(action, "rpc_control") == 0) {
        return step_rpc_control(run, priv, step, index);
    }
    if (strcmp(action, "rpc_application_ready") == 0) {
        return step_rpc_application_ready(run, priv, step, index);
    }
    if (strcmp(action, "alarm") == 0) {
        return step_alarm(run, priv, step, index);
    }
    if (strcmp(action, "record_read") == 0) {
        return step_record_read(run, priv, step, index);
    }
    if (strcmp(action, "lldp") == 0) {
        return step_lldp(run, priv, step, index);
    }
    if (strcmp(action, "snmp_get") == 0) {
        return step_snmp_get(run, priv, step, index);
    }
    if (strcmp(action, "soak") == 0) {
        return step_soak(run, priv, step, index);
    }
    ctt_failf(run, index, action,
              "unknown action (profinet CC-B: dcp_identify, dcp_get, dcp_set, "
              "dcp_set_ip, dcp_signal, dcp_hello, dcp_inject, rpc_connect, "
              "rpc_write, rpc_control, rpc_application_ready, rpc_release, "
              "rpc_inject, write_input, read_input, read_output, rt_output, "
              "io_cycle, alarm, record_read, lldp, snmp_get, soak; CC-C/IRT "
              "never in scope)");
    return -1;
}

const ctt_plugin_t ctt_plugin_profinet = {
    .name = "profinet",
    .setup = pn_setup,
    .step = pn_step,
    .teardown = pn_teardown,
};
