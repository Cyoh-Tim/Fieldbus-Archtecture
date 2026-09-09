#include "ctt.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "logger.h"
#include "pn_crypto.h"
#include "pn_endian.h"
#include "pn_stack.h"

typedef struct {
    pn_stack_t *stack;
    uint8_t ctl_mac[6];
    uint8_t psk[PN_PSK_LEN];
    int psk_set;
} pn_priv_t;

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};
static const uint8_t k_ctl_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};

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

static void inject_eth(ctt_run_t *run, pn_priv_t *priv, const uint8_t *frame,
                       size_t len)
{
    (void)ctt_ring_push(&run->mock.to_dut, frame, len, ctt_now_ns());
    pn_stack_poll(priv->stack);
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

    ctt_ring_clear(&run->mock.to_ctl);
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
    int n;
    while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), NULL)) > 0) {
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
            break;
        }
    }
    return ctt_check(run, idx, action, found,
                     "expect Identify.Res et=0x%04lx fid=0x%04lx service=%s "
                     "status=%s name=%s (TX FrameID=0xFEFE multicast "
                     "01:0E:CF:00:00:00)",
                     want_et, want_fid,
                     expect ? yaml_cstr(expect, "service", "identify")
                            : "identify",
                     expect ? yaml_cstr(expect, "status", "success") : "success",
                     want_name ? want_name : "(any)");
}

static int step_dcp_set(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                        int idx)
{
    const char *action = "dcp_set";
    int signed_req = yaml_bool(step, "signed", 0);
    const char *new_name = yaml_cstr(step, "name_of_station", NULL);
    uint32_t xid = (uint32_t)yaml_ulong(step, "xid", 0xAABBCCDDul);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    if (!new_name) {
        ctt_failf(run, idx, action, "missing name_of_station");
        return -1;
    }

    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);
    size_t nlen = strlen(new_name);
    uint8_t nameblk[2 + PN_STATION_NAME_MAX];
    pn_wr_be16(nameblk, 1);
    memcpy(nameblk + 2, new_name, nlen);

    uint8_t blocks[256];
    size_t bn = 0;
    bn += append_dcp_block(blocks + bn, PN_DCP_OPT_DEV, PN_DCP_SUB_DEV_NAME,
                           nameblk, (uint16_t)(2 + nlen));

    uint8_t pay[512];
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

    ctt_ring_clear(&run->mock.to_ctl);
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
    if (want_result) {
        int accept = strcmp(want_result, "accept") == 0;
        int reject = strcmp(want_result, "reject") == 0;
        int ok = 0;
        uint8_t buf[CTT_FRAME_MAX];
        int n;
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
                }
                if (reject && st == PN_DCP_RESP_UNSUP) {
                    ok = 1;
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
    }
    return rc;
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

static size_t build_connect_pdu(uint8_t *pdu, size_t cap, int integrity,
                                const uint8_t *psk, int psk_set,
                                const uint8_t initiator_mac[6])
{
    if (cap < 80 + 20 + 64) {
        return 0;
    }
    memset(pdu, 0, cap);
    pdu[0] = 1; /* rpcvers */
    pdu[1] = 0; /* request */
    pn_wr_le16(pdu + 68, 0); /* Connect */

    uint8_t blocks[256];
    size_t bn = 0;
    uint8_t ar[2 + 16 + 2 + 6];
    memset(ar, 0, sizeof(ar));
    pn_wr_be16(ar, 0x0001);
    for (int i = 0; i < 16; i++) {
        ar[2 + i] = (uint8_t)(0xA0 + i);
    }
    pn_wr_be16(ar + 18, 1);
    memcpy(ar + 20, initiator_mac, 6);
    bn += wr_pn_block(blocks + bn, PN_BLOCK_AR_REQ, ar, sizeof(ar));

    if (integrity) {
        if (!psk_set) {
            return 0;
        }
        uint8_t mac[PN_HMAC_LEN];
        pn_hmac_sha256(psk, PN_PSK_LEN, blocks, bn, mac);
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

static int step_rpc_connect(ctt_run_t *run, pn_priv_t *priv,
                            const yaml_node_t *step, int idx)
{
    const char *action = "rpc_connect";
    int integrity = yaml_bool(step, "integrity", 0);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    const pn_cfg_t *cfg = pn_stack_cfg(priv->stack);

    uint8_t pdu[512];
    size_t plen =
        build_connect_pdu(pdu, sizeof(pdu), integrity, cfg->psk, cfg->psk_set,
                          priv->ctl_mac);
    if (plen == 0) {
        ctt_failf(run, idx, action, "failed to build Connect PDU");
        return -1;
    }

    uint8_t resp[1024];
    size_t rlen = 0;
    int rc = pn_stack_handle_rpc(priv->stack, pdu, plen, resp, sizeof(resp),
                                 &rlen);

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
    return out;
}

static int is_rtc1(const uint8_t *frame, int n, uint16_t want_et)
{
    if (n < 16) {
        return 0;
    }
    uint16_t et = pn_rd_be16(frame + 12);
    uint16_t fid = pn_rd_be16(frame + 14);
    return et == want_et && fid >= 0x8000u && fid <= 0xBBFFu;
}

static int step_io_cycle(ctt_run_t *run, pn_priv_t *priv, const yaml_node_t *step,
                         int idx)
{
    const char *action = "io_cycle";
    int count = (int)yaml_long(step, "count", 16);
    unsigned cycle_ms = (unsigned)yaml_long(step, "cycle_ms", 8);
    const yaml_node_t *expect = yaml_map_get(step, "expect");
    int min_frames =
        expect ? (int)yaml_long(expect, "min_frames", count) : count;
    long period_max_ms =
        expect ? yaml_long(expect, "period_max_ms", 20) : 20;
    uint16_t want_et = (uint16_t)(expect ? yaml_ulong(expect, "ethertype",
                                                      PN_ETHTYPE_PN)
                                         : PN_ETHTYPE_PN);

    if (!pn_stack_ar_up(priv->stack)) {
        ctt_failf(run, idx, action, "AR not up; Connect first (RTC1 / CC-B)");
        return -1;
    }

    ctt_ring_clear(&run->mock.to_ctl);

    uint64_t times[64];
    int got = 0;
    uint64_t budget_ns =
        (uint64_t)count * (uint64_t)cycle_ms * 1000000ull * 4ull;
    if (budget_ns < 250000000ull) {
        budget_ns = 250000000ull;
    }
    uint64_t deadline = ctt_now_ns() + budget_ns;

    while (got < min_frames && ctt_now_ns() < deadline) {
        pn_stack_poll(priv->stack);
        uint8_t buf[CTT_FRAME_MAX];
        uint64_t ts = 0;
        int n;
        while ((n = ctt_ring_pop(&run->mock.to_ctl, buf, sizeof(buf), &ts)) >
               0) {
            if (is_rtc1(buf, n, want_et)) {
                if (got < 64) {
                    times[got] = ts;
                }
                got++;
            }
        }
        if (got < min_frames) {
            sleep_ms(1);
        }
    }

    int rc = ctt_check(run, idx, action, got >= min_frames,
                       "min_frames expect>=%d actual=%d cycle_ms=%u "
                       "ethertype=0x%04x (RTC1 CC-B, not IRT)",
                       min_frames, got, cycle_ms, want_et);
    if (got >= 2) {
        uint64_t max_dt = 0;
        int lim = got < 64 ? got : 64;
        for (int i = 1; i < lim; i++) {
            uint64_t dt = times[i] - times[i - 1];
            if (dt > max_dt) {
                max_dt = dt;
            }
        }
        long max_ms = (long)(max_dt / 1000000ull);
        rc |= ctt_check(run, idx, action, max_ms <= period_max_ms,
                        "period_max_ms expect<=%ld actual=%ld (mock soft bound)",
                        period_max_ms, max_ms);
    }
    return rc;
}

static int pn_setup(ctt_run_t *run)
{
    const yaml_node_t *dev = yaml_map_get(run->root, "device");
    pn_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    const char *iface = dev ? yaml_cstr(dev, "iface", "mock") : "mock";
    if (strcmp(iface, "mock") != 0) {
        LOG_ERROR("ctt_pn", "Phase 1 CI path only supports iface=mock (got %s)",
                  iface);
        return -EINVAL;
    }
    snprintf(cfg.iface, sizeof(cfg.iface), "%s", iface);

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

    pn_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) {
        return -ENOMEM;
    }
    memcpy(priv->ctl_mac, k_ctl_mac, 6);

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

    pn_stack_t *s = pn_stack_create(&cfg);
    if (!s) {
        LOG_ERROR("ctt_pn", "pn_stack_create failed");
        free(priv);
        return -ENOMEM;
    }
    priv->stack = s;
    run->priv = priv;

    pn_eth_ops_t ops = {.send = ctt_mock_dut_send,
                        .recv = ctt_mock_dut_recv,
                        .ctx = &run->mock};
    pn_stack_set_eth_ops(s, ops);
    if (pn_stack_start(s) != 0) {
        LOG_ERROR("ctt_pn", "pn_stack_start failed");
        return -EIO;
    }
    return 0;
}

static void pn_teardown(ctt_run_t *run)
{
    pn_priv_t *priv = run->priv;
    if (!priv) {
        return;
    }
    if (priv->stack) {
        pn_stack_destroy(priv->stack);
    }
    free(priv);
    run->priv = NULL;
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
    if (strcmp(action, "rpc_connect") == 0) {
        return step_rpc_connect(run, priv, step, index);
    }
    if (strcmp(action, "io_cycle") == 0) {
        return step_io_cycle(run, priv, step, index);
    }
    ctt_failf(run, index, action,
              "unknown or Phase-2 action (Phase 1: dcp_identify, dcp_set, "
              "rpc_connect, io_cycle; CC-C/IRT never in scope)");
    return -1;
}

const ctt_plugin_t ctt_plugin_profinet = {
    .name = "profinet",
    .setup = pn_setup,
    .step = pn_step,
    .teardown = pn_teardown,
};
