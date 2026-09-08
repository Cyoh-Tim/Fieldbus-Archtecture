#include "pn_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "pn_endian.h"

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

void pn_ar_reset(pn_stack_t *s)
{
    pthread_mutex_lock(&s->rt_lock);
    memset(&s->ar, 0, sizeof(s->ar));
    pthread_mutex_lock(&s->io_lock);
    memset(s->input_image, 0, sizeof(s->input_image));
    memset(s->output_image, 0, sizeof(s->output_image));
    pthread_mutex_unlock(&s->io_lock);
    s->last_rt_ns = 0;
    s->next_rt_ns = 0;
    s->last_cpm_ns = 0;
    s->rt_tx_last_ns = 0;
    s->rt_tx_sum = 0;
    s->rt_tx_min = ~0ull;
    s->rt_tx_max = 0;
    s->rt_tx_late_max = 0;
    s->rt_tx_n = 0;
    s->rt_tx_logged = 0;
    pthread_mutex_unlock(&s->rt_lock);
    s->rpc_tx_pending = 0;
    s->rpc_tx_len = 0;
    s->alarm_peer_ref = 0;
    s->alarm_cr_ok = 0;
    s->alarm_rta_sent = 0;
    s->alarm_rta_acked = 1;
    s->alarm_send_seq = 0;
    s->alarm_retries = 0;
    s->last_alarm_ns = 0;
    s->alarm_local_ref = 1;
    s->alarm_max_len = 200;
    s->alarm_kind = -1;
    s->alarm_timeout_ns = 200000000ull;
    s->alarm_max_retry = 3;
    s->diag_present = 0;
    s->n_diag = 0;
    memset(s->diag, 0, sizeof(s->diag));
    s->connect_reject = 0;
}

uint16_t pn_rr_from_cycle_us(uint16_t send_clock, uint32_t cycle_us)
{
    static const uint16_t k_rr[] = {8, 16, 32, 64, 128, 256, 512};
    uint32_t sc = send_clock ? send_clock : PN_SENDCLOCK_DEFAULT;
    uint32_t want = cycle_us;
    if (want < PN_CYCLE_MIN_US) {
        want = PN_CYCLE_MIN_US;
    }
    if (want > PN_CYCLE_MAX_US) {
        want = PN_CYCLE_MAX_US;
    }
    uint16_t best = PN_REDUCTION_MIN;
    uint32_t best_err = 0xffffffffu;
    for (size_t i = 0; i < sizeof(k_rr) / sizeof(k_rr[0]); i++) {
        uint32_t got_us = (sc * (uint32_t)k_rr[i] * 31250u) / 1000u;
        uint32_t err = got_us > want ? got_us - want : want - got_us;
        if (err < best_err) {
            best_err = err;
            best = k_rr[i];
        }
    }
    return best;
}

uint64_t pn_ar_cycle_ns(const pn_ar_t *ar, uint32_t fallback_us)
{
    uint64_t sc = ar->send_clock_factor ? ar->send_clock_factor
                                       : PN_SENDCLOCK_DEFAULT;
    uint64_t ns = 0;
    if (ar->reduction_ratio != 0) {
        ns = sc * (uint64_t)ar->reduction_ratio * 31250ull;
    }
    if (ns == 0) {
        uint32_t us = fallback_us ? fallback_us : PN_CYCLE_MIN_US;
        ns = (uint64_t)us * 1000ull;
    }
    if (ns < (uint64_t)PN_CYCLE_MIN_US * 1000ull) {
        ns = (uint64_t)PN_CYCLE_MIN_US * 1000ull;
    }
    if (ns > (uint64_t)PN_CYCLE_MAX_US * 1000ull) {
        ns = (uint64_t)PN_CYCLE_MAX_US * 1000ull;
    }
    return ns;
}

uint64_t pn_ar_watchdog_ns(const pn_ar_t *ar, uint32_t fallback_us)
{
    uint64_t wf = ar->watchdog_factor ? ar->watchdog_factor : 3;
    return pn_ar_cycle_ns(ar, fallback_us) * wf;
}

const pn_submod_t *pn_find_sub(const pn_ar_t *ar, uint16_t slot,
                               uint16_t subslot)
{
    for (int i = 0; i < ar->n_sub; i++) {
        if (ar->sub[i].slot == slot && ar->sub[i].subslot == subslot) {
            return &ar->sub[i];
        }
    }
    return NULL;
}

void pn_if_on_rx(pn_stack_t *s, size_t n)
{
    if (!s) {
        return;
    }
    s->if_in_octets += (uint32_t)n;
    s->if_in_ucast++;
}

void pn_if_on_tx(pn_stack_t *s, size_t n)
{
    if (!s) {
        return;
    }
    s->if_out_octets += (uint32_t)n;
    s->if_out_ucast++;
}

pn_stack_t *pn_stack_create(const pn_cfg_t *cfg)
{
    if (!cfg) {
        return NULL;
    }
    pn_stack_t *s = calloc(1, sizeof(*s));
    if (!s) {
        return NULL;
    }
    s->cfg = *cfg;
    s->fd_eth = -1;
    s->fd_rpc = -1;
    s->fd_snmp = -1;
    if (!s->cfg.device_type[0]) {
        snprintf(s->cfg.device_type, sizeof(s->cfg.device_type),
                 "Fieldbus PN Device");
    }
    if (!s->cfg.station_name[0]) {
        snprintf(s->cfg.station_name, sizeof(s->cfg.station_name), "pn-device");
    }
    if (s->cfg.input_len == 0) {
        s->cfg.input_len = 32;
    }
    if (s->cfg.output_len == 0) {
        s->cfg.output_len = 8;
    }
    if (s->cfg.input_len > PN_IO_MAX) {
        s->cfg.input_len = PN_IO_MAX;
    }
    if (s->cfg.output_len > PN_IO_MAX) {
        s->cfg.output_len = PN_IO_MAX;
    }
    if (s->cfg.cycle_us == 0) {
        s->cfg.cycle_us = PN_CYCLE_MIN_US;
    }
    if (s->cfg.cycle_us < PN_CYCLE_MIN_US) {
        LOG_WARN("pn_stack", "cycle_us=%u below 8 ms min, clamping",
                 s->cfg.cycle_us);
        s->cfg.cycle_us = PN_CYCLE_MIN_US;
    }
    if (s->cfg.cycle_us > PN_CYCLE_MAX_US) {
        LOG_WARN("pn_stack", "cycle_us=%u above 512 ms max, clamping",
                 s->cfg.cycle_us);
        s->cfg.cycle_us = PN_CYCLE_MAX_US;
    }
    if (s->cfg.vendor_id == 0) {
        s->cfg.vendor_id = 0xABCD;
    }
    if (s->cfg.device_id == 0) {
        s->cfg.device_id = 0x0001;
    }
    if (!s->cfg.mac_set) {
        s->cfg.mac[0] = 0x02;
        s->cfg.mac[1] = 0xFB;
        s->cfg.mac[2] = 0x00;
        s->cfg.mac[3] = 0x00;
        s->cfg.mac[4] = 0x00;
        s->cfg.mac[5] = 0x01;
        s->cfg.mac_set = 1;
    }
    pthread_mutex_init(&s->io_lock, NULL);
    pthread_mutex_init(&s->rt_lock, NULL);
    memset(s->input_image, 0, sizeof(s->input_image));
    memset(s->output_image, 0, sizeof(s->output_image));
    memset(s->im1_function, ' ', sizeof(s->im1_function));
    memset(s->im1_location, ' ', sizeof(s->im1_location));
    memcpy(s->im2_date, "2020-01-01 00:00", 16);
    memset(s->im3_desc, ' ', sizeof(s->im3_desc));
    s->start_ns = pn_now_ns();
    s->lldp_last_change_ns = s->start_ns;
    s->alarm_local_ref = 1;
    s->alarm_max_len = 200;
    s->alarm_kind = -1;
    s->alarm_rta_acked = 1;
    s->alarm_timeout_ns = 200000000ull;
    s->alarm_max_retry = 3;
    return s;
}

void pn_stack_destroy(pn_stack_t *s)
{
    if (!s) {
        return;
    }
    pn_stack_stop(s);
    pthread_mutex_destroy(&s->rt_lock);
    pthread_mutex_destroy(&s->io_lock);
    free(s);
}

void pn_stack_set_eth_ops(pn_stack_t *s, pn_eth_ops_t ops)
{
    s->eth_ops = ops;
    s->use_eth_ops = 1;
}

const pn_cfg_t *pn_stack_cfg(const pn_stack_t *s)
{
    return &s->cfg;
}

int pn_stack_lldp_remote_name(const pn_stack_t *s, char *out, size_t cap)
{
    if (!s || !out || cap == 0) {
        return -EINVAL;
    }
    if (!s->lldp_rem_set || !s->lldp_rem_name[0]) {
        out[0] = '\0';
        return -ENOENT;
    }
    snprintf(out, cap, "%s", s->lldp_rem_name);
    return 0;
}

static void close_udp(pn_stack_t *s)
{
    if (s->fd_rpc >= 0) {
        close(s->fd_rpc);
        s->fd_rpc = -1;
    }
    if (s->fd_snmp >= 0) {
        close(s->fd_snmp);
        s->fd_snmp = -1;
    }
}

static int open_one_udp(uint32_t ip, uint16_t port)
{
    int fd = pn_udp_open_ip(ip, port);
    if (fd < 0 && ip != 0) {
        fd = pn_udp_open_ip(0, port);
    }
    return fd;
}

int pn_stack_start(pn_stack_t *s)
{
    int rc = pn_eth_open(s);
    if (rc != 0 && !s->use_eth_ops) {
        return rc;
    }
    if (!s->use_eth_ops) {
        /* Bind after the OS address exists; otherwise the unicast IP bind
         * fails and RPC stays dead until a later DCP Set. Fall back to
         * INADDR_ANY if the address is not yet local. */
        if (s->cfg.apply_os_ip && s->cfg.ip) {
            pn_if_apply_ipv4(s->cfg.iface, s->cfg.ip, s->cfg.netmask,
                             s->cfg.gateway);
        }
        s->fd_rpc = open_one_udp(s->cfg.ip, PN_RPC_PORT);
        if (s->fd_rpc < 0) {
            LOG_WARN("pn_stack", "RPC UDP %d bind 실패 (%d)", PN_RPC_PORT,
                     s->fd_rpc);
            s->fd_rpc = -1;
        }
        s->fd_snmp = open_one_udp(s->cfg.ip, PN_SNMP_PORT);
        if (s->fd_snmp < 0) {
            LOG_WARN("pn_stack", "SNMP UDP bind 실패 — neighbor 진단은 제한됨");
            s->fd_snmp = -1;
        }
    }
    s->running = 1;
    pn_rt_thread_start(s);
    LOG_INFO("pn_stack",
             "start RT1 sec=%d name=%s iface=%s in=%u out=%u cycle=%uus",
             s->cfg.security_class, s->cfg.station_name,
             s->cfg.iface[0] ? s->cfg.iface : "mock", s->cfg.input_len,
             s->cfg.output_len, s->cfg.cycle_us);
    pn_lldp_send(s);
    pn_dcp_send_hello(s);
    s->last_lldp_ns = pn_now_ns();
    s->last_hello_ns = s->last_lldp_ns;
    return 0;
}

void pn_stack_rebind_udp(pn_stack_t *s)
{
    if (!s || s->use_eth_ops) {
        return;
    }
    close_udp(s);
    s->fd_rpc = open_one_udp(s->cfg.ip, PN_RPC_PORT);
    if (s->fd_rpc < 0) {
        LOG_WARN("pn_stack", "RPC UDP rebind 실패 (%d)", s->fd_rpc);
        s->fd_rpc = -1;
    }
    s->fd_snmp = open_one_udp(s->cfg.ip, PN_SNMP_PORT);
    if (s->fd_snmp < 0) {
        LOG_WARN("pn_stack", "SNMP UDP rebind 실패");
        s->fd_snmp = -1;
    }
}

void pn_stack_stop(pn_stack_t *s)
{
    s->running = 0;
    pn_rt_thread_stop(s);
    pn_ar_reset(s);
    pn_eth_close(s);
    close_udp(s);
}

int pn_stack_handle_eth(pn_stack_t *s, const uint8_t *frame, size_t len)
{
    const uint8_t *payload, *dst, *src;
    size_t plen;
    uint16_t et;
    if (pn_eth_parse(frame, len, &payload, &plen, &et, &dst, &src) != 0) {
        return -EINVAL;
    }
    pn_if_on_rx(s, len);
    int ours = memcmp(dst, s->cfg.mac, 6) == 0;
    int dcp_mc = memcmp(dst, k_dcp_mc, 6) == 0;
    if (et == PN_ETHTYPE_PN && plen >= 2) {
        uint16_t fid = pn_rd_be16(payload);
        if (fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_GETSET ||
            fid == PN_FRAMEID_DCP_HELLO) {
            if (ours || dcp_mc) {
                pn_dcp_on_frame(s, src, payload, plen);
            }
        } else if (fid == PN_FRAMEID_ALARM_HIGH || fid == PN_FRAMEID_ALARM_LOW) {
            if (ours) {
                pn_alarm_on_frame(s, payload, plen);
            }
        } else if (ours) {
            pn_rt_on_frame(s, payload, plen);
        }
        return 0;
    }
    if (et == PN_ETHTYPE_LLDP) {
        pn_lldp_on_frame(s, src, payload, plen);
        return 0;
    }
    /* MRP is optional CC-B media redundancy, not CC-C IRT. Not implemented.
     * Ignore 0x88E3 so a lab flood does not take down RTC1. */
    if (et == PN_ETHTYPE_MRP) {
        return 0;
    }
    return 0;
}

int pn_stack_handle_snmp(pn_stack_t *s, const uint8_t *req, size_t n,
                         uint8_t *resp, size_t cap, size_t *out_len)
{
    return pn_snmp_handle(s, req, n, resp, cap, out_len);
}

int pn_stack_handle_rpc(pn_stack_t *s, const uint8_t *udp_payload, size_t len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return pn_rpc_handle(s, udp_payload, len, resp, resp_cap, resp_len);
}

int pn_stack_handle_rpc_from(pn_stack_t *s, const uint8_t *udp_payload,
                             size_t len, uint32_t src_ip, uint16_t src_port,
                             uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return pn_rpc_handle_from(s, udp_payload, len, src_ip, src_port, resp,
                              resp_cap, resp_len);
}

int pn_stack_take_rpc_tx(pn_stack_t *s, uint8_t *out, size_t cap, size_t *len,
                         uint32_t *dst_ip, uint16_t *dst_port)
{
    if (!s->rpc_tx_pending || s->rpc_tx_len == 0) {
        return -EAGAIN;
    }
    if (cap < s->rpc_tx_len) {
        return -ENOSPC;
    }
    memcpy(out, s->rpc_tx, s->rpc_tx_len);
    *len = s->rpc_tx_len;
    if (dst_ip) {
        *dst_ip = s->rpc_tx_ip;
    }
    if (dst_port) {
        *dst_port = s->rpc_tx_port;
    }
    s->rpc_tx_pending = 0;
    s->rpc_tx_len = 0;
    return 0;
}

void pn_stack_poll(pn_stack_t *s)
{
    if (!s->running) {
        return;
    }
    uint8_t frame[PN_FRAME_MAX];
    for (int i = 0; i < 16; i++) {
        int n = pn_eth_recv(s, frame, sizeof(frame));
        if (n == -EAGAIN) {
            break;
        }
        if (n > 0) {
            pn_stack_handle_eth(s, frame, (size_t)n);
        } else {
            break;
        }
    }
    pn_rpc_flush_tx(s);
    pn_rpc_poll(s);
    pn_snmp_poll(s);
    pn_rt_watchdog(s);
    /* Dedicated RTC1 thread owns cyclic TX. Poll still kicks the first
     * DATAEX frame so AppReady does not wait on the idle 50 us sleep. */
    if (!s->rt_thread_started || s->next_rt_ns == 0) {
        pn_rt_send_if_due(s);
    }
    pn_alarm_poll(s);

    uint64_t now = pn_now_ns();
    if (now - s->last_lldp_ns > 5000000000ull) {
        pn_lldp_send(s);
        s->last_lldp_ns = now;
    }
    if (!s->ar.established && now - s->last_hello_ns > 1000000000ull) {
        pn_dcp_send_hello(s);
        s->last_hello_ns = now;
    }
}

int pn_stack_ar_up(const pn_stack_t *s)
{
    return s && s->ar.established && s->ar.cm_state == PN_CM_DATAEX;
}

int pn_stack_cm_state(const pn_stack_t *s)
{
    return s ? s->ar.cm_state : PN_CM_OFFLINE;
}

static size_t pn_in_cap(const pn_stack_t *s)
{
    size_t n = s->cfg.input_len;
    if (s->ar.in_data_len > n) {
        n = s->ar.in_data_len;
    }
    return n > PN_IO_MAX ? PN_IO_MAX : n;
}

static size_t pn_out_cap(const pn_stack_t *s)
{
    size_t n = s->cfg.output_len;
    if (s->ar.out_data_len > n) {
        n = s->ar.out_data_len;
    }
    return n > PN_IO_MAX ? PN_IO_MAX : n;
}

int pn_stack_io_map(const pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    int output, size_t *base, size_t *mod_len)
{
    if (!s || !base || !mod_len) {
        return -EINVAL;
    }
    const pn_submod_t *sm = pn_find_sub(&s->ar, slot, subslot);
    if (!sm || (!output && !sm->in_len) || (output && !sm->out_len)) {
        return -ENOENT;
    }
    *base = output ? sm->out_pi : sm->in_pi;
    *mod_len = output ? sm->out_len : sm->in_len;
    return 0;
}

int pn_stack_sub_count(const pn_stack_t *s)
{
    return s ? s->ar.n_sub : 0;
}

int pn_stack_sub_info(const pn_stack_t *s, int idx, uint16_t *slot,
                      uint16_t *subslot, uint16_t *in_len, uint16_t *out_len,
                      uint16_t *in_pi, uint16_t *out_pi)
{
    if (!s || idx < 0 || idx >= s->ar.n_sub) {
        return -EINVAL;
    }
    const pn_submod_t *sm = &s->ar.sub[idx];
    if (slot) {
        *slot = sm->slot;
    }
    if (subslot) {
        *subslot = sm->subslot;
    }
    if (in_len) {
        *in_len = sm->in_len;
    }
    if (out_len) {
        *out_len = sm->out_len;
    }
    if (in_pi) {
        *in_pi = sm->in_pi;
    }
    if (out_pi) {
        *out_pi = sm->out_pi;
    }
    return 0;
}

int pn_stack_read_output(pn_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (!s || !dst || len == 0 || off + len > pn_out_cap(s)) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(dst, s->output_image + off, len);
    pthread_mutex_unlock(&s->io_lock);
    return 0;
}

int pn_stack_read_input(pn_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (!s || !dst || len == 0 || off + len > pn_in_cap(s)) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(dst, s->input_image + off, len);
    pthread_mutex_unlock(&s->io_lock);
    return 0;
}

int pn_stack_write_input(pn_stack_t *s, size_t off, const uint8_t *src,
                         size_t len)
{
    if (!s || !src || len == 0 || off + len > pn_in_cap(s)) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(s->input_image + off, src, len);
    pthread_mutex_unlock(&s->io_lock);
    return 0;
}

int pn_stack_diag_appear(pn_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    pn_alarm_request(s, 0);
    return 0;
}

int pn_stack_diag_clear(pn_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    pn_alarm_request(s, 1);
    return 0;
}

int pn_stack_alarm_process(pn_stack_t *s)
{
    if (!s) {
        return -EINVAL;
    }
    pn_alarm_request(s, 2);
    return 0;
}
