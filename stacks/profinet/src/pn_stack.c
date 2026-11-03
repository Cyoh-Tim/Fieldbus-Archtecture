#include "pn_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"
#include "pn_endian.h"

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

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
        s->cfg.cycle_us = 8000;
    }
    if (s->cfg.vendor_id == 0) {
        s->cfg.vendor_id = 0xABCD;
    }
    if (s->cfg.device_id == 0) {
        s->cfg.device_id = 0x0001;
    }
#ifdef PN_ENFORCE_SECURITY_CLASS
    s->cfg.enforce_security_class = 1;
#endif
    if (s->cfg.enforce_security_class) {
        if (s->cfg.security_class < PN_VENDOR_INTEGRITY || !s->cfg.psk_set) {
            LOG_ERROR("pn_stack",
                      "production/enforce_security_class: security_class>=1 "
                      "(vendor integrity extension) 와 psk_hex 가 필요 "
                      "(lab 기본은 enforce=0, security_class 0 허용)");
            free(s);
            return NULL;
        }
    }
    if (!s->cfg.mac_set) {
        /* locally administered default */
        s->cfg.mac[0] = 0x02;
        s->cfg.mac[1] = 0xFB;
        s->cfg.mac[2] = 0x00;
        s->cfg.mac[3] = 0x00;
        s->cfg.mac[4] = 0x00;
        s->cfg.mac[5] = 0x01;
        s->cfg.mac_set = 1;
    }
    pthread_mutex_init(&s->io_lock, NULL);
    memset(s->input_image, 0, sizeof(s->input_image));
    memset(s->output_image, 0, sizeof(s->output_image));
    memset(s->im1_function, ' ', sizeof(s->im1_function));
    memset(s->im1_location, ' ', sizeof(s->im1_location));
    memset(s->im2_date, ' ', sizeof(s->im2_date));
    memset(s->im3_desc, ' ', sizeof(s->im3_desc));
    memset(s->im4_sig, 0, sizeof(s->im4_sig));
    s->start_ns = pn_now_ns();
    return s;
}

void pn_stack_destroy(pn_stack_t *s)
{
    if (!s) {
        return;
    }
    pn_stack_stop(s);
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

int pn_stack_start(pn_stack_t *s)
{
    int rc = pn_eth_open(s);
    if (rc != 0 && !s->use_eth_ops) {
        return rc;
    }
    if (!s->use_eth_ops) {
        s->fd_rpc = pn_udp_open(PN_RPC_PORT);
        if (s->fd_rpc < 0) {
            LOG_WARN("pn_stack", "RPC UDP %d bind 실패 (%d)", PN_RPC_PORT,
                     s->fd_rpc);
            s->fd_rpc = -1;
        }
        s->fd_snmp = pn_udp_open(PN_SNMP_PORT);
        if (s->fd_snmp < 0) {
            LOG_WARN("pn_stack", "SNMP UDP bind 실패 — CC-B neighbor 는 제한됨");
            s->fd_snmp = -1;
        }
    }
    s->running = 1;
    LOG_INFO("pn_stack",
             "start CC-B RT1 sec=%d name=%s iface=%s in=%u out=%u cycle=%uus",
             s->cfg.security_class, s->cfg.station_name,
             s->cfg.iface[0] ? s->cfg.iface : "mock", s->cfg.input_len,
             s->cfg.output_len, s->cfg.cycle_us);
    pn_lldp_send(s);
    s->last_lldp_ns = pn_now_ns();
    return 0;
}

void pn_stack_stop(pn_stack_t *s)
{
    s->running = 0;
    s->ar.established = 0;
    pn_eth_close(s);
    if (s->fd_rpc >= 0) {
        close(s->fd_rpc);
        s->fd_rpc = -1;
    }
    if (s->fd_snmp >= 0) {
        close(s->fd_snmp);
        s->fd_snmp = -1;
    }
}

int pn_stack_handle_eth(pn_stack_t *s, const uint8_t *frame, size_t len)
{
    const uint8_t *payload, *dst, *src;
    size_t plen;
    uint16_t et;
    if (pn_eth_parse(frame, len, &payload, &plen, &et, &dst, &src) != 0) {
        return -EINVAL;
    }
    int ours = memcmp(dst, s->cfg.mac, 6) == 0;
    int dcp_mc = memcmp(dst, k_dcp_mc, 6) == 0;
    if (et == PN_ETHTYPE_PN && plen >= 2) {
        uint16_t fid = pn_rd_be16(payload);
        if (fid == PN_FRAMEID_DCP_ID_REQ || fid == PN_FRAMEID_DCP_GETSET ||
            fid == PN_FRAMEID_DCP_HELLO) {
            if (ours || dcp_mc) {
                pn_dcp_on_frame(s, src, payload, plen);
            }
        } else if (ours) {
            pn_rt_on_frame(s, payload, plen);
        }
        return 0;
    }
    if (et == PN_ETHTYPE_LLDP) {
        return 0;
    }
    return 0;
}

int pn_stack_handle_rpc(pn_stack_t *s, const uint8_t *udp_payload, size_t len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return pn_rpc_handle(s, udp_payload, len, resp, resp_cap, resp_len, 0);
}

int pn_stack_handle_snmp(pn_stack_t *s, const uint8_t *req, size_t len,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
    return pn_snmp_handle(s, req, len, resp, resp_cap, resp_len);
}

int pn_stack_send_alarm(pn_stack_t *s)
{
    return pn_alarm_send_dummy(s, PN_FRAMEID_ALARM_HIGH);
}

int pn_stack_send_alarm_ex(pn_stack_t *s, uint16_t frame_id)
{
    return pn_alarm_send_dummy(s, frame_id);
}

void pn_stack_send_lldp(pn_stack_t *s)
{
    pn_lldp_send(s);
    s->last_lldp_ns = pn_now_ns();
}

void pn_stack_send_hello(pn_stack_t *s)
{
    pn_dcp_send_hello(s);
}

int pn_stack_app_ready(const pn_stack_t *s)
{
    return s && s->ar.app_ready;
}

int pn_stack_take_rpc_tx(pn_stack_t *s, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!s || !out || !out_len) {
        return -EINVAL;
    }
    if (s->pending_rpc_tx_len == 0) {
        *out_len = 0;
        return -EAGAIN;
    }
    if (s->pending_rpc_tx_len > cap) {
        return -ENOSPC;
    }
    memcpy(out, s->pending_rpc_tx, s->pending_rpc_tx_len);
    *out_len = s->pending_rpc_tx_len;
    s->pending_rpc_tx_len = 0;
    s->pending_rpc_tx_ns = 0;
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
    pn_rpc_poll(s);
    pn_snmp_poll(s);
    pn_dcp_poll(s);
    pn_alarm_poll(s);
    pn_ar_watchdog(s);
    pn_rt_send_if_due(s);

    uint64_t now = pn_now_ns();
    if (now - s->last_lldp_ns > 5000000000ull) {
        pn_lldp_send(s);
        s->last_lldp_ns = now;
    }
}

int pn_stack_ar_up(const pn_stack_t *s)
{
    return s && s->ar.established;
}

int pn_stack_read_output(pn_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (off + len > s->cfg.output_len) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(dst, s->output_image + off, len);
    pthread_mutex_unlock(&s->io_lock);
    return 0;
}

int pn_stack_read_input(pn_stack_t *s, size_t off, uint8_t *dst, size_t len)
{
    if (off + len > s->cfg.input_len) {
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
    if (off + len > s->cfg.input_len) {
        return -EINVAL;
    }
    pthread_mutex_lock(&s->io_lock);
    memcpy(s->input_image + off, src, len);
    pthread_mutex_unlock(&s->io_lock);
    return 0;
}

_Static_assert(sizeof(((pn_nvm_image_t *)0)->im1_function) == PN_IM1_FUNC_LEN,
               "nvm I&M1 function");
_Static_assert(sizeof(((pn_nvm_image_t *)0)->im1_location) == PN_IM1_LOC_LEN,
               "nvm I&M1 location");
_Static_assert(sizeof(((pn_nvm_image_t *)0)->im2_date) == PN_IM2_DATE_LEN,
               "nvm I&M2");
_Static_assert(sizeof(((pn_nvm_image_t *)0)->im3_desc) == PN_IM3_DESC_LEN,
               "nvm I&M3");
_Static_assert(sizeof(((pn_nvm_image_t *)0)->im4_sig) == PN_IM4_SIG_LEN,
               "nvm I&M4");

static void nvm_copy_im_from_stack(pn_stack_t *s)
{
    memcpy(s->nvm.im1_function, s->im1_function, PN_IM1_FUNC_LEN);
    memcpy(s->nvm.im1_location, s->im1_location, PN_IM1_LOC_LEN);
    memcpy(s->nvm.im2_date, s->im2_date, PN_IM2_DATE_LEN);
    memcpy(s->nvm.im3_desc, s->im3_desc, PN_IM3_DESC_LEN);
    memcpy(s->nvm.im4_sig, s->im4_sig, PN_IM4_SIG_LEN);
}

static void nvm_im_factory(pn_nvm_image_t *img)
{
    memset(img->im1_function, ' ', sizeof(img->im1_function));
    memset(img->im1_location, ' ', sizeof(img->im1_location));
    memset(img->im2_date, ' ', sizeof(img->im2_date));
    memset(img->im3_desc, ' ', sizeof(img->im3_desc));
    memset(img->im4_sig, 0, sizeof(img->im4_sig));
}

/* Power-on baseline: user config is the nonvolatile ASE until a Set saves
 * it (p-net copies pnet_cfg into cmina_nonvolatile before the first file
 * write). present stays 0 so a missing file does not override config. */
static void nvm_seed(pn_stack_t *s)
{
    memset(&s->nvm, 0, sizeof(s->nvm));
    memcpy(s->nvm.station_name, s->cfg.station_name, sizeof(s->nvm.station_name));
    s->nvm.station_name[PN_STATION_NAME_MAX] = '\0';
    s->nvm.ip = s->cfg.ip;
    s->nvm.netmask = s->cfg.netmask;
    s->nvm.gateway = s->cfg.gateway;
    nvm_copy_im_from_stack(s);
}

static void nvm_apply(pn_stack_t *s)
{
    if (s->nvm.present & PN_NVM_NAME) {
        memcpy(s->cfg.station_name, s->nvm.station_name,
               sizeof(s->cfg.station_name));
        s->cfg.station_name[PN_STATION_NAME_MAX] = '\0';
    }
    if (s->nvm.present & PN_NVM_IP) {
        s->cfg.ip = s->nvm.ip;
        s->cfg.netmask = s->nvm.netmask;
        s->cfg.gateway = s->nvm.gateway;
        pn_os_apply_configured_ip(s);
    }
    if (s->nvm.present & PN_NVM_IM) {
        memcpy(s->im1_function, s->nvm.im1_function, PN_IM1_FUNC_LEN);
        memcpy(s->im1_location, s->nvm.im1_location, PN_IM1_LOC_LEN);
        memcpy(s->im2_date, s->nvm.im2_date, PN_IM2_DATE_LEN);
        memcpy(s->im3_desc, s->nvm.im3_desc, PN_IM3_DESC_LEN);
        memcpy(s->im4_sig, s->nvm.im4_sig, PN_IM4_SIG_LEN);
    }
    LOG_INFO("pn_stack", "nvm load present=0x%x name=%s", s->nvm.present,
             (s->nvm.present & PN_NVM_NAME) ? s->cfg.station_name : "(cfg)");
}

static int nvm_save(pn_stack_t *s)
{
    int rc = s->nvm_ops.save(s->nvm_ops.ctx, &s->nvm);
    if (rc != 0) {
        LOG_ERROR("pn_stack", "nvm save 실패 (%d)", rc);
    }
    return rc;
}

static int nvm_erase(pn_stack_t *s)
{
    int rc = s->nvm_ops.erase(s->nvm_ops.ctx);
    if (rc != 0) {
        LOG_ERROR("pn_stack", "nvm erase 실패 (%d)", rc);
    }
    memset(&s->nvm, 0, sizeof(s->nvm));
    return rc;
}

void pn_stack_set_nvm_ops(pn_stack_t *s, const pn_nvm_ops_t *ops)
{
    if (!s) {
        return;
    }
    if (!ops || !ops->load || !ops->save || !ops->erase) {
        memset(&s->nvm_ops, 0, sizeof(s->nvm_ops));
        s->nvm_on = 0;
        memset(&s->nvm, 0, sizeof(s->nvm));
        return;
    }
    s->nvm_ops = *ops;
    s->nvm_on = 1;
    pn_nvm_image_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    int rc = ops->load(ops->ctx, &loaded);
    if (rc == 0) {
        s->nvm = loaded;
        s->nvm.station_name[PN_STATION_NAME_MAX] = '\0';
        nvm_apply(s);
        return;
    }
    if (rc < 0) {
        LOG_WARN("pn_stack", "nvm load 실패 (%d) — config 사용", rc);
    }
    nvm_seed(s);
}

void pn_stack_set_os_ip_fn(pn_stack_t *s, pn_os_apply_ip_fn fn, void *ctx)
{
    if (!s) {
        return;
    }
    s->os_ip_fn = fn;
    s->os_ip_ctx = ctx;
}

void pn_os_apply_configured_ip(pn_stack_t *s)
{
    if (!s || !s->cfg.apply_os_ip) {
        return;
    }
    int rc;
    if (s->os_ip_fn) {
        rc = s->os_ip_fn(s->os_ip_ctx, s->cfg.iface, s->cfg.ip, s->cfg.netmask,
                         s->cfg.gateway);
    } else {
        rc = pn_os_apply_ip_default(s->cfg.iface, s->cfg.ip, s->cfg.netmask,
                                    s->cfg.gateway);
    }
    if (rc != 0) {
        LOG_ERROR("pn_dcp", "OS IP 적용 실패 (%d) iface=%s", rc,
                  s->cfg.iface[0] ? s->cfg.iface : "(none)");
        return;
    }
    LOG_INFO("pn_dcp", "OS IP 적용 %u.%u.%u.%u", (s->cfg.ip >> 24) & 0xff,
             (s->cfg.ip >> 16) & 0xff, (s->cfg.ip >> 8) & 0xff, s->cfg.ip & 0xff);
}

void pn_nvm_after_name(pn_stack_t *s, int permanent)
{
    if (!s || !s->nvm_on) {
        return;
    }
    if (permanent) {
        memcpy(s->nvm.station_name, s->cfg.station_name,
               sizeof(s->nvm.station_name));
        s->nvm.station_name[PN_STATION_NAME_MAX] = '\0';
    } else {
        memset(s->nvm.station_name, 0, sizeof(s->nvm.station_name));
    }
    /* One ASE file: the first name or IP Set stores both fields. */
    s->nvm.present |= PN_NVM_NAME | PN_NVM_IP;
    nvm_save(s);
}

void pn_nvm_after_ip(pn_stack_t *s, int permanent)
{
    if (!s || !s->nvm_on) {
        return;
    }
    if (permanent) {
        s->nvm.ip = s->cfg.ip;
        s->nvm.netmask = s->cfg.netmask;
        s->nvm.gateway = s->cfg.gateway;
    } else {
        s->nvm.ip = 0;
        s->nvm.netmask = 0;
        s->nvm.gateway = 0;
    }
    s->nvm.present |= PN_NVM_NAME | PN_NVM_IP;
    nvm_save(s);
}

void pn_nvm_after_im(pn_stack_t *s)
{
    if (!s || !s->nvm_on) {
        return;
    }
    nvm_copy_im_from_stack(s);
    s->nvm.present |= PN_NVM_IM;
    nvm_save(s);
}

void pn_nvm_after_reset(pn_stack_t *s, int clear_comm, int clear_im)
{
    if (!s || !s->nvm_on || (!clear_comm && !clear_im)) {
        return;
    }
    if (clear_comm && clear_im) {
        nvm_erase(s);
        return;
    }
    if (clear_comm) {
        s->nvm.present &= ~(PN_NVM_NAME | PN_NVM_IP);
        memset(s->nvm.station_name, 0, sizeof(s->nvm.station_name));
        s->nvm.ip = 0;
        s->nvm.netmask = 0;
        s->nvm.gateway = 0;
    }
    if (clear_im) {
        s->nvm.present &= ~PN_NVM_IM;
        nvm_im_factory(&s->nvm);
    }
    if (s->nvm.present == 0) {
        nvm_erase(s);
        return;
    }
    nvm_save(s);
}
