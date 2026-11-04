#include "pn_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "logger.h"
#include "pn_endian.h"

static const uint8_t k_dcp_mc[6] = {0x01, 0x0E, 0xCF, 0x00, 0x00, 0x00};

static void nvm_capture_baseline(pn_stack_t *s);
static void nvm_install_file(pn_stack_t *s);

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
    s->cfg.nvm_dir[sizeof(s->cfg.nvm_dir) - 1] = '\0';
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
    nvm_capture_baseline(s);
    if (s->cfg.nvm_dir[0]) {
        nvm_install_file(s);
    }
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

/* Config fills any field the loaded image does not store, then the
 * stored bits replace it. A partial file (or a rejected sibling file)
 * therefore keeps the config value instead of zero. */
static void nvm_take(pn_stack_t *s, const pn_nvm_image_t *loaded)
{
    nvm_seed(s);
    if (loaded->present & PN_NVM_NAME) {
        memcpy(s->nvm.station_name, loaded->station_name,
               sizeof(s->nvm.station_name));
        s->nvm.station_name[PN_STATION_NAME_MAX] = '\0';
    }
    if (loaded->present & PN_NVM_IP) {
        s->nvm.ip = loaded->ip;
        s->nvm.netmask = loaded->netmask;
        s->nvm.gateway = loaded->gateway;
    }
    if (loaded->present & PN_NVM_IM) {
        memcpy(s->nvm.im1_function, loaded->im1_function, PN_IM1_FUNC_LEN);
        memcpy(s->nvm.im1_location, loaded->im1_location, PN_IM1_LOC_LEN);
        memcpy(s->nvm.im2_date, loaded->im2_date, PN_IM2_DATE_LEN);
        memcpy(s->nvm.im3_desc, loaded->im3_desc, PN_IM3_DESC_LEN);
        memcpy(s->nvm.im4_sig, loaded->im4_sig, PN_IM4_SIG_LEN);
    }
    s->nvm.present = loaded->present;
    nvm_apply(s);
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

static void nvm_capture_baseline(pn_stack_t *s)
{
    memcpy(s->nvm_base_name, s->cfg.station_name, sizeof(s->nvm_base_name));
    s->nvm_base_name[PN_STATION_NAME_MAX] = '\0';
    s->nvm_base_ip = s->cfg.ip;
    s->nvm_base_mask = s->cfg.netmask;
    s->nvm_base_gw = s->cfg.gateway;
    memcpy(s->nvm_base_im1f, s->im1_function, PN_IM1_FUNC_LEN);
    memcpy(s->nvm_base_im1l, s->im1_location, PN_IM1_LOC_LEN);
    memcpy(s->nvm_base_im2, s->im2_date, PN_IM2_DATE_LEN);
    memcpy(s->nvm_base_im3, s->im3_desc, PN_IM3_DESC_LEN);
    memcpy(s->nvm_base_im4, s->im4_sig, PN_IM4_SIG_LEN);
    s->nvm_base_ready = 1;
}

static void nvm_restore_baseline(pn_stack_t *s)
{
    if (!s->nvm_base_ready) {
        return;
    }
    memcpy(s->cfg.station_name, s->nvm_base_name, sizeof(s->cfg.station_name));
    s->cfg.station_name[PN_STATION_NAME_MAX] = '\0';
    s->cfg.ip = s->nvm_base_ip;
    s->cfg.netmask = s->nvm_base_mask;
    s->cfg.gateway = s->nvm_base_gw;
    memcpy(s->im1_function, s->nvm_base_im1f, PN_IM1_FUNC_LEN);
    memcpy(s->im1_location, s->nvm_base_im1l, PN_IM1_LOC_LEN);
    memcpy(s->im2_date, s->nvm_base_im2, PN_IM2_DATE_LEN);
    memcpy(s->im3_desc, s->nvm_base_im3, PN_IM3_DESC_LEN);
    memcpy(s->im4_sig, s->nvm_base_im4, PN_IM4_SIG_LEN);
}

static void nvm_bind(pn_stack_t *s, const pn_nvm_ops_t *ops, int is_file)
{
    s->nvm_ops = *ops;
    s->nvm_on = 1;
    s->nvm_file_active = is_file;
    pn_nvm_image_t loaded;
    memset(&loaded, 0, sizeof(loaded));
    int rc = ops->load(ops->ctx, &loaded);
    if (rc == 0) {
        nvm_take(s, &loaded);
        return;
    }
    if (rc < 0) {
        LOG_WARN("pn_stack", "nvm load 실패 (%d) — config 사용", rc);
    }
    nvm_seed(s);
}

static void nvm_clear(pn_stack_t *s)
{
    memset(&s->nvm_ops, 0, sizeof(s->nvm_ops));
    s->nvm_on = 0;
    s->nvm_file_active = 0;
    memset(&s->nvm, 0, sizeof(s->nvm));
}

_Static_assert(PN_NVM_FILE_HDR_LEN + PN_NVM_IP_PAYLOAD_LEN + 4u <= 512,
               "pn-ip.bin fits the encode buffer");
_Static_assert(PN_NVM_FILE_HDR_LEN + PN_NVM_IM_PAYLOAD_LEN + 4u <= 512,
               "pn-im.bin fits the encode buffer");

static uint32_t nvm_crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int b = 0; b < 8; b++) {
            uint32_t mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static int nvm_join(const char *dir, const char *name, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= cap) {
        return -ENAMETOOLONG;
    }
    return 0;
}

static int nvm_write_full(int fd, const uint8_t *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, p + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (w == 0) {
            return -EIO;
        }
        off += (size_t)w;
    }
    return 0;
}

/* Temp file in the same directory, fsync, then rename. A power loss
 * leaves either the previous file or the temp name, never a short
 * pn-ip.bin / pn-im.bin. */
static int nvm_write_file(const char *dir, const char *filename,
                          const char magic[4], uint16_t version,
                          const uint8_t *payload, uint32_t len)
{
    char path[512];
    char tmp[512];
    char tmpname[64];
    uint8_t buf[512];
    size_t total = PN_NVM_FILE_HDR_LEN + (size_t)len + 4u;
    if (!dir || !dir[0] || !filename || !magic || (!payload && len) ||
        total > sizeof(buf)) {
        return -EINVAL;
    }
    int jn = snprintf(tmpname, sizeof(tmpname), "%s.tmp", filename);
    if (jn < 0 || (size_t)jn >= sizeof(tmpname)) {
        return -ENAMETOOLONG;
    }
    if (nvm_join(dir, filename, path, sizeof(path)) != 0 ||
        nvm_join(dir, tmpname, tmp, sizeof(tmp)) != 0) {
        return -ENAMETOOLONG;
    }
    memcpy(buf, magic, 4);
    pn_wr_le16(buf + 4, version);
    pn_wr_le32(buf + 6, len);
    if (len) {
        memcpy(buf + PN_NVM_FILE_HDR_LEN, payload, len);
    }
    pn_wr_le32(buf + PN_NVM_FILE_HDR_LEN + len,
               nvm_crc32(buf, PN_NVM_FILE_HDR_LEN + len));

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        LOG_ERROR("pn_stack", "nvm %s 임시 파일 실패 (%d)", filename, errno);
        return -errno;
    }
    int rc = nvm_write_full(fd, buf, total);
    if (rc == 0 && fsync(fd) != 0) {
        rc = -errno;
    }
    if (close(fd) != 0 && rc == 0) {
        rc = -errno;
    }
    if (rc != 0) {
        unlink(tmp);
        LOG_ERROR("pn_stack", "nvm %s 쓰기 실패 (%d)", filename, rc);
        return rc;
    }
    if (rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        LOG_ERROR("pn_stack", "nvm %s rename 실패 (%d)", filename, e);
        return -e;
    }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        if (fsync(dfd) != 0) {
            LOG_WARN("pn_stack", "nvm dir fsync 실패 (%d)", errno);
        }
        close(dfd);
    }
    return 0;
}

static int nvm_unlink_file(const char *dir, const char *filename)
{
    char path[512];
    if (nvm_join(dir, filename, path, sizeof(path)) != 0) {
        return -ENAMETOOLONG;
    }
    if (unlink(path) != 0 && errno != ENOENT) {
        LOG_ERROR("pn_stack", "nvm %s 삭제 실패 (%d)", filename, errno);
        return -errno;
    }
    return 0;
}

/* 0 = payload filled, 1 = no file, -1 = rejected (already logged). */
static int nvm_read_record(const char *dir, const char *filename,
                           const char magic[4], uint8_t *payload,
                           uint32_t expect_len)
{
    char path[512];
    if (nvm_join(dir, filename, path, sizeof(path)) != 0) {
        LOG_WARN("pn_stack", "nvm %s 무시 (경로가 김) — config 사용", filename);
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) {
            return 1;
        }
        LOG_WARN("pn_stack", "nvm %s 무시 (열기 실패 %d) — config 사용",
                 filename, errno);
        return -1;
    }
    uint8_t buf[512];
    size_t n = 0;
    int too_big = 0;
    while (n < sizeof(buf)) {
        ssize_t r = read(fd, buf + n, sizeof(buf) - n);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            int e = errno;
            close(fd);
            LOG_WARN("pn_stack", "nvm %s 무시 (읽기 실패 %d) — config 사용",
                     filename, e);
            return -1;
        }
        if (r == 0) {
            break;
        }
        n += (size_t)r;
    }
    if (n == sizeof(buf)) {
        uint8_t extra;
        ssize_t r = read(fd, &extra, 1);
        if (r > 0) {
            too_big = 1;
        }
    }
    close(fd);
    if (too_big || n < PN_NVM_FILE_HDR_LEN + 4u) {
        LOG_WARN("pn_stack", "nvm %s 무시 (잘린 파일) — config 사용", filename);
        return -1;
    }
    if (memcmp(buf, magic, 4) != 0) {
        LOG_WARN("pn_stack", "nvm %s 무시 (매직 불일치) — config 사용",
                 filename);
        return -1;
    }
    uint32_t len = pn_rd_le32(buf + 6);
    if ((size_t)PN_NVM_FILE_HDR_LEN + (size_t)len + 4u != n) {
        LOG_WARN("pn_stack", "nvm %s 무시 (길이 불일치) — config 사용",
                 filename);
        return -1;
    }
    uint32_t crc = pn_rd_le32(buf + PN_NVM_FILE_HDR_LEN + len);
    if (crc != nvm_crc32(buf, PN_NVM_FILE_HDR_LEN + len)) {
        LOG_WARN("pn_stack", "nvm %s 무시 (CRC 불일치) — config 사용",
                 filename);
        return -1;
    }
    uint16_t ver = pn_rd_le16(buf + 4);
    if (ver != PN_NVM_FILE_VERSION) {
        LOG_WARN("pn_stack", "nvm %s 무시 (버전 불일치 %u) — config 사용",
                 filename, ver);
        return -1;
    }
    if (len != expect_len) {
        LOG_WARN("pn_stack", "nvm %s 무시 (길이 불일치) — config 사용",
                 filename);
        return -1;
    }
    memcpy(payload, buf + PN_NVM_FILE_HDR_LEN, expect_len);
    return 0;
}

static int nvm_file_load(void *ctx, pn_nvm_image_t *out)
{
    const char *dir = ctx;
    if (!dir || !dir[0] || !out) {
        return 1;
    }
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        LOG_WARN("pn_stack", "nvm_dir '%s' 없음 — config 사용", dir);
        return -ENOENT;
    }
    memset(out, 0, sizeof(*out));
    uint8_t ipb[PN_NVM_IP_PAYLOAD_LEN];
    int ip = nvm_read_record(dir, PN_NVM_FILE_IP, "PNIP", ipb, sizeof(ipb));
    if (ip == 0) {
        uint32_t present = pn_rd_le32(ipb) & (PN_NVM_NAME | PN_NVM_IP);
        size_t off = 4;
        if (present & PN_NVM_NAME) {
            memcpy(out->station_name, ipb + off, PN_STATION_NAME_MAX + 1);
            out->station_name[PN_STATION_NAME_MAX] = '\0';
            out->present |= PN_NVM_NAME;
        }
        off += PN_STATION_NAME_MAX + 1u;
        if (present & PN_NVM_IP) {
            out->ip = pn_rd_le32(ipb + off);
            out->netmask = pn_rd_le32(ipb + off + 4);
            out->gateway = pn_rd_le32(ipb + off + 8);
            out->present |= PN_NVM_IP;
        }
    }
    uint8_t imb[PN_NVM_IM_PAYLOAD_LEN];
    int im = nvm_read_record(dir, PN_NVM_FILE_IM, "PNIM", imb, sizeof(imb));
    if (im == 0) {
        size_t off = 0;
        memcpy(out->im1_function, imb + off, PN_IM1_FUNC_LEN);
        off += PN_IM1_FUNC_LEN;
        memcpy(out->im1_location, imb + off, PN_IM1_LOC_LEN);
        off += PN_IM1_LOC_LEN;
        memcpy(out->im2_date, imb + off, PN_IM2_DATE_LEN);
        off += PN_IM2_DATE_LEN;
        memcpy(out->im3_desc, imb + off, PN_IM3_DESC_LEN);
        off += PN_IM3_DESC_LEN;
        memcpy(out->im4_sig, imb + off, PN_IM4_SIG_LEN);
        out->present |= PN_NVM_IM;
    }
    if (ip == 0 || im == 0) {
        return 0;
    }
    return 1;
}

static int nvm_file_save(void *ctx, const pn_nvm_image_t *image)
{
    const char *dir = ctx;
    if (!dir || !image) {
        return -EINVAL;
    }
    int rc = 0;
    if (image->present & (PN_NVM_NAME | PN_NVM_IP)) {
        uint8_t ipb[PN_NVM_IP_PAYLOAD_LEN];
        memset(ipb, 0, sizeof(ipb));
        pn_wr_le32(ipb, image->present & (PN_NVM_NAME | PN_NVM_IP));
        memcpy(ipb + 4, image->station_name, PN_STATION_NAME_MAX + 1);
        size_t off = 4u + PN_STATION_NAME_MAX + 1u;
        pn_wr_le32(ipb + off, image->ip);
        pn_wr_le32(ipb + off + 4, image->netmask);
        pn_wr_le32(ipb + off + 8, image->gateway);
        int w = nvm_write_file(dir, PN_NVM_FILE_IP, "PNIP", PN_NVM_FILE_VERSION,
                               ipb, sizeof(ipb));
        if (w != 0) {
            rc = w;
        }
    } else {
        int u = nvm_unlink_file(dir, PN_NVM_FILE_IP);
        if (u != 0) {
            rc = u;
        }
    }
    if (image->present & PN_NVM_IM) {
        uint8_t imb[PN_NVM_IM_PAYLOAD_LEN];
        size_t off = 0;
        memcpy(imb + off, image->im1_function, PN_IM1_FUNC_LEN);
        off += PN_IM1_FUNC_LEN;
        memcpy(imb + off, image->im1_location, PN_IM1_LOC_LEN);
        off += PN_IM1_LOC_LEN;
        memcpy(imb + off, image->im2_date, PN_IM2_DATE_LEN);
        off += PN_IM2_DATE_LEN;
        memcpy(imb + off, image->im3_desc, PN_IM3_DESC_LEN);
        off += PN_IM3_DESC_LEN;
        memcpy(imb + off, image->im4_sig, PN_IM4_SIG_LEN);
        int w = nvm_write_file(dir, PN_NVM_FILE_IM, "PNIM", PN_NVM_FILE_VERSION,
                               imb, sizeof(imb));
        if (w != 0) {
            rc = w;
        }
    } else {
        int u = nvm_unlink_file(dir, PN_NVM_FILE_IM);
        if (u != 0) {
            rc = u;
        }
    }
    return rc;
}

static int nvm_file_erase(void *ctx)
{
    int a = nvm_unlink_file(ctx, PN_NVM_FILE_IP);
    int b = nvm_unlink_file(ctx, PN_NVM_FILE_IM);
    return a != 0 ? a : b;
}

static void nvm_install_file(pn_stack_t *s)
{
    pn_nvm_ops_t ops = {
        .load = nvm_file_load,
        .save = nvm_file_save,
        .erase = nvm_file_erase,
        .ctx = s->cfg.nvm_dir,
    };
    nvm_bind(s, &ops, 1);
}

void pn_stack_set_nvm_ops(pn_stack_t *s, const pn_nvm_ops_t *ops)
{
    if (!s) {
        return;
    }
    int was_file = s->nvm_file_active;
    if (!ops || !ops->load || !ops->save || !ops->erase) {
        if (s->cfg.nvm_dir[0]) {
            nvm_restore_baseline(s);
            nvm_install_file(s);
            return;
        }
        nvm_clear(s);
        return;
    }
    if (was_file) {
        nvm_restore_baseline(s);
    }
    nvm_bind(s, ops, 0);
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
