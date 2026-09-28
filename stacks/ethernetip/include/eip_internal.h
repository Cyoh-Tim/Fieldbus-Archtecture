#ifndef EIP_INTERNAL_H
#define EIP_INTERNAL_H

#include <pthread.h>
#include <stdint.h>

#include "eip_stack.h"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

typedef struct {
    uint16_t instance;
    uint16_t size;
    uint8_t *data;
    int is_input; /* 1 = produced (T->O), 0 = consumed (O->T) / config */
} eip_assembly_t;

typedef struct {
    int in_use;
    uint32_t o2t_conn_id;
    uint32_t t2o_conn_id;
    uint16_t o2t_size;
    uint16_t t2o_size;
    uint32_t o2t_rpi_us;
    uint32_t t2o_rpi_us;
    uint32_t peer_ip; /* host order */
    uint16_t peer_udp_port;
    uint32_t o2t_seq;
    uint32_t t2o_seq;
    uint64_t last_rx_ns;
    uint64_t last_tx_ns; /* next Class1 produce due (0 = immediately) */
    uint16_t conn_serial;
    uint16_t vendor_id;
    uint32_t originator_serial;
    uint8_t timeout_multiplier;
    uint32_t watchdog_us; /* derived close timeout */
    /* CPF: item count(2) + seq addr(12) + connected hdr(4) + seq(2) + data */
    uint8_t last_produce[20 + EIP_ASSEMBLY_SIZE_MAX];
    size_t last_produce_len;
    int produce_ready;
} eip_class1_conn_t;

typedef struct {
    int fd;
    int active;
    uint32_t session;
    uint8_t rx[EIP_TCP_BUF_MAX];
    size_t rx_len;
} eip_tcp_client_t;

typedef struct {
    int fd;
    int active;
    int hs_done; /* 0 until SSL_accept completes (non-blocking) */
    SSL *ssl;
    uint8_t rx[EIP_TCP_BUF_MAX];
    size_t rx_len;
} eip_tls_client_t;

struct eip_stack {
    eip_cfg_t cfg;
    eip_transport_ops_t tops;
    int tops_set;

    int listen_fd;
    int udp_fd;
    int originator_fd;
    int running;

    uint32_t next_session;
    uint32_t sessions[EIP_CLASS3_SESSIONS_MAX];
    int n_sessions;
    uint32_t next_conn_id;

    eip_tcp_client_t clients[EIP_TCP_CLIENTS_MAX];
    eip_class1_conn_t class1[EIP_CLASS1_CONN_MAX];

    eip_assembly_t assemblies[EIP_ASSEMBLY_INSTANCES_MAX];
    int assembly_count;

    uint8_t *input_data;
    uint16_t input_size;
    uint8_t *output_data;
    uint16_t output_size;
    uint8_t *config_data;
    uint16_t config_size;

    /* CIP Security confidentiality (class >= 2) */
    SSL_CTX *tls_ctx;
    int tls_listen_fd;
    eip_tls_client_t tls_clients[EIP_TLS_CLIENTS_MAX];

    uint16_t config_consistency;
    uint8_t device_state; /* Identity state */

    /* QoS DSCP */
    uint8_t dscp_urgent;
    uint8_t dscp_scheduled;
    uint8_t dscp_high;
    uint8_t dscp_low;
    uint8_t dscp_explicit;

    /* ACD */
    int acd_conflict;
    uint32_t acd_activity; /* bitmask / counter for TCP/IP attr */

    /* LLDP (TX-only profile for first-time cert path) */
    uint32_t lldp_enable_flags;
    uint16_t lldp_tx_interval_sec;
    uint16_t lldp_tx_hold;
    uint32_t lldp_sys_uptime_sec;
    uint32_t lldp_last_change_sec;
    uint8_t lldp_last_frame[512];
    size_t lldp_last_frame_len;
    uint64_t lldp_last_tx_ns;
    uint64_t lldp_uptime_anchor_ns;

    /* Real-time accounting */
    uint64_t last_poll_ns;
    uint64_t max_poll_ns;
    uint32_t class1_timeouts;

    pthread_mutex_t lock;
    char last_error[128];
};

int eip_encap_process(eip_stack_t *s, const uint8_t *req, size_t req_len,
                      uint8_t *resp, size_t resp_cap, size_t *resp_len);

int eip_cip_route(eip_stack_t *s, const uint8_t *req, size_t req_len,
                  uint8_t *resp, size_t resp_cap, size_t *resp_len);

int eip_cm_forward_open(eip_stack_t *s, const uint8_t *data, size_t len,
                        int large, uint8_t *resp, size_t resp_cap,
                        size_t *resp_len);
int eip_cm_forward_close(eip_stack_t *s, const uint8_t *data, size_t len,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len);

int eip_io_handle_udp(eip_stack_t *s, const uint8_t *frame, size_t len,
                      uint32_t src_ip, uint16_t src_port);
void eip_io_produce(eip_stack_t *s);

int eip_assembly_init(eip_stack_t *s);
void eip_assembly_fini(eip_stack_t *s);
eip_assembly_t *eip_assembly_find(eip_stack_t *s, uint16_t instance);
int eip_assembly_read(eip_stack_t *s, uint16_t instance, uint8_t *dst,
                      size_t *inout_len);
int eip_assembly_write(eip_stack_t *s, uint16_t instance, const uint8_t *src,
                       size_t len);

int eip_path_append_class(uint8_t *path, size_t cap, size_t *used,
                          uint16_t class_id);
int eip_path_append_instance(uint8_t *path, size_t cap, size_t *used,
                             uint16_t instance);
int eip_path_append_attribute(uint8_t *path, size_t cap, size_t *used,
                              uint16_t attribute);
int eip_path_append_ansi_tag(uint8_t *path, size_t cap, size_t *used,
                             const char *tag);
int eip_path_parse(const uint8_t *path, size_t path_bytes, uint16_t *class_id,
                   uint16_t *instance, uint16_t *attribute, char *tag,
                   size_t tag_cap);

uint64_t eip_now_ns(void);

/* CIP Vol1: timeout = 4 * RPI * 2^timeout_multiplier. TM=0 is valid (4*RPI). */
static inline uint32_t eip_class1_watchdog_us(uint32_t rpi_us,
                                              uint8_t timeout_mult)
{
    if (rpi_us == 0) {
        rpi_us = 8000;
    }
    unsigned shift = timeout_mult > 7u ? 7u : (unsigned)timeout_mult;
    uint64_t us = (uint64_t)rpi_us * 4ull * (1ull << shift);
    if (us > 0xffffffffull) {
        return 0xffffffffu;
    }
    return (uint32_t)us;
}

/* Class1 watchdog — close stale connections */
void eip_io_watchdog(eip_stack_t *s);

/* LLDP TX-only helpers */
int eip_lldp_build(eip_stack_t *s);
void eip_lldp_poll(eip_stack_t *s);

#endif /* EIP_INTERNAL_H */
