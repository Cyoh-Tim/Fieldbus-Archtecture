#ifndef PN_INTERNAL_H
#define PN_INTERNAL_H

#include "pn_stack.h"

#include <pthread.h>

#define PN_TXQ_MAX 8

typedef struct {
    uint8_t data[PN_FRAME_MAX];
    size_t len;
} pn_frame_t;

typedef struct {
    uint8_t uuid[PN_UUID_LEN];
    uint16_t session_key;
    uint16_t in_frame_id;
    uint16_t out_frame_id;
    uint16_t in_data_len;
    uint16_t out_data_len;
    uint16_t send_clock_factor;
    uint16_t reduction_ratio;
    uint8_t initiator_mac[6];
    int established;
} pn_ar_t;

struct pn_stack {
    pn_cfg_t cfg;
    int running;
    int fd_eth;
    int fd_rpc;
    int fd_snmp;
    int ifindex;
    pn_eth_ops_t eth_ops;
    int use_eth_ops;

    pn_ar_t ar;
    uint8_t input_image[PN_IO_MAX];
    uint8_t output_image[PN_IO_MAX];
    uint16_t cycle_counter;
    uint64_t last_rt_ns;
    uint64_t last_lldp_ns;
    uint64_t start_ns;

    uint8_t last_rpc_resp[PN_FRAME_MAX];
    size_t last_rpc_resp_len;

    pthread_mutex_t io_lock;
};

uint64_t pn_now_ns(void);
int pn_eth_open(pn_stack_t *s);
void pn_eth_close(pn_stack_t *s);
int pn_eth_send(pn_stack_t *s, const uint8_t *frame, size_t len);
int pn_eth_recv(pn_stack_t *s, uint8_t *frame, size_t cap);

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen);
int pn_eth_parse(const uint8_t *frame, size_t len, const uint8_t **payload,
                 size_t *plen, uint16_t *ethertype, const uint8_t **dst,
                 const uint8_t **src);

void pn_dcp_on_frame(pn_stack_t *s, const uint8_t *src, const uint8_t *payload,
                     size_t plen);
int pn_dcp_verify_set(const pn_stack_t *s, const uint8_t *payload, size_t plen);

void pn_lldp_send(pn_stack_t *s);

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen);
void pn_rt_send_if_due(pn_stack_t *s);

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len);
void pn_rpc_poll(pn_stack_t *s);

void pn_snmp_poll(pn_stack_t *s);
int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t len, uint8_t *resp,
                   size_t cap, size_t *out_len);
int pn_udp_open(uint16_t port);

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len);

int pn_alarm_send_dummy(pn_stack_t *s);

int pn_sec_hmac(const pn_stack_t *s, const uint8_t *data, size_t len,
                uint8_t mac[PN_HMAC_LEN]);
int pn_sec_ok(const pn_stack_t *s, const uint8_t *data, size_t len,
              const uint8_t mac[PN_HMAC_LEN]);

#endif /* PN_INTERNAL_H */
