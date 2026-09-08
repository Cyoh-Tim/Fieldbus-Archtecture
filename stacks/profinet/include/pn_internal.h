#ifndef PN_INTERNAL_H
#define PN_INTERNAL_H

#include "pn_stack.h"

#include <pthread.h>

typedef struct {
    uint16_t slot;
    uint16_t subslot;
    uint16_t frame_off;
} pn_iocr_obj_t;

typedef struct {
    uint16_t type;
    uint16_t reference;
    uint16_t data_len; /* C_SDU length (data + IOPS + IOCS) */
    uint16_t frame_id;
    uint16_t send_clock;
    uint16_t reduction;
    uint16_t watchdog;
    uint16_t datahold;
    uint16_t vlan_id;
    uint8_t pcp;
    uint8_t n_data;
    uint8_t n_iocs;
    pn_iocr_obj_t data[PN_IOBJ_MAX];
    pn_iocr_obj_t iocs[PN_IOBJ_MAX];
} pn_iocr_t;

typedef struct {
    uint16_t slot;
    uint16_t subslot;
    uint16_t channel;
    uint16_t properties;
    uint16_t error_type;
    uint16_t ext_error;
    uint32_t ext_add;
    uint32_t qualified;
    int present;
} pn_diag_ch_t;

typedef struct {
    uint16_t slot;
    uint16_t subslot;
    uint16_t in_len;
    uint16_t out_len;
    uint16_t in_pi;
    uint16_t out_pi;
    uint32_t module_ident;
    uint32_t submodule_ident;
    uint8_t iops_len;
    uint8_t iocs_len;
} pn_submod_t;

typedef struct {
    uint8_t uuid[PN_UUID_LEN];
    uint8_t initiator_uuid[PN_UUID_LEN];
    uint16_t session_key;
    uint16_t in_frame_id;
    uint16_t out_frame_id;
    uint16_t in_data_len;  /* user data bytes in process image */
    uint16_t out_data_len;
    uint16_t send_clock_factor;
    uint16_t reduction_ratio;
    uint16_t watchdog_factor;
    uint8_t initiator_mac[6];
    uint32_t initiator_ip; /* host order */
    uint16_t initiator_udp;
    int cm_state;
    int established; /* DATAEX */
    pn_iocr_t iocr_in;
    pn_iocr_t iocr_out;
    int n_sub;
    pn_submod_t sub[PN_SUBMOD_MAX];
    uint8_t last_rpc_hdr[80];
    int last_rpc_hdr_set;
    int rpc_le;
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
    uint64_t last_cpm_ns;
    uint64_t last_lldp_ns;
    uint64_t last_hello_ns;
    uint64_t start_ns;

    char lldp_rem_name[PN_STATION_NAME_MAX + 1];
    char lldp_rem_port[64];
    char lldp_rem_desc[64];
    uint8_t lldp_rem_mac[6];
    uint8_t lldp_rem_chassis[32];
    uint8_t lldp_rem_chassis_len;
    uint8_t lldp_rem_chassis_subtype;
    uint8_t lldp_rem_port_subtype;
    int lldp_rem_set;
    uint64_t lldp_last_change_ns;

    uint16_t alarm_type;
    uint16_t alarm_peer_ref;
    uint16_t alarm_local_ref;
    uint16_t alarm_max_len;
    uint16_t alarm_tci;
    uint16_t alarm_send_seq;
    int alarm_cr_ok;
    int alarm_rta_sent;
    int alarm_rta_acked;
    int alarm_retries;
    uint64_t last_alarm_ns;
    int diag_present;
    int n_diag;
    pn_diag_ch_t diag[PN_DIAG_MAX];
    int connect_reject;

    char im1_function[32];
    char im1_location[22];
    char im2_date[16];
    char im3_desc[54];
    uint8_t im4_sig[54];
    uint8_t pdport_adjust[PN_PDEV_STORE];
    uint16_t pdport_adjust_len;
    uint8_t pdport_check[PN_PDEV_STORE];
    uint16_t pdport_check_len;
    uint8_t pdif_adjust[PN_PDEV_STORE];
    uint16_t pdif_adjust_len;

    char snmp_syscontact[64];
    char snmp_syslocation[64];
    char snmp_sysname[PN_STATION_NAME_MAX + 1];
    uint32_t if_in_octets;
    uint32_t if_in_ucast;
    uint32_t if_in_discards;
    uint32_t if_in_errors;
    uint32_t if_out_octets;
    uint32_t if_out_ucast;
    uint32_t if_out_discards;
    uint32_t if_out_errors;
    uint32_t snmp_in_pkts;
    uint32_t snmp_out_pkts;
    uint32_t snmp_in_get;
    uint32_t snmp_in_next;
    uint32_t snmp_in_set;
    uint32_t udp_in;
    uint32_t udp_out;
    uint32_t lldp_rem_inserts;

    uint8_t rpc_tx[PN_FRAME_MAX];
    size_t rpc_tx_len;
    uint32_t rpc_tx_ip;
    uint16_t rpc_tx_port;
    int rpc_tx_pending;

    pthread_mutex_t io_lock;
};

uint64_t pn_now_ns(void);
uint64_t pn_ar_cycle_ns(const pn_ar_t *ar, uint32_t fallback_us);
uint64_t pn_ar_watchdog_ns(const pn_ar_t *ar, uint32_t fallback_us);
const pn_submod_t *pn_find_sub(const pn_ar_t *ar, uint16_t slot,
                               uint16_t subslot);
void pn_ar_reset(pn_stack_t *s);

int pn_eth_open(pn_stack_t *s);
void pn_eth_close(pn_stack_t *s);
int pn_eth_send(pn_stack_t *s, const uint8_t *frame, size_t len);
int pn_eth_recv(pn_stack_t *s, uint8_t *frame, size_t cap);
int pn_if_apply_ipv4(const char *iface, uint32_t ip, uint32_t netmask,
                     uint32_t gateway);

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen);
size_t pn_eth_build_vlan(uint8_t *out, size_t cap, const uint8_t dst[6],
                         const uint8_t src[6], uint16_t tci, uint16_t ethertype,
                         const uint8_t *payload, size_t plen);
int pn_eth_parse(const uint8_t *frame, size_t len, const uint8_t **payload,
                 size_t *plen, uint16_t *ethertype, const uint8_t **dst,
                 const uint8_t **src);

void pn_dcp_on_frame(pn_stack_t *s, const uint8_t *src, const uint8_t *payload,
                     size_t plen);
int pn_dcp_verify_set(const pn_stack_t *s, const uint8_t *payload, size_t plen);
void pn_dcp_send_hello(pn_stack_t *s);

void pn_lldp_send(pn_stack_t *s);
void pn_lldp_on_frame(pn_stack_t *s, const uint8_t *src, const uint8_t *payload,
                      size_t plen);

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen);
void pn_rt_send_if_due(pn_stack_t *s);
void pn_rt_watchdog(pn_stack_t *s);

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len);
int pn_rpc_handle_from(pn_stack_t *s, const uint8_t *pdu, size_t len,
                       uint32_t src_ip, uint16_t src_port, uint8_t *resp,
                       size_t cap, size_t *out_len);
void pn_rpc_poll(pn_stack_t *s);
void pn_rpc_flush_tx(pn_stack_t *s);

void pn_snmp_poll(pn_stack_t *s);
int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t n, uint8_t *resp,
                   size_t cap, size_t *out_len);

void pn_alarm_poll(pn_stack_t *s);
void pn_alarm_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen);
void pn_alarm_on_connect(pn_stack_t *s, const uint8_t *body, uint16_t blen);
int pn_udp_open(uint16_t port);
int pn_udp_open_ip(uint32_t ip_host, uint16_t port);

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len);
int pn_record_write(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    uint16_t index, const uint8_t *data, uint32_t len);
void pn_diag_arm_default(pn_stack_t *s);
void pn_if_on_rx(pn_stack_t *s, size_t n);
void pn_if_on_tx(pn_stack_t *s, size_t n);

int pn_sec_hmac(const pn_stack_t *s, const uint8_t *data, size_t len,
                uint8_t mac[PN_HMAC_LEN]);
int pn_sec_ok(const pn_stack_t *s, const uint8_t *data, size_t len,
              const uint8_t mac[PN_HMAC_LEN]);

#endif /* PN_INTERNAL_H */
