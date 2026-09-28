#ifndef PN_INTERNAL_H
#define PN_INTERNAL_H

#include "pn_stack.h"

#include <pthread.h>
#include <netinet/in.h>

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
    uint16_t send_clock_factor; /* O→T IOCR; 0 = not negotiated */
    uint16_t reduction_ratio;   /* O→T IOCR; 0 = not negotiated */
    uint8_t initiator_mac[6];
    uint8_t initiator_uuid[PN_UUID_LEN]; /* CMInitiatorObjectUUID */
    int have_initiator_uuid;
    uint32_t owner_ip; /* host-order IPv4 of Connect sender; 0 = unset */
    int established;
    int prm_end;
    int app_ready;
    int saw_rt; /* at least one matching O→T RTC1 received */
    uint16_t data_hold_factor; /* 0 = PN_AR_DATA_HOLD_CYCLES */
    uint64_t last_rt_rx_ns;
    uint64_t last_cmi_ns;
} pn_ar_t;

/* CMI activity (2 s) stays armed until the controller shows liveness
 * (O→T RTC1, or PrmEnd / ApplicationReady). Our own RTC1 TX does not
 * count. After liveness, data-hold is factor × negotiated O→T period.
 * Period = SendClockFactor × ReductionRatio × 31.25 µs (output CR).
 * Factor is IOCR DataHoldFactor, else WatchdogFactor, else 3.
 * cfg.cycle_us is not used. A zero SendClockFactor or ReductionRatio
 * leaves data-hold disarmed (no negotiated clock). */
#define PN_SEND_CLOCK_BASE_NS        31250ull
#define PN_AR_DATA_HOLD_CYCLES       3
#define PN_CMI_ACTIVITY_TIMEOUT_NS   2000000000ull

#define PN_IM1_FUNC_LEN 32
#define PN_IM1_LOC_LEN  22
#define PN_IM2_DATE_LEN 16
#define PN_IM3_DESC_LEN 54
#define PN_IM4_SIG_LEN  54

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
    uint64_t last_rt_ns; /* next RTC1 due (0 = immediately); abs phase */
    uint64_t last_lldp_ns;
    uint64_t start_ns;

    uint8_t last_rpc_resp[PN_FRAME_MAX];
    size_t last_rpc_resp_len;

    char im1_function[PN_IM1_FUNC_LEN];
    char im1_location[PN_IM1_LOC_LEN];
    char im2_date[PN_IM2_DATE_LEN];
    char im3_desc[PN_IM3_DESC_LEN];
    uint8_t im4_sig[PN_IM4_SIG_LEN];

    struct sockaddr_in rpc_peer;
    int rpc_peer_set;
    uint8_t pending_rpc_tx[PN_FRAME_MAX];
    size_t pending_rpc_tx_len;

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
void pn_dcp_send_hello(pn_stack_t *s);

void pn_lldp_send(pn_stack_t *s);

void pn_rt_on_frame(pn_stack_t *s, const uint8_t *payload, size_t plen);
void pn_rt_send_if_due(pn_stack_t *s);
void pn_ar_abort(pn_stack_t *s, const char *why);
void pn_ar_watchdog(pn_stack_t *s);

int pn_rpc_handle(pn_stack_t *s, const uint8_t *pdu, size_t len, uint8_t *resp,
                  size_t cap, size_t *out_len, uint32_t src_ip);
void pn_rpc_poll(pn_stack_t *s);

void pn_snmp_poll(pn_stack_t *s);
int pn_snmp_handle(pn_stack_t *s, const uint8_t *req, size_t len, uint8_t *resp,
                   size_t cap, size_t *out_len);
int pn_udp_open(uint16_t port);

int pn_record_read(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                   uint16_t index, uint8_t *out, size_t cap, size_t *out_len);
int pn_record_write(pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    uint16_t index, const uint8_t *data, size_t len);

int pn_alarm_send_dummy(pn_stack_t *s, uint16_t frame_id);

int pn_sec_hmac(const pn_stack_t *s, const uint8_t *data, size_t len,
                uint8_t mac[PN_HMAC_LEN]);
int pn_sec_ok(const pn_stack_t *s, const uint8_t *data, size_t len,
              const uint8_t mac[PN_HMAC_LEN]);

#endif /* PN_INTERNAL_H */
