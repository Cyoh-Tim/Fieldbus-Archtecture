#ifndef PN_STACK_H
#define PN_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "pn_types.h"

/*
 * PROFINET IO Device stack (Fieldbus Architecture profile)
 *
 * Scope:
 *   - Device-side DCP, CM (Connect/Write/WriteMultiple/PrmEnd/ApplicationReady
 *     ACK then DATAEX), RTC1 cyclic IO, record (I&M0–4, RealIdent, PD*),
 *     LLDP, SNMP (MIB-II system/interfaces/at/ip/icmp/tcp/udp/snmp + ifX,
 *     LLDP-MIB, LLDP-EXT-PNO; Get/GetNext/GetBulk with non-repeaters),
 *     AlarmCR + event-driven RTA appear/disappear/process
 *   - Lab Conformance Class B: RT Class 1, DCP, CM, alarms, SNMP MIB-II +
 *     LLDP-MIB, ChannelDiagnosis ASE, PDEV. Not PI-certified.
 *     SNMP Get/GetNext/GetBulk with non-repeaters; Set is read-only.
 *   - CC-C / IRT (RT Class 3, PTCP, SPIRTA) is not implemented; Connect
 *     with RT_CLASS_3 is rejected.
 *   - MRP is a CC-B optional (media redundancy), not CC-C. Not implemented;
 *     0x88E3 frames are ignored.
 *   - Official ART/ETS/PITL are not substituted.
 *   - Lab PI Security Class 1 subset (always on, not a PI certificate):
 *     DCP Set of Name/IP is rejected while an AR is up; SNMP is read-only
 *     (Get/GetNext/GetBulk still served for CC-B topology). GSDX signatures
 *     are not implemented. Optional stack-local HMAC-SHA256 PSK
 *     (security_class=1) is a separate lab profile, not PI SC1.
 *
 * Not a PI-certified product. CRA/CE is a product process.
 */

typedef struct pn_stack pn_stack_t;

typedef struct {
    char iface[16];
    uint8_t mac[6];
    int mac_set;
    char station_name[PN_STATION_NAME_MAX + 1];
    char device_type[64];
    uint16_t vendor_id;
    uint16_t device_id;
    uint32_t ip;      /* host order */
    uint32_t netmask; /* host order */
    uint32_t gateway; /* host order */
    int security_class; /* 0 = unsigned (lab default), 1 = HMAC required */
    uint8_t psk[PN_PSK_LEN];
    int psk_set;
    uint16_t input_len;  /* device -> controller */
    uint16_t output_len; /* controller -> device */
    uint32_t cycle_us;   /* RTC1 fallback if Connect omits RR; min 8 ms */
    int apply_os_ip;
} pn_cfg_t;

typedef struct {
    int (*send)(void *ctx, const uint8_t *frame, size_t len);
    int (*recv)(void *ctx, uint8_t *frame, size_t cap, int timeout_ms);
    void *ctx;
} pn_eth_ops_t;

pn_stack_t *pn_stack_create(const pn_cfg_t *cfg);
void pn_stack_destroy(pn_stack_t *s);

int pn_stack_start(pn_stack_t *s);
void pn_stack_stop(pn_stack_t *s);
void pn_stack_poll(pn_stack_t *s);

int pn_stack_ar_up(const pn_stack_t *s);
int pn_stack_cm_state(const pn_stack_t *s);
int pn_stack_read_output(pn_stack_t *s, size_t off, uint8_t *dst, size_t len);
int pn_stack_read_input(pn_stack_t *s, size_t off, uint8_t *dst, size_t len);
int pn_stack_write_input(pn_stack_t *s, size_t off, const uint8_t *src,
                         size_t len);

/* Slot/subslot → process-image base after Connect. -ENOENT if unknown. */
int pn_stack_io_map(const pn_stack_t *s, uint16_t slot, uint16_t subslot,
                    int output, size_t *base, size_t *mod_len);
int pn_stack_sub_count(const pn_stack_t *s);
int pn_stack_sub_info(const pn_stack_t *s, int idx, uint16_t *slot,
                      uint16_t *subslot, uint16_t *in_len, uint16_t *out_len,
                      uint16_t *in_pi, uint16_t *out_pi);

/* Diagnosis ASE: appear / disappear / process RTA. Idle has no diagnosis. */
int pn_stack_diag_appear(pn_stack_t *s);
int pn_stack_diag_clear(pn_stack_t *s);
int pn_stack_alarm_process(pn_stack_t *s);

/* Test / mock Ethernet. Replaces AF_PACKET. */
void pn_stack_set_eth_ops(pn_stack_t *s, pn_eth_ops_t ops);
int pn_stack_handle_eth(pn_stack_t *s, const uint8_t *frame, size_t len);
int pn_stack_handle_rpc(pn_stack_t *s, const uint8_t *udp_payload, size_t len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len);
int pn_stack_handle_rpc_from(pn_stack_t *s, const uint8_t *udp_payload,
                             size_t len, uint32_t src_ip, uint16_t src_port,
                             uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Drain a pending device-originated RPC (ApplicationReady). */
int pn_stack_take_rpc_tx(pn_stack_t *s, uint8_t *out, size_t cap, size_t *len,
                         uint32_t *dst_ip, uint16_t *dst_port);

const pn_cfg_t *pn_stack_cfg(const pn_stack_t *s);
int pn_stack_lldp_remote_name(const pn_stack_t *s, char *out, size_t cap);
int pn_stack_handle_snmp(pn_stack_t *s, const uint8_t *req, size_t n,
                         uint8_t *resp, size_t cap, size_t *out_len);

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen);
size_t pn_eth_build_vlan(uint8_t *out, size_t cap, const uint8_t dst[6],
                         const uint8_t src[6], uint16_t tci, uint16_t ethertype,
                         const uint8_t *payload, size_t plen);

#endif /* PN_STACK_H */
