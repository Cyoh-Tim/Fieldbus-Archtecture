#ifndef PN_STACK_H
#define PN_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "pn_types.h"

/*
 * PROFINET IO Device stack (Fieldbus Architecture profile)
 *
 * Scope:
 *   - Conformance Class B functions: DCP (Identify/Get/Set/Hello/Signal),
 *     cyclic RTC1, record (I&M0–4), alarm TX (High/Low), LLDP, minimal SNMP
 *   - RT Class 1 only (unsynchronized cyclic IO). IRT / RT Class 3: no.
 *   - Optional vendor integrity extension: HMAC-SHA256 PSK on DCP Set and
 *     CM Connect when security_class >= 1. Off by default. Not PI
 *     Security Class.
 *
 * This is a working Device-side stack, not a PI-certified product.
 * CRA/CE is a product process, not a compile flag.
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
    int security_class; /* config key. 0 = off, >= PN_VENDOR_INTEGRITY = HMAC */
    /* 1 = require the vendor integrity extension (unsigned DCP Set rejected).
     * Lab default 0. Production builds may also set
     * CMake -DPN_ENFORCE_SECURITY_CLASS=ON. */
    int enforce_security_class;
    uint8_t psk[PN_PSK_LEN];
    int psk_set;
    uint16_t input_len;  /* device -> controller */
    uint16_t output_len; /* controller -> device */
    uint32_t cycle_us;
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
int pn_stack_read_output(pn_stack_t *s, size_t off, uint8_t *dst, size_t len);
int pn_stack_read_input(pn_stack_t *s, size_t off, uint8_t *dst, size_t len);
int pn_stack_write_input(pn_stack_t *s, size_t off, const uint8_t *src,
                         size_t len);

/* Test / mock Ethernet. Replaces AF_PACKET. */
void pn_stack_set_eth_ops(pn_stack_t *s, pn_eth_ops_t ops);
int pn_stack_handle_eth(pn_stack_t *s, const uint8_t *frame, size_t len);
int pn_stack_handle_rpc(pn_stack_t *s, const uint8_t *udp_payload, size_t len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len);
/* Mock SNMP (UDP 161). Same idea as handle_rpc: no bind, no sudo. */
int pn_stack_handle_snmp(pn_stack_t *s, const uint8_t *req, size_t len,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Device TX helpers for CTT (CC-B). Alarm requires an established AR. */
int pn_stack_send_alarm(pn_stack_t *s);
int pn_stack_send_alarm_ex(pn_stack_t *s, uint16_t frame_id);
void pn_stack_send_lldp(pn_stack_t *s);
void pn_stack_send_hello(pn_stack_t *s);
int pn_stack_app_ready(const pn_stack_t *s);
/* Mock: pull Device-originated RPC (ApplicationReady after PrmEnd). */
int pn_stack_take_rpc_tx(pn_stack_t *s, uint8_t *out, size_t cap, size_t *out_len);

const pn_cfg_t *pn_stack_cfg(const pn_stack_t *s);

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen);

#endif /* PN_STACK_H */
