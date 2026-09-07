#ifndef PN_STACK_H
#define PN_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "pn_types.h"

/*
 * PROFINET IO Device stack (Fieldbus Architecture profile)
 *
 * Scope:
 *   - Conformance Class B functions: DCP, cyclic RTC1, record, alarm TX,
 *     LLDP, minimal SNMP
 *   - RT Class 1 only (unsynchronized cyclic IO). IRT / RT Class 3: no.
 *   - Security Class 1 integrity: HMAC-SHA256 PSK on DCP Set and CM Connect.
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
    int security_class; /* 0 = unsigned (lab), 1 = HMAC required */
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

const pn_cfg_t *pn_stack_cfg(const pn_stack_t *s);

size_t pn_eth_build(uint8_t *out, size_t cap, const uint8_t dst[6],
                    const uint8_t src[6], uint16_t ethertype,
                    const uint8_t *payload, size_t plen);

#endif /* PN_STACK_H */
