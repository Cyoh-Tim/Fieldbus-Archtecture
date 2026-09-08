#ifndef EIP_STACK_H
#define EIP_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "eip_types.h"

/*
 * EtherNet/IP stack (Fieldbus Architecture profile)
 *
 * Self-implemented (no vendor SDK required). Scope:
 *   - Adapter (target): TCP encapsulation, Identity/Assembly/CM objects,
 *     Forward Open/Close, Class 1 cyclic I/O on UDP 2222
 *   - Originator (client): RegisterSession + explicit Get/Set Attribute
 *     Single and symbolic tag read/write (UCMM)
 *
 * Not ODVA-certified. Suitable for sensor process-image exchange and
 * config-driven point mapping. Capacity limits are intentionally high.
 */

typedef struct eip_stack eip_stack_t;

typedef struct {
    eip_role_t role;
    char bind_ip[64];    /* adapter listen address; empty = 0.0.0.0 */
    int tcp_port;        /* default 44818 */
    int udp_io_port;     /* default 2222 */
    char remote_ip[64];  /* originator peer */
    int remote_port;

    uint16_t vendor_id;
    uint16_t device_type;
    uint16_t product_code;
    uint8_t major_rev;
    uint8_t minor_rev;
    uint32_t serial_number;
    char product_name[EIP_PRODUCT_NAME_MAX + 1];

    uint16_t input_assembly;  /* produced (T->O) */
    uint16_t output_assembly; /* consumed (O->T) */
    uint16_t config_assembly;
    uint16_t input_size;  /* bytes */
    uint16_t output_size;
    uint16_t config_size;

    uint32_t rpi_us; /* Class 1 RPI hint (default 8000) */
    int mock;        /* 1 = no real sockets (unit tests) */
} eip_cfg_t;

/* Optional transport ops for tests (replaces TCP/UDP sockets). */
typedef struct {
    int (*tcp_send)(void *ctx, const uint8_t *data, size_t len);
    int (*udp_send)(void *ctx, const uint8_t *data, size_t len,
                    uint32_t dst_ip_be, uint16_t dst_port);
    void *ctx;
} eip_transport_ops_t;

eip_stack_t *eip_stack_create(const eip_cfg_t *cfg);
void eip_stack_destroy(eip_stack_t *s);

int eip_stack_start(eip_stack_t *s);
void eip_stack_stop(eip_stack_t *s);
void eip_stack_poll(eip_stack_t *s);

/* Class 1 exclusive-owner (or any Class1) up */
int eip_stack_class1_up(const eip_stack_t *s);
/* Adapter has at least one TCP session, or originator session registered */
int eip_stack_session_up(const eip_stack_t *s);

int eip_stack_read_input(eip_stack_t *s, size_t off, uint8_t *dst, size_t len);
int eip_stack_write_input(eip_stack_t *s, size_t off, const uint8_t *src,
                          size_t len);
int eip_stack_read_output(eip_stack_t *s, size_t off, uint8_t *dst, size_t len);
int eip_stack_write_output(eip_stack_t *s, size_t off, const uint8_t *src,
                           size_t len);

/* Originator explicit messaging (blocking over existing session). */
int eip_stack_explicit_get(eip_stack_t *s, uint16_t class_id, uint16_t instance,
                           uint16_t attribute, uint8_t *out, size_t *inout_len);
int eip_stack_explicit_set(eip_stack_t *s, uint16_t class_id, uint16_t instance,
                           uint16_t attribute, const uint8_t *data, size_t len);
int eip_stack_tag_read(eip_stack_t *s, const char *tag, uint8_t *out,
                       size_t *inout_len);
int eip_stack_tag_write(eip_stack_t *s, const char *tag, const uint8_t *data,
                        size_t len);

const eip_cfg_t *eip_stack_cfg(const eip_stack_t *s);

void eip_stack_set_transport_ops(eip_stack_t *s, eip_transport_ops_t ops);

/* Inject encapsulation PDU (mock / tests). Returns response length or <0. */
int eip_stack_handle_encap(eip_stack_t *s, const uint8_t *req, size_t req_len,
                           uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Inject Class 1 UDP IO frame (mock / tests). */
int eip_stack_handle_io(eip_stack_t *s, const uint8_t *frame, size_t len);

#endif /* EIP_STACK_H */
