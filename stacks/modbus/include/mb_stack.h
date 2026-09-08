#ifndef MB_STACK_H
#define MB_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "mb_types.h"

/*
 * Modbus TCP stack (Fieldbus Architecture profile)
 *
 * Primary role: TCP server (slave). Matches the sensor/device deployment
 * model used by the PROFINET stack — the PLC is the master.
 *
 * Optional MB_ROLE_CLIENT polls a remote slave and caches registers.
 * This is a working stack, not a certified Modbus conformance product.
 */

typedef struct mb_stack mb_stack_t;

typedef struct {
    mb_role_t role;
    char bind_ip[64];   /* server: listen address ("" / "0.0.0.0" = all) */
    char remote_ip[64]; /* client: remote slave IP */
    int port;
    int unit_id;
    uint16_t n_holding;
    uint16_t n_input;
    uint16_t n_coil;
    uint16_t n_discrete;
} mb_cfg_t;

mb_stack_t *mb_stack_create(const mb_cfg_t *cfg);
void mb_stack_destroy(mb_stack_t *s);

int mb_stack_start(mb_stack_t *s);
void mb_stack_stop(mb_stack_t *s);

/* Scheduler tick: accept/serve requests (server) or refresh cache (client). */
void mb_stack_poll(mb_stack_t *s);

int mb_stack_connected(const mb_stack_t *s);
const mb_cfg_t *mb_stack_cfg(const mb_stack_t *s);

/* Local process-image style map (server always; client after poll). */
int mb_stack_read_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint16_t *dst, uint16_t quantity);
int mb_stack_write_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint16_t *src, uint16_t quantity);
int mb_stack_read_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint8_t *dst, uint16_t quantity);
int mb_stack_write_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint8_t *src, uint16_t quantity);

/* Byte helpers for adapter string/raw mapping (big-endian register packing). */
int mb_stack_read_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        uint8_t *dst, size_t len);
int mb_stack_write_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         const uint8_t *src, size_t len);

/* Client-role: poll remote slave into the local cache. */
int mb_stack_client_read(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         uint16_t quantity);
int mb_stack_client_write_regs(mb_stack_t *s, uint16_t addr,
                               const uint16_t *src, uint16_t quantity);
int mb_stack_client_write_bits(mb_stack_t *s, uint16_t addr, const uint8_t *src,
                               uint16_t quantity);

/* Test hook: feed a raw Modbus TCP ADU, get response ADU (server path). */
int mb_stack_handle_adu(mb_stack_t *s, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len);

#endif /* MB_STACK_H */
