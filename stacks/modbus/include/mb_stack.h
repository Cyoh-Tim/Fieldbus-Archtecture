#ifndef MB_STACK_H
#define MB_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "mb_types.h"

/*
 * Modbus TCP stack — server-first (sensor/device), optional client.
 * Not a certified conformance product; covers common industrial PDUs.
 */

typedef struct mb_stack mb_stack_t;

typedef struct {
    mb_role_t role;
    char bind_ip[64];
    char remote_ip[64];
    int port;
    int unit_id;
    int unit_id_any;       /* 1: respond to any unit id */
    int client_timeout_ms; /* client role response wait (default 200) */
    int max_clients;       /* server concurrent masters (1..8, default 4) */
    uint16_t n_holding;
    uint16_t n_input;
    uint16_t n_coil;
    uint16_t n_discrete;
} mb_cfg_t;

mb_stack_t *mb_stack_create(const mb_cfg_t *cfg);
void mb_stack_destroy(mb_stack_t *s);

int mb_stack_start(mb_stack_t *s);
void mb_stack_stop(mb_stack_t *s);
void mb_stack_poll(mb_stack_t *s);

int mb_stack_connected(const mb_stack_t *s);
const mb_cfg_t *mb_stack_cfg(const mb_stack_t *s);

int mb_stack_read_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint16_t *dst, uint16_t quantity);
int mb_stack_write_regs(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint16_t *src, uint16_t quantity);
int mb_stack_read_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                       uint8_t *dst, uint16_t quantity);
int mb_stack_write_bits(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        const uint8_t *src, uint16_t quantity);

int mb_stack_read_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                        uint8_t *dst, size_t len);
int mb_stack_write_bytes(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         const uint8_t *src, size_t len);

int mb_stack_client_read(mb_stack_t *s, mb_reg_type_t type, uint16_t addr,
                         uint16_t quantity);
int mb_stack_client_write_regs(mb_stack_t *s, uint16_t addr,
                               const uint16_t *src, uint16_t quantity);
int mb_stack_client_write_bits(mb_stack_t *s, uint16_t addr, const uint8_t *src,
                               uint16_t quantity);

int mb_stack_handle_adu(mb_stack_t *s, const uint8_t *req, size_t req_len,
                        uint8_t *resp, size_t resp_cap, size_t *resp_len);

#endif /* MB_STACK_H */
