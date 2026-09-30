#ifndef SLMP_STACK_H
#define SLMP_STACK_H

#include <stddef.h>
#include <stdint.h>

#include "slmp_types.h"

/*
 * SLMP stack — client-first (sensor writes/reads PLC), optional server map
 * for lab/simulator. Binary 3E frame. Not a certified conformance product.
 */

typedef struct slmp_stack slmp_stack_t;

typedef struct {
    slmp_role_t role;
    slmp_frame_type_t frame;
    char plc_ip[64];
    char bind_ip[64];
    int port;
    uint8_t network_no;
    uint8_t pc_no;
    uint16_t dest_module_io; /* default 0x03FF (CPU) */
    uint8_t dest_multidrop;
    uint16_t monitoring_timer; /* units of 250 ms; 0 = wait forever */
    int timeout_ms;
    int max_clients; /* server role */
    int idle_timeout_ms; /* drop idle TCP clients; 0 = 60000 */
    int max_conn_per_ip; /* per-source IPv4 cap; 0 = 4 */
    uint32_t map_words; /* per word-device map capacity */
    uint32_t map_bits;  /* per bit-device map capacity (bits) */
} slmp_cfg_t;

typedef struct {
    uint8_t device_code;
    uint32_t head;
    slmp_access_unit_t unit;
} slmp_addr_t;

typedef struct {
    slmp_addr_t addr;
    uint16_t quantity; /* words or bits depending on unit */
} slmp_range_t;

slmp_stack_t *slmp_stack_create(const slmp_cfg_t *cfg);
void slmp_stack_destroy(slmp_stack_t *s);

int slmp_stack_start(slmp_stack_t *s);
void slmp_stack_stop(slmp_stack_t *s);
void slmp_stack_poll(slmp_stack_t *s);

int slmp_stack_connected(const slmp_stack_t *s);
const slmp_cfg_t *slmp_stack_cfg(const slmp_stack_t *s);

/* Resolve symbolic device name ("D","M","X","ZR","0xA8",…) → binary code.
 * is_bit set when device is bit-type by default. Returns -1 if unknown. */
int slmp_device_code_from_name(const char *name, uint8_t *code_out, int *is_bit);
const char *slmp_device_name_from_code(uint8_t code);
/* 1 if manuals typically express head address in hex (X/Y/B/W/SB/SW…). */
int slmp_device_is_hex_addr(uint8_t code);
/* 1 if `code` is a built-in Binary 3E device (not a raw unknown). */
int slmp_device_known(uint8_t code);

/* ---- Local device map (server / client cache) ---- */
int slmp_stack_map_ensure(slmp_stack_t *s, uint8_t device_code, int is_bit);
int slmp_stack_read_words(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          uint16_t *dst, uint16_t quantity);
int slmp_stack_write_words(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                           const uint16_t *src, uint16_t quantity);
int slmp_stack_read_bits(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                         uint8_t *dst, uint16_t quantity);
int slmp_stack_write_bits(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          const uint8_t *src, uint16_t quantity);

/* Word map as big-endian byte window (2 bytes per word) for adapters. */
int slmp_stack_read_bytes(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                          uint8_t *dst, size_t len);
int slmp_stack_write_bytes(slmp_stack_t *s, uint8_t device_code, uint32_t head,
                           const uint8_t *src, size_t len);

/* Bit-unit caller buffers are one byte per point (0 = OFF, 1 = ON).
 * Binary 3E subcommand 0001 packs two points per byte on the wire
 * (earlier point in the high nibble). Client batch and encode/decode
 * convert between those two forms. */
/* ---- Client: remote PLC I/O (also refreshes local cache) ---- */
int slmp_stack_client_batch_read(slmp_stack_t *s, const slmp_range_t *range,
                                 uint8_t *raw_out, size_t raw_cap,
                                 size_t *raw_len);
int slmp_stack_client_batch_write(slmp_stack_t *s, const slmp_range_t *range,
                                  const uint8_t *raw, size_t raw_len);

/* ---- Frame codec (for tests / custom transports) ---- */
int slmp_encode_batch_read(const slmp_cfg_t *cfg, const slmp_range_t *range,
                           uint8_t *out, size_t out_cap, size_t *out_len);
int slmp_encode_batch_write(const slmp_cfg_t *cfg, const slmp_range_t *range,
                            const uint8_t *raw, size_t raw_len, uint8_t *out,
                            size_t out_cap, size_t *out_len);
int slmp_decode_response(const uint8_t *frame, size_t frame_len,
                         uint16_t *end_code, const uint8_t **data,
                         size_t *data_len);

/* Server/sim: handle one complete Binary 3E request against local map. */
int slmp_stack_handle_request(slmp_stack_t *s, const uint8_t *req,
                              size_t req_len, uint8_t *resp, size_t resp_cap,
                              size_t *resp_len);

#endif /* SLMP_STACK_H */
