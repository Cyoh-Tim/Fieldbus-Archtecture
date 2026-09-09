#ifndef MODBUS_CODEC_H
#define MODBUS_CODEC_H

#include <stddef.h>
#include <stdint.h>

/* Wire endian layouts used by almost every Modbus sensor/PLC manual. */
typedef enum {
    MB_END_ABCD = 0, /* big-endian (default) */
    MB_END_BADC = 1, /* byte-swap within words */
    MB_END_CDAB = 2, /* word-swap */
    MB_END_DCBA = 3, /* full little-endian */
} mb_endian_t;

typedef enum {
    MB_DT_UINT8 = 0,
    MB_DT_INT8,
    MB_DT_UINT16,
    MB_DT_INT16,
    MB_DT_UINT32,
    MB_DT_INT32,
    MB_DT_UINT64,
    MB_DT_INT64,
    MB_DT_FLOAT32,
    MB_DT_FLOAT64,
    MB_DT_BOOL,
    MB_DT_STRING,
    MB_DT_RAW,
    MB_DT_BCD16,
    MB_DT_BCD32,
} mb_data_type_t;

mb_endian_t mb_parse_endian(const char *byte_order, const char *word_order,
                            const char *endian);
mb_data_type_t mb_parse_data_type(const char *s);
size_t mb_type_native_size(mb_data_type_t dt, int length, int quantity,
                           int chars_per_reg);

/* Apply/remove wire endian so `buf` becomes canonical big-endian numeric layout. */
void mb_wire_to_canonical(uint8_t *buf, size_t n, mb_endian_t end);
void mb_canonical_to_wire(uint8_t *buf, size_t n, mb_endian_t end);

double mb_decode_number(mb_data_type_t dt, const uint8_t *canon, size_t n);
void mb_encode_number(mb_data_type_t dt, double raw, uint8_t *canon, size_t n);

/* Pack/unpack ASCII into registers (chars_per_reg = 1 or 2). */
void mb_pack_string(uint8_t *regs_be, size_t reg_bytes, const uint8_t *str,
                    size_t str_len, int chars_per_reg, int swap_chars);
void mb_unpack_string(uint8_t *str, size_t str_len, const uint8_t *regs_be,
                      size_t reg_bytes, int chars_per_reg, int swap_chars,
                      int trim_null);

uint64_t mb_extract_bits(uint64_t word, int bit, int bit_count);
uint64_t mb_insert_bits(uint64_t word, int bit, int bit_count, uint64_t value);

uint32_t mb_bcd_to_u32(uint32_t bcd);
uint32_t mb_u32_to_bcd(uint32_t v);

#endif /* MODBUS_CODEC_H */
