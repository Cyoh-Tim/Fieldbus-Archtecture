#ifndef SLMP_CODEC_H
#define SLMP_CODEC_H

#include <stddef.h>
#include <stdint.h>

/* Value codec for packing sensor/PLC guide data into SLMP word/bit windows.
 * Same endian/type vocabulary as the Modbus adapter for cross-protocol reuse. */

typedef enum {
    SLMP_END_ABCD = 0,
    SLMP_END_BADC = 1,
    SLMP_END_CDAB = 2,
    SLMP_END_DCBA = 3,
} slmp_endian_t;

typedef enum {
    SLMP_DT_UINT8 = 0,
    SLMP_DT_INT8,
    SLMP_DT_UINT16,
    SLMP_DT_INT16,
    SLMP_DT_UINT32,
    SLMP_DT_INT32,
    SLMP_DT_UINT64,
    SLMP_DT_INT64,
    SLMP_DT_FLOAT32,
    SLMP_DT_FLOAT64,
    SLMP_DT_BOOL,
    SLMP_DT_STRING,
    SLMP_DT_RAW,
    SLMP_DT_BCD16,
    SLMP_DT_BCD32,
} slmp_data_type_t;

slmp_endian_t slmp_parse_endian(const char *byte_order, const char *word_order,
                                const char *endian);
slmp_data_type_t slmp_parse_data_type(const char *s);
size_t slmp_type_native_size(slmp_data_type_t dt, int length, int quantity,
                             int chars_per_word);

void slmp_wire_to_canonical(uint8_t *buf, size_t n, slmp_endian_t end);
void slmp_canonical_to_wire(uint8_t *buf, size_t n, slmp_endian_t end);

double slmp_decode_number(slmp_data_type_t dt, const uint8_t *canon, size_t n);
void slmp_encode_number(slmp_data_type_t dt, double raw, uint8_t *canon,
                        size_t n);

void slmp_pack_string(uint8_t *words_be, size_t word_bytes, const uint8_t *str,
                      size_t str_len, int chars_per_word, int swap_chars);
void slmp_unpack_string(uint8_t *str, size_t str_len, const uint8_t *words_be,
                        size_t word_bytes, int chars_per_word, int swap_chars,
                        int trim_null);

uint64_t slmp_extract_bits(uint64_t word, int bit, int bit_count);
uint64_t slmp_insert_bits(uint64_t word, int bit, int bit_count, uint64_t value);

uint32_t slmp_bcd_to_u32(uint32_t bcd);
uint32_t slmp_u32_to_bcd(uint32_t v);

#endif /* SLMP_CODEC_H */
