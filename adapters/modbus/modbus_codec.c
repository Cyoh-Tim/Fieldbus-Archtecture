#include "modbus_codec.h"

#include <ctype.h>
#include <math.h>
#include <string.h>

static int eqi(const char *a, const char *b)
{
    if (!a || !b) {
        return 0;
    }
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

mb_endian_t mb_parse_endian(const char *byte_order, const char *word_order,
                            const char *endian)
{
    if (endian && endian[0]) {
        if (eqi(endian, "ABCD") || eqi(endian, "BE") || eqi(endian, "big")) {
            return MB_END_ABCD;
        }
        if (eqi(endian, "BADC")) {
            return MB_END_BADC;
        }
        if (eqi(endian, "CDAB") || eqi(endian, "ba")) {
            return MB_END_CDAB;
        }
        if (eqi(endian, "DCBA") || eqi(endian, "LE") || eqi(endian, "little")) {
            return MB_END_DCBA;
        }
    }
    int le = byte_order && eqi(byte_order, "little");
    int ba = word_order && (eqi(word_order, "ba") || eqi(word_order, "cdab"));
    if (!le && !ba) {
        return MB_END_ABCD;
    }
    if (le && ba) {
        return MB_END_DCBA;
    }
    if (ba) {
        return MB_END_CDAB;
    }
    return MB_END_BADC; /* little bytes, no word swap ≈ BADC for 32-bit */
}

mb_data_type_t mb_parse_data_type(const char *s)
{
    if (!s) {
        return MB_DT_UINT16;
    }
    if (eqi(s, "uint8") || eqi(s, "u8") || eqi(s, "byte")) {
        return MB_DT_UINT8;
    }
    if (eqi(s, "int8") || eqi(s, "i8") || eqi(s, "sbyte")) {
        return MB_DT_INT8;
    }
    if (eqi(s, "uint16") || eqi(s, "u16") || eqi(s, "word") || eqi(s, "ushort")) {
        return MB_DT_UINT16;
    }
    if (eqi(s, "int16") || eqi(s, "i16") || eqi(s, "short")) {
        return MB_DT_INT16;
    }
    if (eqi(s, "uint32") || eqi(s, "u32") || eqi(s, "dword") ||
        eqi(s, "uint")) {
        return MB_DT_UINT32;
    }
    if (eqi(s, "int32") || eqi(s, "i32") || eqi(s, "int") || eqi(s, "long")) {
        return MB_DT_INT32;
    }
    if (eqi(s, "uint64") || eqi(s, "u64") || eqi(s, "qword")) {
        return MB_DT_UINT64;
    }
    if (eqi(s, "int64") || eqi(s, "i64")) {
        return MB_DT_INT64;
    }
    if (eqi(s, "float32") || eqi(s, "float") || eqi(s, "real") ||
        eqi(s, "single")) {
        return MB_DT_FLOAT32;
    }
    if (eqi(s, "float64") || eqi(s, "double")) {
        return MB_DT_FLOAT64;
    }
    if (eqi(s, "bool") || eqi(s, "boolean") || eqi(s, "bit")) {
        return MB_DT_BOOL;
    }
    if (eqi(s, "string") || eqi(s, "ascii") || eqi(s, "str")) {
        return MB_DT_STRING;
    }
    if (eqi(s, "raw") || eqi(s, "bytes") || eqi(s, "blob")) {
        return MB_DT_RAW;
    }
    if (eqi(s, "bcd16") || eqi(s, "bcd")) {
        return MB_DT_BCD16;
    }
    if (eqi(s, "bcd32")) {
        return MB_DT_BCD32;
    }
    return MB_DT_UINT16;
}

size_t mb_type_native_size(mb_data_type_t dt, int length, int quantity,
                           int chars_per_reg)
{
    switch (dt) {
    case MB_DT_UINT8:
    case MB_DT_INT8:
    case MB_DT_BOOL:
        return 1;
    case MB_DT_UINT16:
    case MB_DT_INT16:
    case MB_DT_BCD16:
        return 2;
    case MB_DT_UINT32:
    case MB_DT_INT32:
    case MB_DT_FLOAT32:
    case MB_DT_BCD32:
        return 4;
    case MB_DT_UINT64:
    case MB_DT_INT64:
    case MB_DT_FLOAT64:
        return 8;
    case MB_DT_STRING:
        if (length > 0) {
            return (size_t)length;
        }
        if (quantity > 0) {
            int cpr = chars_per_reg > 0 ? chars_per_reg : 2;
            return (size_t)quantity * (size_t)cpr;
        }
        return 2;
    case MB_DT_RAW:
        if (length > 0) {
            return (size_t)length;
        }
        if (quantity > 0) {
            return (size_t)quantity * 2u;
        }
        return 2;
    }
    return 2;
}

static void swap2(uint8_t *p)
{
    uint8_t t = p[0];
    p[0] = p[1];
    p[1] = t;
}

static void swap4_words(uint8_t *p)
{
    uint8_t t0 = p[0], t1 = p[1];
    p[0] = p[2];
    p[1] = p[3];
    p[2] = t0;
    p[3] = t1;
}

static void rev(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n / 2; i++) {
        uint8_t t = p[i];
        p[i] = p[n - 1 - i];
        p[n - 1 - i] = t;
    }
}

static void apply_endian_chunk4(uint8_t *p, mb_endian_t end)
{
    switch (end) {
    case MB_END_ABCD:
        break;
    case MB_END_BADC:
        swap2(p);
        swap2(p + 2);
        break;
    case MB_END_CDAB:
        swap4_words(p);
        break;
    case MB_END_DCBA:
        rev(p, 4);
        break;
    }
}

void mb_wire_to_canonical(uint8_t *buf, size_t n, mb_endian_t end)
{
    if (!buf || n == 0 || end == MB_END_ABCD) {
        return;
    }
    if (n == 2) {
        if (end == MB_END_BADC || end == MB_END_DCBA) {
            swap2(buf);
        }
        return;
    }
    if (n == 4) {
        apply_endian_chunk4(buf, end);
        return;
    }
    if (n == 8) {
        /* Treat as two 32-bit halves; CDAB/DCBA also swap the halves. */
        apply_endian_chunk4(buf, end);
        apply_endian_chunk4(buf + 4, end);
        if (end == MB_END_CDAB || end == MB_END_DCBA) {
            uint8_t tmp[4];
            memcpy(tmp, buf, 4);
            memcpy(buf, buf + 4, 4);
            memcpy(buf + 4, tmp, 4);
        }
        return;
    }
    /* Odd sizes: byte-reverse if little-ish */
    if (end == MB_END_DCBA || end == MB_END_BADC) {
        rev(buf, n);
    }
}

void mb_canonical_to_wire(uint8_t *buf, size_t n, mb_endian_t end)
{
    /* All layouts used here are involutions. */
    mb_wire_to_canonical(buf, n, end);
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xff);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | (uint64_t)be32(p + 4);
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)v);
}

uint32_t mb_bcd_to_u32(uint32_t bcd)
{
    uint32_t out = 0;
    uint32_t mul = 1;
    for (int i = 0; i < 8; i++) {
        out += ((bcd >> (i * 4)) & 0xF) * mul;
        mul *= 10;
    }
    return out;
}

uint32_t mb_u32_to_bcd(uint32_t v)
{
    uint32_t bcd = 0;
    for (int i = 0; i < 8; i++) {
        bcd |= (v % 10) << (i * 4);
        v /= 10;
    }
    return bcd;
}

double mb_decode_number(mb_data_type_t dt, const uint8_t *canon, size_t n)
{
    switch (dt) {
    case MB_DT_UINT8:
        return n >= 1 ? (double)canon[0] : 0;
    case MB_DT_INT8:
        return n >= 1 ? (double)(int8_t)canon[0] : 0;
    case MB_DT_UINT16:
        return n >= 2 ? (double)be16(canon) : 0;
    case MB_DT_INT16:
        return n >= 2 ? (double)(int16_t)be16(canon) : 0;
    case MB_DT_UINT32:
        return n >= 4 ? (double)be32(canon) : 0;
    case MB_DT_INT32:
        return n >= 4 ? (double)(int32_t)be32(canon) : 0;
    case MB_DT_UINT64:
        return n >= 8 ? (double)be64(canon) : 0;
    case MB_DT_INT64:
        return n >= 8 ? (double)(int64_t)be64(canon) : 0;
    case MB_DT_FLOAT32: {
        if (n < 4) {
            return 0;
        }
        uint32_t u = be32(canon);
        float f;
        memcpy(&f, &u, sizeof(f));
        return (double)f;
    }
    case MB_DT_FLOAT64: {
        if (n < 8) {
            return 0;
        }
        uint64_t u = be64(canon);
        double d;
        memcpy(&d, &u, sizeof(d));
        return d;
    }
    case MB_DT_BOOL:
        return (n >= 1 && canon[0]) ? 1.0 : 0.0;
    case MB_DT_BCD16:
        return n >= 2 ? (double)mb_bcd_to_u32(be16(canon)) : 0;
    case MB_DT_BCD32:
        return n >= 4 ? (double)mb_bcd_to_u32(be32(canon)) : 0;
    default:
        return 0;
    }
}

void mb_encode_number(mb_data_type_t dt, double raw, uint8_t *canon, size_t n)
{
    memset(canon, 0, n);
    switch (dt) {
    case MB_DT_UINT8:
        if (n >= 1) {
            canon[0] = (uint8_t)lround(raw);
        }
        break;
    case MB_DT_INT8:
        if (n >= 1) {
            canon[0] = (uint8_t)(int8_t)lround(raw);
        }
        break;
    case MB_DT_UINT16:
        if (n >= 2) {
            put_be16(canon, (uint16_t)lround(raw));
        }
        break;
    case MB_DT_INT16:
        if (n >= 2) {
            put_be16(canon, (uint16_t)(int16_t)lround(raw));
        }
        break;
    case MB_DT_UINT32:
        if (n >= 4) {
            put_be32(canon, (uint32_t)llround(raw));
        }
        break;
    case MB_DT_INT32:
        if (n >= 4) {
            put_be32(canon, (uint32_t)(int32_t)llround(raw));
        }
        break;
    case MB_DT_UINT64:
        if (n >= 8) {
            put_be64(canon, (uint64_t)llround(raw));
        }
        break;
    case MB_DT_INT64:
        if (n >= 8) {
            put_be64(canon, (uint64_t)(int64_t)llround(raw));
        }
        break;
    case MB_DT_FLOAT32:
        if (n >= 4) {
            float f = (float)raw;
            uint32_t u;
            memcpy(&u, &f, sizeof(u));
            put_be32(canon, u);
        }
        break;
    case MB_DT_FLOAT64:
        if (n >= 8) {
            double d = raw;
            uint64_t u;
            memcpy(&u, &d, sizeof(u));
            put_be64(canon, u);
        }
        break;
    case MB_DT_BOOL:
        if (n >= 1) {
            canon[0] = (raw != 0.0) ? 1 : 0;
        }
        break;
    case MB_DT_BCD16:
        if (n >= 2) {
            put_be16(canon, (uint16_t)mb_u32_to_bcd((uint32_t)llround(raw)));
        }
        break;
    case MB_DT_BCD32:
        if (n >= 4) {
            put_be32(canon, mb_u32_to_bcd((uint32_t)llround(raw)));
        }
        break;
    default:
        break;
    }
}

void mb_pack_string(uint8_t *regs_be, size_t reg_bytes, const uint8_t *str,
                    size_t str_len, int chars_per_reg, int swap_chars)
{
    memset(regs_be, 0, reg_bytes);
    int cpr = chars_per_reg == 1 ? 1 : 2;
    size_t i = 0;
    for (size_t off = 0; off + (cpr == 1 ? 2u : 2u) <= reg_bytes && i < str_len;
         off += 2) {
        if (cpr == 1) {
            regs_be[off] = 0;
            regs_be[off + 1] = str[i++];
        } else {
            uint8_t a = (i < str_len) ? str[i++] : 0;
            uint8_t b = (i < str_len) ? str[i++] : 0;
            if (swap_chars) {
                regs_be[off] = b;
                regs_be[off + 1] = a;
            } else {
                regs_be[off] = a;
                regs_be[off + 1] = b;
            }
        }
    }
}

void mb_unpack_string(uint8_t *str, size_t str_len, const uint8_t *regs_be,
                      size_t reg_bytes, int chars_per_reg, int swap_chars,
                      int trim_null)
{
    memset(str, 0, str_len);
    int cpr = chars_per_reg == 1 ? 1 : 2;
    size_t o = 0;
    for (size_t off = 0; off + 2 <= reg_bytes && o < str_len; off += 2) {
        if (cpr == 1) {
            str[o++] = regs_be[off + 1];
        } else {
            uint8_t a = regs_be[off];
            uint8_t b = regs_be[off + 1];
            if (swap_chars) {
                uint8_t t = a;
                a = b;
                b = t;
            }
            if (o < str_len) {
                str[o++] = a;
            }
            if (o < str_len) {
                str[o++] = b;
            }
        }
    }
    if (trim_null) {
        for (size_t i = 0; i < str_len; i++) {
            if (str[i] == '\0') {
                memset(str + i, 0, str_len - i);
                break;
            }
        }
    }
}

uint64_t mb_extract_bits(uint64_t word, int bit, int bit_count)
{
    if (bit < 0) {
        bit = 0;
    }
    if (bit_count <= 0) {
        bit_count = 1;
    }
    if (bit_count > 63) {
        bit_count = 63;
    }
    uint64_t mask = (bit_count == 64) ? ~0ull : ((1ull << bit_count) - 1ull);
    return (word >> bit) & mask;
}

uint64_t mb_insert_bits(uint64_t word, int bit, int bit_count, uint64_t value)
{
    if (bit < 0) {
        bit = 0;
    }
    if (bit_count <= 0) {
        bit_count = 1;
    }
    if (bit_count > 63) {
        bit_count = 63;
    }
    uint64_t mask = (bit_count == 64) ? ~0ull : ((1ull << bit_count) - 1ull);
    word &= ~(mask << bit);
    word |= (value & mask) << bit;
    return word;
}
