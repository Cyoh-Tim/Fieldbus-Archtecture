#ifndef SLMP_TYPES_H
#define SLMP_TYPES_H

#include <stddef.h>
#include <stdint.h>

/* Mitsubishi SLMP / MC Protocol — Binary 3E (QnA compatible) frame constants.
 * Spec basis: published SLMP Reference Manual (Binary communication, 3E frame).
 * ASCII / 4E are reserved via frame enum for future extension. */

#define SLMP_TCP_DEFAULT_PORT 5000

#define SLMP_SUBHEADER_REQ_3E 0x0050
#define SLMP_SUBHEADER_RES_3E 0x00D0

#define SLMP_DEST_MODULE_CPU 0x03FF
#define SLMP_PC_OWN_STATION 0xFF

/* Commands (little-endian on wire) */
#define SLMP_CMD_BATCH_READ 0x0401
#define SLMP_CMD_BATCH_WRITE 0x1401
#define SLMP_CMD_RANDOM_READ 0x0403
#define SLMP_CMD_RANDOM_WRITE 0x1402

/* Subcommands */
#define SLMP_SUB_WORD 0x0000
#define SLMP_SUB_BIT 0x0001

/* End codes (Binary 3E / QnA compatible) */
#define SLMP_END_OK 0x0000
#define SLMP_END_CMD 0xC050     /* command / subcommand not supported */
#define SLMP_END_POINTS 0xC051  /* number of points / data length */
#define SLMP_END_DEVICE 0xC056  /* device designation */

#define SLMP_FRAME_MAX 2048
#define SLMP_HEADER_3E_LEN 11 /* up to and including request data length field */
#define SLMP_PAYLOAD_MAX 1920
#define SLMP_POINTS_PER_BATCH_MAX 960
/* Binary 3E device batch (QnA compatible): word 1–960, bit 1–7168. */
#define SLMP_QTY_WORD_MAX SLMP_POINTS_PER_BATCH_MAX
#define SLMP_QTY_BIT_MAX 7168

#define SLMP_DEV_MAP_MAX 48
#define SLMP_DEV_WORDS_DEFAULT 4096
#define SLMP_DEV_BITS_DEFAULT 8192

typedef enum {
    SLMP_ROLE_CLIENT = 0, /* sensor → PLC (default for SLMP) */
    SLMP_ROLE_SERVER = 1, /* local device map / lab simulator */
} slmp_role_t;

typedef enum {
    SLMP_FRAME_3E_BINARY = 0,
    SLMP_FRAME_3E_ASCII = 1, /* reserved */
    SLMP_FRAME_4E_BINARY = 2, /* reserved */
} slmp_frame_type_t;

/* Built-in binary device codes (extensible via config raw code). */
#define SLMP_DEV_X 0x9C
#define SLMP_DEV_Y 0x9D
#define SLMP_DEV_M 0x90
#define SLMP_DEV_L 0x92
#define SLMP_DEV_F 0x93
#define SLMP_DEV_V 0x94
#define SLMP_DEV_B 0xA0
#define SLMP_DEV_D 0xA8
#define SLMP_DEV_W 0xB4
#define SLMP_DEV_TS 0xC1
#define SLMP_DEV_TC 0xC0
#define SLMP_DEV_TN 0xC2
#define SLMP_DEV_SS 0xC7
#define SLMP_DEV_SC 0xC6
#define SLMP_DEV_SN 0xC8
#define SLMP_DEV_CS 0xC4
#define SLMP_DEV_CC 0xC3
#define SLMP_DEV_CN 0xC5
#define SLMP_DEV_SB 0xA1
#define SLMP_DEV_SW 0xB5
#define SLMP_DEV_S 0x98
#define SLMP_DEV_DX 0xA2
#define SLMP_DEV_DY 0xA3
#define SLMP_DEV_Z 0xCC
#define SLMP_DEV_R 0xAF
#define SLMP_DEV_ZR 0xB0
#define SLMP_DEV_SM 0x91
#define SLMP_DEV_SD 0xA9

typedef enum {
    SLMP_ACCESS_WORD = 0,
    SLMP_ACCESS_BIT = 1,
} slmp_access_unit_t;

#endif /* SLMP_TYPES_H */
