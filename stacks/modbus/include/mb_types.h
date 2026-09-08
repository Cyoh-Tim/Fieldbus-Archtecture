#ifndef MB_TYPES_H
#define MB_TYPES_H

#include <stddef.h>
#include <stdint.h>

#define MB_TCP_DEFAULT_PORT 502
#define MB_UNIT_ID_DEFAULT 1

#define MB_MAP_REGS_MAX 10000
#define MB_MAP_BITS_MAX 10000

#define MB_ADU_MAX 260
#define MB_PDU_MAX 253
#define MB_MBAP_LEN 7

/* Function codes */
#define MB_FC_READ_COILS 0x01
#define MB_FC_READ_DISCRETE 0x02
#define MB_FC_READ_HOLDING 0x03
#define MB_FC_READ_INPUT 0x04
#define MB_FC_WRITE_SINGLE_COIL 0x05
#define MB_FC_WRITE_SINGLE_REG 0x06
#define MB_FC_WRITE_MULTI_COILS 0x0F
#define MB_FC_WRITE_MULTI_REGS 0x10

/* Exception codes */
#define MB_EX_ILLEGAL_FUNCTION 0x01
#define MB_EX_ILLEGAL_ADDRESS 0x02
#define MB_EX_ILLEGAL_VALUE 0x03
#define MB_EX_SLAVE_FAILURE 0x04

typedef enum {
    MB_ROLE_SERVER = 0, /* TCP slave — PLC/마스터가 이 장치에 접속 */
    MB_ROLE_CLIENT = 1, /* TCP master — 원격 슬레이브에 접속 */
} mb_role_t;

typedef enum {
    MB_REG_HOLDING = 0,
    MB_REG_INPUT = 1,
    MB_REG_COIL = 2,
    MB_REG_DISCRETE = 3,
} mb_reg_type_t;

#endif /* MB_TYPES_H */
