#ifndef SLMP_ADAPTER_H
#define SLMP_ADAPTER_H

#include "protocol_adapter.h"

/*
 * SLMP adapter — 센서/PLC 통신 가이드 표기를 최대한 수용.
 *
 * protocol_params:
 *   role (client|server), plc_ip|ip|host, bind_ip, port,
 *   network_no, pc_no, dest_module_io|io_no, dest_multidrop|station_no,
 *   monitoring_timer, timeout_ms, frame ("3E"|"3E_binary"),
 *   map_words, map_bits, max_clients
 *
 * point:
 *   data_type (uint8..float64, bool, string/ascii, raw, bcd16/32 + 별칭)
 *   length, scale|gain, offset, byte_order, word_order, endian(ABCD|…)
 *   chars_per_word|chars_per_register, string_swap, trim_null
 *
 * address.slmp:
 *   device_code|device|dev ("D"|"M"|"X"|"ZR"|"0xA8"|…)
 *   start|address|addr|head (숫자, "100", "D100", "X1A")
 *   offset, quantity|count, bit|bit_offset, bit_count
 *   unit ("word"|"bit"), soft_device (raw code override)
 *
 * access (PLC 관점, Modbus/PROFINET과 동일):
 *   read      — PLC가 읽는 값 → 앱 write_point → 클라이언트가 PLC에 write
 *   write     — PLC가 쓰는 값 → 앱 read_point/poll → 클라이언트가 PLC에서 read
 *   readwrite — 양쪽
 *
 * Binary 3E 프레임 (Mitsubishi SLMP Reference Manual). ASCII/4E는 예약.
 */
protocol_adapter_t *slmp_adapter_create(void);

#endif /* SLMP_ADAPTER_H */
