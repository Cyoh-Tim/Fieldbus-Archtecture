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
 *   map_words, map_bits, max_clients,
 *   layout ("melsec"|"legacy")
 *     생략 또는 melsec: 32/64비트 기본 CDAB, 문자열은 앞 문자가 하위 바이트.
 *     legacy: 예전 기본(ABCD, 앞 문자가 상위 바이트). protocol_params 에
 *     이 키 하나만 두면, endian/byte_order/word_order 와 string_swap 을
 *     생략한 포인트가 예전 배치를 유지한다.
 *
 * point:
 *   data_type (uint8..float64, bool, string/ascii, raw, bcd16/32 + 별칭)
 *   length, scale|gain, offset, byte_order, word_order, endian(ABCD|…)
 *   chars_per_word|chars_per_register, string_swap, trim_null, layout
 *   endian 을 생략하면 CDAB (MELSEC, 하위 워드가 D(n)). 포인트의 endian,
 *   byte_order, word_order 가 있으면 layout 보다 우선한다.
 *   string_swap 을 생략하면 true (MELSEC $MOV, 앞 문자 = 하위 바이트).
 *   JSON boolean 이 있으면 그 값이 우선한다.
 *   layout 은 protocol_params.layout 을 이 포인트에 한해 덮어쓴다.
 *   address.slmp 에도 endian/string_swap/layout 을 둘 수 있다.
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
