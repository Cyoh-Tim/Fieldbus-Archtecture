"""Modbus TCP — 오라클: pymodbus (실제 TCP 로 mb_seeded_server 에 접속).

mb_seeded_server 시드: holding[i]=0xA000+i, input[i]=0xB000+i, coil[i]=i&1,
discrete[i]=(i>>1)&1 (i<256), holding 300..301 = float 1.5 (ABCD), holding 400.. = "ABCD".
"""
import socket
import struct

import pytest
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ExceptionResponse

from conftest import known_defect

UNIT = 1


@pytest.fixture
def client(mb_dut):
    c = ModbusTcpClient("127.0.0.1", port=mb_dut.port, timeout=2, retries=0)
    assert c.connect()
    yield c
    c.close()


def raw_request(port, pdu: bytes, unit=UNIT, tid=0x1234, timeout=1.0):
    """MBAP 를 직접 붙여 보낸다 (pymodbus 가 클라이언트 쪽에서 막는 비정상 요청용)."""
    adu = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit) + pdu
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(adu)
        try:
            hdr = s.recv(7)
        except socket.timeout:
            return None
        if len(hdr) < 7:
            return None
        _, _, length, _ = struct.unpack(">HHHB", hdr)
        return s.recv(length - 1)


def test_fc03_read_holding(client):
    rr = client.read_holding_registers(0, count=10, device_id=UNIT)
    assert not rr.isError(), rr
    assert rr.registers == [0xA000 + i for i in range(10)]


def test_fc04_read_input(client):
    rr = client.read_input_registers(5, count=3, device_id=UNIT)
    assert not rr.isError(), rr
    assert rr.registers == [0xB005, 0xB006, 0xB007]


def test_fc01_fc02_bit_packing(client):
    rc = client.read_coils(0, count=10, device_id=UNIT)
    assert not rc.isError(), rc
    assert rc.bits[:10] == [bool(i & 1) for i in range(10)]
    rd = client.read_discrete_inputs(0, count=10, device_id=UNIT)
    assert not rd.isError(), rd
    assert rd.bits[:10] == [bool((i >> 1) & 1) for i in range(10)]


def test_fc06_fc16_write_then_read(client):
    assert not client.write_register(500, 0x1234, device_id=UNIT).isError()
    assert not client.write_registers(501, [1, 2, 3], device_id=UNIT).isError()
    rr = client.read_holding_registers(500, count=4, device_id=UNIT)
    assert rr.registers == [0x1234, 1, 2, 3]


def test_fc05_fc15_write_coils(client):
    assert not client.write_coil(600, True, device_id=UNIT).isError()
    assert not client.write_coils(601, [True, False, True], device_id=UNIT).isError()
    rc = client.read_coils(600, count=4, device_id=UNIT)
    assert rc.bits[:4] == [True, True, False, True]


def test_fc23_read_write_multiple(client):
    rr = client.readwrite_registers(
        read_address=700, read_count=2, write_address=700, values=[7, 8], device_id=UNIT
    )
    assert not rr.isError(), rr
    # 사양: 쓰기를 먼저 수행하고 읽는다.
    assert rr.registers == [7, 8]


def test_float_abcd_decode(client):
    rr = client.read_holding_registers(300, count=2, device_id=UNIT)
    value = client.convert_from_registers(rr.registers, client.DATATYPE.FLOAT32)
    assert value == pytest.approx(1.5)


def test_illegal_address_is_exception_02(mb_dut):
    # 주소 범위 밖 (맵 1000 워드) → ILLEGAL DATA ADDRESS
    rsp = raw_request(mb_dut.port, struct.pack(">BHH", 0x03, 990, 20))
    assert rsp == bytes([0x83, 0x02])


def test_illegal_function_is_exception_01(mb_dut):
    rsp = raw_request(mb_dut.port, bytes([0x41]))
    assert rsp == bytes([0xC1, 0x01])


@known_defect("T9-4", "수량 위반(0 또는 >125)에 예외 02 를 낸다. 사양은 03 (ILLEGAL DATA VALUE)")
@pytest.mark.parametrize("qty", [0, 126])
def test_fc03_bad_quantity_is_exception_03(mb_dut, qty):
    rsp = raw_request(mb_dut.port, struct.pack(">BHH", 0x03, 0, qty))
    assert rsp == bytes([0x83, 0x03])


@known_defect("T9-6", "Unit ID 0xFF 요청을 무시한다. TCP 구현 가이드는 직접 연결 장치에 0xFF 를 권고")
def test_unit_id_ff_is_answered(mb_dut):
    rsp = raw_request(mb_dut.port, struct.pack(">BHH", 0x03, 0, 1), unit=0xFF)
    assert rsp == bytes([0x03, 0x02, 0xA0, 0x00])
