"""SLMP Binary 3E — 오라클: pymcprotocol (실제 TCP 로 slmp_oracle_server 에 접속).

pymcprotocol 은 실제 MELSEC PLC 와 쓰이는 클라이언트다. 비트 단위 데이터를 사양대로
1점=니블(앞 점이 상위 니블)로 인코딩한다.
slmp_oracle_server 시드: D0..D9 = 0x1000 + n.
"""
import socket
import struct

import pymcprotocol
import pytest

from conftest import known_defect


@pytest.fixture
def plc(slmp_dut):
    c = pymcprotocol.Type3E(plctype="Q")
    c.soc_timeout = 1
    c.connect("127.0.0.1", slmp_dut.port)
    yield c
    c.close()


def raw_3e(port, command: int, subcommand: int, data: bytes = b"", timeout=1.0):
    """3E 바이너리 요청을 직접 만든다 (오라클 라이브러리가 지원하지 않는 커맨드용)."""
    body = struct.pack("<HHH", 0x0010, command, subcommand) + data  # timer 4s
    req = struct.pack("<HBBHBH", 0x0050, 0x00, 0xFF, 0x03FF, 0x00, len(body)) + body
    # subheader 는 바이트 순서 그대로 50 00
    req = bytes([0x50, 0x00]) + req[2:]
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(req)
        try:
            hdr = s.recv(9)
        except socket.timeout:
            return None
        if len(hdr) < 9:
            return None
        (length,) = struct.unpack("<H", hdr[7:9])
        rest = s.recv(length)
        (end_code,) = struct.unpack("<H", rest[:2])
        return end_code


def test_word_batch_read(plc):
    assert plc.batchread_wordunits(headdevice="D0", readsize=10) == [
        0x1000 + n for n in range(10)
    ]


def test_word_batch_write_then_read(plc):
    plc.batchwrite_wordunits(headdevice="D100", values=[1, -2, 300])
    assert plc.batchread_wordunits(headdevice="D100", readsize=3) == [1, -2, 300]


def test_hex_numbered_device_word(plc):
    # W 는 16진 번호 디바이스. W1A = 26번째 워드.
    plc.batchwrite_wordunits(headdevice="W1A", values=[0x55AA])
    assert plc.batchread_wordunits(headdevice="W1A", readsize=1) == [0x55AA]
    # 같은 값을 워드 오프셋 26 으로도 읽을 수 있어야 한다 (16진 번호 해석 확인).
    assert plc.batchread_wordunits(headdevice="W10", readsize=11)[10] == 0x55AA


@known_defect("T10-1", "비트 단위(서브커맨드 0001)를 1점=1바이트로 처리한다. 사양은 1점=니블")
def test_bit_batch_write_then_read(plc):
    plc.batchwrite_bitunits(headdevice="M0", values=[1, 0, 1, 1])
    assert plc.batchread_bitunits(headdevice="M0", readsize=4) == [1, 0, 1, 1]


@known_defect("T10-1", "비트 단위 읽기 응답을 1점=1바이트(ON=01)로 보낸다. 사양은 상위 니블 (ON=10)")
def test_single_bit_read_format(plc):
    # 워드 단위로 M0..M15 = 0x0002 (M1 만 ON) 을 쓰고, 비트 단위로 M1 1점을 읽는다.
    plc.batchwrite_wordunits(headdevice="M0", values=[0x0002])
    assert plc.batchread_bitunits(headdevice="M1", readsize=1) == [1]


@known_defect("T10-6", "비트 디바이스를 워드 단위로 접근할 때 선두 번호를 워드 인덱스로 해석한다 (M16 → M256~)")
def test_bit_device_word_access_head_is_bit_number(plc):
    plc.batchwrite_wordunits(headdevice="M16", values=[0x0001])
    # M16..M31 워드의 bit0 = M16. 같은 영역을 M0 부터 2워드로 읽으면 두 번째 워드의 bit0 이다.
    assert plc.batchread_wordunits(headdevice="M0", readsize=2)[1] & 0x0001 == 1


@known_defect("T10-5", "미지원 커맨드에 C050 을 낸다. 사양은 C059 (C050 은 ASCII 변환 오류)")
def test_unsupported_command_end_code(slmp_dut):
    # 저장소 서버는 21바이트 미만 요청을 응답 없이 버리므로 더미 6바이트를 붙여 길이를 맞춘다.
    assert raw_3e(slmp_dut.port, 0x0619, 0x0000, bytes(6)) == 0xC059
