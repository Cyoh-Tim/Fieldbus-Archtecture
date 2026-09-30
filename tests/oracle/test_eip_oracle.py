"""EtherNet/IP — 오라클: pycomm3 (explicit), 사양 기반 인코더 (Forward Open, Class 1).

pycomm3 는 Logix·타사 장비와 쓰이는 독립 구현체다. pycomm3 가 지원하지 않는 Class 1
Forward Open 과 UDP I/O 는 CIP Vol 1/Vol 2 형식을 이 파일에서 직접 인코딩한다
(저장소 코드를 참조하지 않는다). Logix 기본 형식: O→T = 데이터 + 2(seq) + 4(Run/Idle),
T→O = 데이터 + 2(seq).

eip_oracle_adapter: input assembly 150 (8B, 01..08), output 101 (4B), config 100.
"""
import itertools
import socket
import struct

import pytest
from pycomm3 import CIPDriver
from pycomm3.cip.data_types import UINT, UDINT, SHORT_STRING

from conftest import known_defect

IN_ASM, OUT_ASM, CFG_ASM = 150, 101, 100
IN_SIZE, OUT_SIZE = 8, 4
_serial = itertools.count(0x100)


# ---------------------------------------------------------------- encoders
def encap(cmd: int, data: bytes, session: int = 0) -> bytes:
    return struct.pack("<HHII8sI", cmd, len(data), session, 0, b"oracle00", 0) + data


def send_rr(cip: bytes) -> bytes:
    items = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(cip)) + cip
    return struct.pack("<IHH", 0, 0, 2) + items


def ncp(size: int, p2p=True, prio=0b10) -> int:
    """Network Connection Parameters (16-bit). type 10=P2P, 01=multicast."""
    ctype = 0b10 if p2p else 0b01
    return (ctype << 13) | (prio << 10) | size


def forward_open(o2t_size: int, t2o_size: int, conn_serial: int, rpi_us=20000,
                 t2o_p2p=True, transport=0x01) -> bytes:
    path = bytes([0x20, 0x04, 0x24, CFG_ASM, 0x2C, OUT_ASM, 0x2C, IN_ASM])
    body = struct.pack(
        "<BBIIHHIB3sIHIHB",
        0x0A, 0x0E,                 # priority/tick, timeout ticks
        0, 0x7E000001,              # O→T ID (target 가 고름), T→O ID 제안
        conn_serial, 0x1337, 0xCAFEBABE,
        0, b"\0\0\0",               # timeout multiplier x4
        rpi_us, ncp(o2t_size),
        rpi_us, ncp(t2o_size, p2p=t2o_p2p),
        transport,                  # class 1, cyclic
    ) + bytes([len(path) // 2]) + path
    return bytes([0x54, 0x02, 0x20, 0x06, 0x24, 0x01]) + body


class Session:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        self.sock.sendall(encap(0x0065, struct.pack("<HH", 1, 0)))
        hdr = self._recv()
        self.handle = struct.unpack_from("<I", hdr, 4)[0]
        assert self.handle != 0

    def _recv(self):
        hdr = b""
        while len(hdr) < 24:
            chunk = self.sock.recv(24 - len(hdr))
            if not chunk:
                raise ConnectionError("closed")
            hdr += chunk
        (length,) = struct.unpack_from("<H", hdr, 2)
        data = b""
        while len(data) < length:
            data += self.sock.recv(length - len(data))
        return hdr + data

    def cip(self, req: bytes) -> bytes:
        """SendRRData → MR 응답 (service, reserved, gen status, ext size, ...)."""
        self.sock.sendall(encap(0x006F, send_rr(req), self.handle))
        pkt = self._recv()
        data = pkt[24 + 6:]
        count = struct.unpack_from("<H", data, 0)[0]
        off = 2
        for _ in range(count):
            typ, ln = struct.unpack_from("<HH", data, off)
            if typ == 0x00B2:
                return data[off + 4: off + 4 + ln]
            off += 4 + ln
        raise AssertionError("unconnected data item 없음")

    def close(self):
        self.sock.close()


@pytest.fixture
def sess(eip_dut):
    s = Session(eip_dut.port)
    yield s
    s.close()


# ---------------------------------------------------------------- pycomm3
@pytest.fixture
def driver(eip_dut):
    d = CIPDriver(f"127.0.0.1:{eip_dut.port}")
    d.open()
    yield d
    d.close()


def get_attr(driver, cls, inst, attr, dtype):
    tag = driver.generic_message(
        service=0x0E, class_code=cls, instance=inst, attribute=attr,
        data_type=dtype, connected=False, route_path=False,
    )
    assert tag.error is None, tag.error
    return tag.value


def test_identity_attributes(driver):
    assert get_attr(driver, 0x01, 1, 1, UINT) == 0xABCD
    assert get_attr(driver, 0x01, 1, 6, UDINT) == 0x12345678
    assert get_attr(driver, 0x01, 1, 7, SHORT_STRING) == "FieldbusOracle"


def test_input_assembly_get(driver):
    raw = get_attr(driver, 0x04, IN_ASM, 3, None)
    assert bytes(raw) == bytes(range(1, 9))


def test_list_identity_tcp(eip_dut):
    ident = CIPDriver.list_identity(f"127.0.0.1:{eip_dut.port}")
    assert ident is not None
    assert ident["vendor"] or ident.get("vendor_id") is not None
    assert ident["product_name"] == "FieldbusOracle"


# ---------------------------------------------------------------- Forward Open
def test_forward_open_modeless_and_class1_io(sess, eip_dut):
    rsp = sess.cip(forward_open(OUT_SIZE + 2, IN_SIZE + 2, next(_serial)))
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()
    o2t_id, t2o_id = struct.unpack_from("<II", rsp, 4)
    o2t_api, t2o_api = struct.unpack_from("<II", rsp, 20)
    assert o2t_id != 0 and t2o_id != 0

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1.0)
    udp.bind(("127.0.0.1", 0))
    out = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    items = (struct.pack("<HHII", 0x8002, 8, o2t_id, 1)
             + struct.pack("<HH", 0x00B1, 2 + len(out)) + struct.pack("<H", 1) + out)
    udp.sendto(struct.pack("<H", 2) + items, ("127.0.0.1", eip_dut.udp_port))
    pkt, _ = udp.recvfrom(1500)
    udp.close()
    count = struct.unpack_from("<H", pkt, 0)[0]
    assert count == 2
    typ, ln, conn_id, _seq = struct.unpack_from("<HHII", pkt, 2)
    assert typ == 0x8002 and conn_id == t2o_id
    typ, ln = struct.unpack_from("<HH", pkt, 14)
    assert typ == 0x00B1 and ln == 2 + IN_SIZE
    assert pkt[20:20 + IN_SIZE] == bytes(range(1, 9))


@known_defect("T11-1", "O→T 32-bit Run/Idle 헤더 형식(데이터+6)을 크기 오류로 거부한다")
def test_forward_open_logix_run_idle_format(sess):
    rsp = sess.cip(forward_open(OUT_SIZE + 6, IN_SIZE + 2, next(_serial)))
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()


@known_defect("T11-3", "Forward Open 실패 응답이 General 0x01 + Extended + triad·Remaining Path Size 형식이 아니다")
def test_forward_open_bad_size_error_format(sess):
    serial = next(_serial)
    rsp = sess.cip(forward_open(OUT_SIZE + 2, 99, serial))
    assert rsp[0] == 0xD4
    assert rsp[2] == 0x01, f"general status {rsp[2]:#x}"
    ext_words = rsp[3]
    assert ext_words >= 1
    (ext,) = struct.unpack_from("<H", rsp, 4)
    assert ext in (0x0109, 0x0128), f"extended {ext:#06x}"
    tail = rsp[4 + 2 * ext_words:]
    assert len(tail) == 10
    conn_serial, vendor, orig_serial, _rps, _res = struct.unpack("<HHIBB", tail)
    assert (conn_serial, vendor, orig_serial) == (serial, 0x1337, 0xCAFEBABE)


@known_defect("T11-5", "두 번째 Exclusive Owner 연결(다른 triad)도 수락한다. 사양은 0x01/0x0106")
def test_second_exclusive_owner_rejected(sess):
    first = sess.cip(forward_open(OUT_SIZE + 2, IN_SIZE + 2, next(_serial)))
    assert first[2] == 0x00, first.hex()
    second = sess.cip(forward_open(OUT_SIZE + 2, IN_SIZE + 2, next(_serial)))
    assert second[2] == 0x01
    assert struct.unpack_from("<H", second, 4)[0] == 0x0106


@known_defect("T11-7", "transport class 3 Forward Open 을 Class 1 슬롯으로 수락한다. 사양은 0x01/0x0103")
def test_class3_transport_to_assembly_rejected(sess):
    rsp = sess.cip(forward_open(OUT_SIZE + 2, IN_SIZE + 2, next(_serial), transport=0xA3))
    assert rsp[2] == 0x01


@known_defect("T11-9", "NOP 에 응답한다. 사양은 무응답")
def test_nop_has_no_reply(sess):
    sess.sock.sendall(encap(0x0000, b"", sess.handle))
    sess.sock.settimeout(0.5)
    with pytest.raises(socket.timeout):
        sess._recv()
