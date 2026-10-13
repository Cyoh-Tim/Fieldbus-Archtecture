"""EtherNet/IP — 오라클: pycomm3 (explicit), 사양 기반 인코더 (Forward Open, Class 1).

pycomm3 는 Logix·타사 장비와 쓰이는 독립 구현체다. pycomm3 가 지원하지 않는 Class 1
Forward Open 과 UDP I/O 는 CIP Vol 1/Vol 2 형식을 이 파일에서 직접 인코딩한다
(저장소 코드를 참조하지 않는다). Logix 기본 형식: O→T = 데이터 + 2(seq) + 4(Run/Idle),
T→O = 데이터 + 2(seq).

eip_oracle_adapter: input assembly 150 (8B, 01..08), output 101 (4B), config 100, 최소 RPI 8000 µs.
eip_oracle_originator: 스택 Originator 경로. 판정은 이 파일의 사양 기반 가짜 Logix 대상(FakeLogix).
eip_oracle_fbapi: fb_api + adapters/ethernetip (T1/T2). BUILD_DAEMON=ON 에서만 빌드된다 (CI oracle job 이 빌드한다).
EDS 는 CIP Vol 1 7장 형식으로 정적 검사한다.
"""
import itertools
import json
import re
import socket
import struct
import subprocess
import threading
import time

import pytest
from pycomm3 import CIPDriver
from pycomm3.cip import Services
from pycomm3.cip.data_types import UINT, UDINT, USINT, SHORT_STRING
from scapy.contrib.enipTCP import ENIPTCP, ENIPListIdentity

from conftest import REPO, Dut, dut_path, free_port, known_defect

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
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1.0)
    udp.bind(("127.0.0.1", 0))
    # T→O 목적지는 Sockaddr Info(T→O, 0x8001)로 준다. 없으면 사양상 Originator IP:2222 로 간다 (T11-6).
    rsp = cip_with_items(sess, forward_open(OUT_SIZE + 2, IN_SIZE + 2, next(_serial)),
                         [(0x8001, sockaddr_item("127.0.0.1", udp.getsockname()[1]))])
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()
    o2t_id, t2o_id = struct.unpack_from("<II", rsp, 4)
    o2t_api, t2o_api = struct.unpack_from("<II", rsp, 20)
    assert o2t_id != 0 and t2o_id != 0

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


def test_forward_open_logix_run_idle_format(sess):
    rsp = sess.cip(forward_open(OUT_SIZE + 6, IN_SIZE + 2, next(_serial)))
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()


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


# ================================================================ 선행 오라클 (큐 04·05·18·20·22·24·43·45·47·48)
# 아래 기대값의 근거는 CIP Vol 1 / EtherNet/IP Vol 2 필드 정의와 인수인계 문서
# (docs/reports/structure_handoff_20260930.md T1·T2·T5·T11) 의 기대값이다. 스택 코드를 참조하지 않는다.
DEFAULT_FO_PATH = bytes([0x20, 0x04, 0x24, CFG_ASM, 0x2C, OUT_ASM, 0x2C, IN_ASM])
ORIG_VENDOR, ORIG_SERIAL = 0x1337, 0xCAFEBABE
DUT_VENDOR, DUT_DEVICE_TYPE, DUT_PRODUCT = 0xABCD, 12, 1
DUT_MIN_RPI_US = 8000  # eip_oracle_adapter 의 rpi_us (장치 최소 RPI = cycle 8 ms)


def epath(cls: int, inst: int, attr=None) -> bytes:
    """Logical segments (CIP Vol 1 C-1.4.2): 8-bit 0x20/0x24/0x30, 16-bit 0x21/0x25/0x31."""
    def seg(s8, s16, v):
        return bytes([s8, v]) if v < 0x100 else bytes([s16, 0]) + struct.pack("<H", v)
    p = seg(0x20, 0x21, cls) + seg(0x24, 0x25, inst)
    if attr is not None:
        p += seg(0x30, 0x31, attr)
    return p


def mr(service: int, cls: int, inst: int, attr=None, data: bytes = b"") -> bytes:
    """Message Router 요청: service, path size(워드), path, data."""
    p = epath(cls, inst, attr)
    return bytes([service, len(p) // 2]) + p + data


def ext_status(rsp: bytes):
    return struct.unpack_from("<H", rsp, 4)[0] if rsp[3] else None


def reply_data(rsp: bytes) -> bytes:
    return rsp[4 + 2 * rsp[3]:]


def fo_ex(serial: int, *, o2t_size=OUT_SIZE + 2, t2o_size=IN_SIZE + 2, o2t_rpi=20000,
          t2o_rpi=20000, o2t_id=0, t2o_id=None, mult=0, transport=0x01,
          path=DEFAULT_FO_PATH) -> bytes:
    """Forward Open (0x54) — 필드 순서는 CIP Vol 1 3-5.4.1.2 (docs/protocols/ethernetip.md 5.6.1)."""
    if t2o_id is None:
        t2o_id = 0x7E000000 | serial  # P2P T→O 는 Originator 가 정한다
    body = struct.pack(
        "<BBIIHHIB3sIHIHB",
        0x0A, 0x0E, o2t_id, t2o_id, serial, ORIG_VENDOR, ORIG_SERIAL,
        mult, b"\0\0\0", o2t_rpi, ncp(o2t_size), t2o_rpi, ncp(t2o_size), transport,
    ) + bytes([len(path) // 2]) + path
    return bytes([0x54, 0x02, 0x20, 0x06, 0x24, 0x01]) + body


def sockaddr_item(ip: str, port: int) -> bytes:
    """Sockaddr Info item 데이터 (Vol 2 2-6.3.3): sin_family, sin_port, sin_addr 는 빅 엔디안, sin_zero 8."""
    return struct.pack(">HH4s8s", 2, port, socket.inet_aton(ip), b"\0" * 8)


def unconnected_item(pkt: bytes) -> bytes:
    data = pkt[24 + 6:]
    count = struct.unpack_from("<H", data, 0)[0]
    off = 2
    for _ in range(count):
        typ, ln = struct.unpack_from("<HH", data, off)
        if typ == 0x00B2:
            return data[off + 4: off + 4 + ln]
        off += 4 + ln
    raise AssertionError("unconnected data item 없음")


def cip_with_items(sess: Session, req: bytes, items) -> bytes:
    """SendRRData 에 추가 CPF 항목(예: 0x8001 Sockaddr Info T→O)을 붙여 보낸다."""
    extra = b"".join(struct.pack("<HH", t, len(d)) + d for t, d in items)
    cpf = struct.pack("<HH", 0x0000, 0) + struct.pack("<HH", 0x00B2, len(req)) + req + extra
    sess.sock.sendall(encap(0x006F, struct.pack("<IHH", 0, 0, 2 + len(items)) + cpf, sess.handle))
    return unconnected_item(sess._recv())


def io_socket(ip="127.0.0.1") -> socket.socket:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    u.bind((ip, 0))
    return u


def o2t_packet(conn_id: int, seq: int, data: bytes) -> bytes:
    """Class 1 O→T (modeless, asm+2 형식): 0x8002 Sequenced Address(conn id, encap seq) + 0x00B1 (CIP seq + data)."""
    return (struct.pack("<H", 2) + struct.pack("<HHII", 0x8002, 8, conn_id, seq)
            + struct.pack("<HH", 0x00B1, 2 + len(data)) + struct.pack("<H", seq & 0xFFFF) + data)


def recv_t2o(u: socket.socket, conn_id: int, timeout: float, with_tos=False):
    """conn_id 의 T→O 패킷 데이터(CIP seq 뒤)를 기다린다. 없으면 None."""
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            return None
        u.settimeout(left)
        try:
            pkt, anc, _, _ = u.recvmsg(2048, 64)
        except socket.timeout:
            return None
        if len(pkt) < 20 or struct.unpack_from("<H", pkt, 0)[0] != 2:
            continue
        typ, _ln, cid, _seq = struct.unpack_from("<HHII", pkt, 2)
        if typ != 0x8002 or cid != conn_id:
            continue
        typ, ln = struct.unpack_from("<HH", pkt, 14)
        data = pkt[20:18 + ln]
        if with_tos:
            tos = next((c[2][0] for c in anc if c[0] == socket.IPPROTO_IP and c[1] == socket.IP_TOS), None)
            return data, tos
        return data


def drain(u: socket.socket):
    u.setblocking(False)
    try:
        while True:
            u.recv(2048)
    except OSError:
        pass
    finally:
        u.setblocking(True)


def get_output(sess: Session) -> bytes:
    rsp = sess.cip(mr(0x0E, 0x04, OUT_ASM, 3))
    assert rsp[2] == 0x00, f"output assembly Get 실패: {rsp.hex()}"
    return reply_data(rsp)


def wait_output(sess: Session, want: bytes, timeout=1.0) -> bytes:
    deadline = time.monotonic() + timeout
    got = get_output(sess)
    while got != want and time.monotonic() < deadline:
        time.sleep(0.02)
        got = get_output(sess)
    return got


def open_class1(sess: Session, items=(), **kw):
    """Forward Open 성공 → (o2t_id, t2o_id, 응답)."""
    rsp = cip_with_items(sess, fo_ex(next(_serial), **kw), list(items))
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, f"Forward Open 실패: {rsp.hex()}"
    o2t_id, t2o_id = struct.unpack_from("<II", rsp, 4)
    return o2t_id, t2o_id, rsp


def list_identity_item(raw: bytes):
    """scapy 디섹터로 ListIdentity 응답의 CIP Identity 항목을 해석한다."""
    pkt = ENIPTCP(raw)
    assert pkt.commandId == 0x0063 and pkt.status == 0, pkt.summary()
    li = pkt[ENIPListIdentity]
    assert li.itemCount >= 1
    return li.items[0]


def recv_encap(s: socket.socket) -> bytes:
    hdr = b""
    while len(hdr) < 24:
        chunk = s.recv(24 - len(hdr))
        if not chunk:
            raise ConnectionError("TCP 연결이 닫힘")
        hdr += chunk
    (length,) = struct.unpack_from("<H", hdr, 2)
    body = b""
    while len(body) < length:
        chunk = s.recv(length - len(body))
        if not chunk:
            raise ConnectionError("TCP 연결이 닫힘")
        body += chunk
    return hdr + body


def encap_roundtrip(port: int, cmd: int, data=b"") -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
        s.sendall(encap(cmd, data))
        return recv_encap(s)


@pytest.fixture
def adapter_dut():
    """eip_oracle_adapter 를 추가 옵션으로 띄운다: adapter_dut("--acd")."""
    duts = []

    def start(*extra):
        tcp, udp = free_port(), free_port()
        d = Dut([dut_path("eip_oracle_adapter"), "--tcp-port", tcp, "--udp-port", udp, *extra], tcp)
        d.udp_port = udp
        duts.append(d)
        return d

    yield start
    for d in duts:
        d.stop()


# ---------------------------------------------------------------- EDS (T11-2, T5)
EDS_DIR = REPO / "stacks" / "ethernetip" / "eds"
EXAMPLE_CFG = REPO / "config" / "example.ethernetip.json"
# CIP Vol 1 Appendix C 기본 데이터 타입 코드 → 크기(바이트)
CIP_TYPE_SIZE = {0xC1: 1, 0xC2: 1, 0xC3: 2, 0xC4: 4, 0xC5: 8, 0xC6: 1, 0xC7: 2, 0xC8: 4,
                 0xC9: 8, 0xCA: 4, 0xCB: 8, 0xD1: 1, 0xD2: 2, 0xD3: 4, 0xD4: 8}


def parse_eds(text: str) -> dict:
    """EDS (CIP Vol 1 7장) 를 {section: {key: [field, ...]}} 로. `$` 주석, 따옴표 안 쉼표 처리."""
    sections, cur, stmt, inq = {}, None, "", False
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '"':
            inq = not inq
        if not inq and ch == "$":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if not inq and ch == "[" and not stmt.strip():
            end = text.index("]", i)
            cur = text[i + 1:end].strip()
            sections[cur] = {}
            i = end + 1
            stmt = ""
            continue
        if not inq and ch == ";":
            key, _, rest = stmt.partition("=")
            fields, buf, q = [], "", False
            for c in rest:
                if c == '"':
                    q = not q
                if c == "," and not q:
                    fields.append(buf.strip())
                    buf = ""
                else:
                    buf += c
            fields.append(buf.strip())
            sections.setdefault(cur, {})[key.strip()] = fields
            stmt = ""
        else:
            stmt += ch
        i += 1
    return sections


def eds_file():
    files = sorted(EDS_DIR.glob("*.eds"))
    assert files, f"EDS 파일 없음: {EDS_DIR}"
    return parse_eds(files[0].read_text(encoding="latin-1"))


def unquote(s: str) -> str:
    assert len(s) >= 2 and s.startswith('"') and s.endswith('"'), f"따옴표 문자열 아님: {s!r}"
    return s[1:-1]


def test_eds_connection1_field_layout():
    conn = eds_file()["Connection Manager"]["Connection1"]
    # trigger&transport, conn params, O→T RPI/size/format, T→O RPI/size/format,
    # config1 size/format, config2 size/format, name, help, path
    assert len(conn) == 15, f"{len(conn)} 필드: {conn}"
    assert conn[4] == f"Assem{OUT_ASM}" and conn[7] == f"Assem{IN_ASM}", conn
    path = unquote(conn[14]).replace(" ", "").upper()
    # Assembly 클래스 + config 100, 소비(O→T) 101 → 생산(T→O) 150 순서
    assert "20042464" in path and "2C652C96" in path, conn[14]


def test_eds_param_type_matches_size():
    params = eds_file()["Params"]
    assert params
    for name, f in params.items():
        code, size = int(f[4], 0), int(f[5], 0)
        assert CIP_TYPE_SIZE.get(code) == size, f"{name}: type {code:#x} size {size}"


def test_eds_port_entry_format():
    port = eds_file()["Port"]["Port1"]
    assert port[0] == "TCP", port
    unquote(port[1])
    assert unquote(port[2]).split()[:2] == ["20", "F5"], port  # TCP/IP Interface 객체 경로
    int(port[3], 0)


@known_defect("A20261011-1", "Param1 의 링크 경로가 크기 6, 경로 0 이다 (EPATH 문자열 아님). 사양: 크기 = 경로 바이트 수, "
              "링크가 없으면 둘 다 비움 (OpENer 샘플 EDS `,,`)")
def test_eds_param_link_path_consistent():
    params = eds_file()["Params"]
    assert params
    for name, f in params.items():
        size_s, path_s = f[1].strip(), f[2].strip()
        size = int(size_s, 0) if size_s else 0
        if size == 0:
            assert path_s == "", f"{name}: 링크 경로 크기 0 인데 경로 {path_s!r}"
            continue
        octets = unquote(path_s).split()
        assert len(octets) == size, f"{name}: 크기 {size} 인데 경로 {path_s!r}"
        assert all(len(o) == 2 and int(o, 16) >= 0 for o in octets), f"{name}: 경로 {path_s!r}"


def test_eds_rpi_param_minimum_matches_cycle():
    eds = eds_file()
    conn = eds["Connection Manager"]["Connection1"]
    min_us = json.loads(EXAMPLE_CFG.read_text())["cycle_ms"] * 1000
    for idx in (2, 5):  # O→T RPI, T→O RPI
        ref = conn[idx]
        assert re.fullmatch(r"Param\d+", ref), f"RPI 칸 {idx}: {ref!r}"
        p = eds["Params"][ref]
        assert int(p[4], 0) == 0xC8 and int(p[5], 0) == 4, p  # UDINT
        assert int(p[9], 0) == min_us, f"{ref} min {p[9]} (기대 {min_us})"


# ---------------------------------------------------------------- fb_api 경로 (T1, T2, T11-2 어댑터)
class FbApiDut:
    """eip_oracle_fbapi (fb_open + adapters/ethernetip, 실제 루프백 소켓)."""

    def __init__(self, cfg: dict, tmp_path):
        exe = dut_path("eip_oracle_fbapi")
        path = tmp_path / "eip_fbapi.json"
        path.write_text(json.dumps(cfg))
        pp = cfg["protocol_params"]
        self.port, self.udp_port = pp["port"], pp["udp_io_port"]
        self.proc = subprocess.Popen([str(exe), str(path)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
        self._lines = []
        self._cv = threading.Condition()
        threading.Thread(target=self._reader, daemon=True).start()
        first = self._next(5.0)
        if first != "READY":
            self.close()
            raise RuntimeError(f"eip_oracle_fbapi 시작 실패: {first}")

    def _reader(self):
        for line in self.proc.stdout:
            with self._cv:
                self._lines.append(line.strip())
                self._cv.notify()

    def _next(self, timeout=2.0):
        with self._cv:
            self._cv.wait_for(lambda: self._lines, timeout)
            return self._lines.pop(0) if self._lines else None

    def cmd(self, line: str) -> str:
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self._next()

    def write(self, name, typ, value):
        rsp = self.cmd(f"W {name} {typ} {value}")
        assert rsp == "OK 0", rsp

    def read(self, name, typ):
        _, rc, v = self.cmd(f"R {name} {typ}").split()
        return int(rc), (float(v) if typ == "f32" else int(v))

    def close(self):
        try:
            self.proc.stdin.write("Q\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


def fbapi_cfg(extra_params=None) -> dict:
    pp = {
        "role": "server", "bind_ip": "127.0.0.1", "port": free_port(), "udp_io_port": free_port(),
        "vendor_id": DUT_VENDOR, "device_type": DUT_DEVICE_TYPE, "product_code": DUT_PRODUCT,
        "serial_number": 0x12345678, "product_name": "FieldbusOracle",
        "input_assembly": IN_ASM, "output_assembly": OUT_ASM, "config_assembly": CFG_ASM,
        "input_size": 64, "output_size": 8, "rpi_us": 8000, "security_class": 0,
        "lldp_enable": False, "acd_enable": False, "mock": False,
    }
    pp.update(extra_params or {})

    def pt(name, access, dtype, asm, off, length, **kw):
        return dict(name=name, access=access, data_type=dtype, length=length,
                    address={"ethernetip": {"assembly": asm, "byte_offset": off, "length": length}}, **kw)

    return {
        "protocol": "ethernetip",
        "device": {"name": "eip_oracle", "role": "server"},
        "cycle_ms": 8,
        "protocol_params": pp,
        "points": [
            # 앱 → 스캐너 (input assembly 150, T→O)
            pt("status_word", "read", "uint16", IN_ASM, 32, 2),
            pt("count_i32", "read", "int32", IN_ASM, 36, 4),
            pt("temp_f32", "read", "float", IN_ASM, 40, 4),
            pt("status_scaled", "read", "uint16", IN_ASM, 44, 2, scale=0.1),
            # 스캐너 → 앱 (output assembly 101, O→T)
            pt("cmd_word", "write", "uint16", OUT_ASM, 0, 2),
            pt("setpoint_scaled", "write", "uint16", OUT_ASM, 2, 2, scale=0.1),
        ],
    }


@pytest.fixture
def fbapi(tmp_path):
    d = FbApiDut(fbapi_cfg(), tmp_path)
    yield d
    d.close()


def scanner_read_input(port: int) -> bytes:
    """스캐너(pycomm3) 가 input assembly 를 Get_Attribute_Single(attr 3) 로 읽는다."""
    d = CIPDriver(f"127.0.0.1:{port}")
    d.open()
    try:
        return bytes(get_attr(d, 0x04, IN_ASM, 3, None))
    finally:
        d.close()


def scanner_write_output(port: int, udp_port: int, data: bytes):
    """스캐너가 Class 1 연결을 열고 O→T 패킷으로 output assembly(8B) 를 보낸다."""
    s = Session(port)
    u = io_socket()
    try:
        o2t_id, _, _ = open_class1(s, o2t_size=8 + 2, t2o_size=64 + 2, mult=5)
        u.sendto(o2t_packet(o2t_id, 1, data), ("127.0.0.1", udp_port))
        time.sleep(0.1)
    finally:
        u.close()
        s.close()


@pytest.mark.parametrize("name,typ,value,off,wire", [
    ("status_word", "u32", 300, 32, struct.pack("<H", 300)),  # 인수인계 T1 재현: 기대 2C 01
    ("count_i32", "i32", -2, 36, struct.pack("<i", -2)),
    ("temp_f32", "f32", 12.5, 40, struct.pack("<f", 12.5)),
], ids=["uint16", "int32", "float32"])
def test_numeric_point_write_is_little_endian_on_wire(fbapi, name, typ, value, off, wire):
    fbapi.write(name, typ, value)
    raw = scanner_read_input(fbapi.port)
    assert raw[off:off + len(wire)] == wire, raw[off:off + len(wire)].hex(" ")


def test_numeric_point_read_from_scanner_little_endian(fbapi):
    scanner_write_output(fbapi.port, fbapi.udp_port, struct.pack("<H", 300) + bytes(6))
    assert fbapi.read("cmd_word", "u32") == (0, 300)


def test_scaled_point_write_raw_on_wire(fbapi):
    fbapi.write("status_scaled", "u32", 300)
    raw = scanner_read_input(fbapi.port)
    assert raw[44:46] == bytes([0xB8, 0x0B]), raw[44:46].hex(" ")


def test_scaled_point_read_from_scanner(fbapi):
    scanner_write_output(fbapi.port, fbapi.udp_port, bytes(2) + struct.pack("<H", 3000) + bytes(4))
    rc, v = fbapi.read("setpoint_scaled", "f32")
    assert rc == 0 and abs(v - 300.0) < 1e-3, (rc, v)


def test_adapter_minor_rev_from_config(tmp_path):
    d = FbApiDut(fbapi_cfg({"major_rev": 1, "minor_rev": 7}), tmp_path)
    try:
        ident = CIPDriver.list_identity(f"127.0.0.1:{d.port}")
    finally:
        d.close()
    assert ident["revision"] == {"major": 1, "minor": 7}, ident["revision"]


def test_eds_revision_matches_example_identity(tmp_path):
    eds = eds_file()["Device"]
    cfg = json.loads(EXAMPLE_CFG.read_text())
    pp = cfg["protocol_params"]
    pp.update(bind_ip="127.0.0.1", port=free_port(), udp_io_port=free_port(), security_class=0,
              mock=False, lldp_enable=False, acd_enable=False)
    pp.pop("iface", None)
    d = FbApiDut(cfg, tmp_path)
    try:
        ident = CIPDriver.list_identity(f"127.0.0.1:{d.port}")
    finally:
        d.close()
    want = {"major": int(eds["MajRev"][0]), "minor": int(eds["MinRev"][0])}
    assert ident["revision"] == want, f"Identity {ident['revision']} vs EDS {want}"


# ---------------------------------------------------------------- 발견 (T11-4)
def test_list_identity_over_udp(eip_dut):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(1.0)
    u.bind(("127.0.0.1", 0))
    try:
        u.sendto(encap(0x0063, b""), ("127.0.0.1", eip_dut.port))
        try:
            raw, _ = u.recvfrom(4096)
        except socket.timeout:
            raw = None
    finally:
        u.close()
    assert raw is not None, "UDP ListIdentity 무응답"
    assert list_identity_item(raw).productName == b"FieldbusOracle"


def test_list_identity_socket_address(eip_dut):
    item = list_identity_item(encap_roundtrip(eip_dut.port, 0x0063))
    assert (item.sinFamily, item.sinPort, item.sinAddress) == (2, eip_dut.port, "127.0.0.1")


def test_list_identity_status_state_match_identity(eip_dut, driver):
    item = list_identity_item(encap_roundtrip(eip_dut.port, 0x0063))
    status = get_attr(driver, 0x01, 1, 5, UINT)
    state = get_attr(driver, 0x01, 1, 8, USINT)
    assert (item.status, item.state) == (status, state)


def test_list_interfaces_supported(eip_dut):
    raw = encap_roundtrip(eip_dut.port, 0x0064)
    cmd, length, _sess, status = struct.unpack_from("<HHII", raw, 0)
    assert (cmd, status) == (0x0064, 0), raw[:24].hex(" ")
    assert length >= 2
    count = struct.unpack_from("<H", raw, 24)[0]
    off = 26
    for _ in range(count):
        _typ, ln = struct.unpack_from("<HH", raw, off)
        off += 4 + ln
    assert off == 24 + length


# ---------------------------------------------------------------- Connection ID·생산 목적지 (T11-6)
@known_defect("T11-6", "요청의 O→T Connection ID(0 아님)를 그대로 에코한다. 사양은 P2P O→T ID 를 Target 이 고른다 (요청값 무의미)")
def test_o2t_connection_id_chosen_by_target(sess):
    proposal = 0x13572468
    o2t_id, _, _ = open_class1(sess, o2t_id=proposal)
    assert o2t_id != proposal, f"요청값 {proposal:#x} 에코"


@known_defect("T11-6", "T→O 생산이 첫 O→T 패킷을 받아야 시작하고 0x8001 Sockaddr Info(T→O)를 무시한다. 사양은 연결 직후 Sockaddr(없으면 Originator:2222)로 생산")
def test_t2o_produced_to_sockaddr_without_o2t(sess):
    u = io_socket()
    try:
        _, t2o_id, _ = open_class1(sess, items=[(0x8001, sockaddr_item("127.0.0.1", u.getsockname()[1]))], mult=5)
        assert recv_t2o(u, t2o_id, timeout=1.0) is not None, "O→T 없이 T→O 가 오지 않음"
    finally:
        u.close()


@known_defect("T11-6", "Connection ID 만 맞으면 다른 IP(127.0.0.2)에서 온 O→T 패킷도 출력에 적용한다. 사양은 Originator IP 가 아닌 출발지 패킷 폐기")
def test_o2t_from_other_ip_ignored(sess, eip_dut):
    legit, spoof = io_socket("127.0.0.1"), io_socket("127.0.0.2")
    try:
        o2t_id, _, _ = open_class1(sess, mult=5)
        a, b = bytes([0xA1, 0xA2, 0xA3, 0xA4]), bytes([0xB1, 0xB2, 0xB3, 0xB4])
        legit.sendto(o2t_packet(o2t_id, 1, a), ("127.0.0.1", eip_dut.udp_port))
        assert wait_output(sess, a) == a, "정상 Originator 의 O→T 가 적용되지 않음 (전제)"
        spoof.sendto(o2t_packet(o2t_id, 2, b), ("127.0.0.1", eip_dut.udp_port))
        time.sleep(0.2)
        assert get_output(sess) == a, "다른 IP 의 O→T 가 출력에 적용됨"
    finally:
        legit.close()
        spoof.close()


@known_defect("T11-6", "O→T 패킷 출발지로 T→O 목적지를 매번 바꿔 다른 IP 가 T→O 를 가로챈다. 사양은 FO 에서 정한 목적지 유지")
def test_t2o_not_redirected_by_other_ip(sess, eip_dut):
    legit, spoof = io_socket("127.0.0.1"), io_socket("127.0.0.2")
    try:
        o2t_id, t2o_id, _ = open_class1(
            sess, items=[(0x8001, sockaddr_item("127.0.0.1", legit.getsockname()[1]))], mult=5)
        legit.sendto(o2t_packet(o2t_id, 1, bytes(4)), ("127.0.0.1", eip_dut.udp_port))
        assert recv_t2o(legit, t2o_id, timeout=1.0) is not None, "정상 Originator 가 T→O 를 받지 못함 (전제)"
        spoof.sendto(o2t_packet(o2t_id, 2, bytes(4)), ("127.0.0.1", eip_dut.udp_port))
        assert recv_t2o(spoof, t2o_id, timeout=0.5) is None, "T→O 가 다른 IP 로 넘어감"
    finally:
        legit.close()
        spoof.close()


# ---------------------------------------------------------------- 최소 RPI (T5 EIP)
@known_defect("T5 (EIP)", "최소 RPI(8000µs)보다 짧은 500µs Forward Open 을 수락한다. 사양은 0x01/0x0112 + 허용 RPI(추가 상태 6워드)")
def test_rpi_below_minimum_rejected_with_acceptable_rpi(sess):
    serial = next(_serial)
    rsp = sess.cip(fo_ex(serial, o2t_rpi=500, t2o_rpi=500))
    assert rsp[0] == 0xD4 and rsp[2] == 0x01, rsp.hex()
    assert rsp[3] == 6, f"additional status size {rsp[3]} 워드 (기대 6)"
    ext, o2t_type, t2o_type, o2t_rpi, t2o_rpi = struct.unpack_from("<HBBII", rsp, 4)
    assert ext == 0x0112, f"extended {ext:#06x}"
    # RPI type 2 = 허용 최소 RPI, 값은 cycle_ms×1000
    assert (o2t_type, t2o_type, o2t_rpi, t2o_rpi) == (2, 2, DUT_MIN_RPI_US, DUT_MIN_RPI_US)
    tail = rsp[16:]
    assert len(tail) == 10, f"Unsuccessful FO 응답 꼬리 {len(tail)}B (triad 8 + remaining path size + reserved)"
    assert struct.unpack_from("<HHI", tail) == (serial, ORIG_VENDOR, ORIG_SERIAL)


@known_defect("T5 (EIP)", "RPI 10000µs 를 수락하고 T→O API 에 10000 을 에코한다. 사양은 실제 생산 주기(8000µs 배수로 올림) 16000")
def test_accepted_rpi_api_is_actual_production_interval(sess):
    _, _, rsp = open_class1(sess, o2t_rpi=10000, t2o_rpi=10000)
    _o2t_api, t2o_api = struct.unpack_from("<II", rsp, 20)
    assert t2o_api == 16000, f"T→O API {t2o_api}"


# ---------------------------------------------------------------- Class 1 소비 규칙·FO 검사 (T11-8)
@known_defect("T11-8", "O→T 순번을 비교하지 않아 늦게 온 옛 패킷(seq 9)이 새 데이터(seq 10)를 덮어쓴다. 사양은 새롭지 않은 순번 폐기")
def test_o2t_older_sequence_discarded(sess, eip_dut):
    u = io_socket()
    try:
        o2t_id, _, _ = open_class1(sess, mult=5)
        new, old = bytes([0x10] * 4), bytes([0x09] * 4)
        u.sendto(o2t_packet(o2t_id, 10, new), ("127.0.0.1", eip_dut.udp_port))
        assert wait_output(sess, new) == new, "첫 O→T 가 적용되지 않음 (전제)"
        u.sendto(o2t_packet(o2t_id, 9, old), ("127.0.0.1", eip_dut.udp_port))
        time.sleep(0.2)
        assert get_output(sess) == new, "옛 순번 패킷이 출력에 적용됨"
    finally:
        u.close()


@known_defect("T11-8", "timeout multiplier 8(예약값)을 7로 클램프해 수락한다. 사양은 0x01/0x0133")
def test_reserved_timeout_multiplier_rejected(sess):
    rsp = sess.cip(fo_ex(next(_serial), mult=8))
    assert (rsp[2], ext_status(rsp)) == (0x01, 0x0133), rsp.hex()


def ekey(vendor=DUT_VENDOR, dtype=DUT_DEVICE_TYPE, product=DUT_PRODUCT, major=1, minor=1) -> bytes:
    """Electronic Key 세그먼트 (CIP Vol 1 C-1.4.2): 34 04 vendor type product major(bit7=compat 0) minor."""
    return bytes([0x34, 0x04]) + struct.pack("<HHHBB", vendor, dtype, product, major, minor)


def test_electronic_key_exact_match_accepted(sess):
    """판정 헬퍼 확인: 장치와 같은 키(0xABCD/12/1/1.1)는 수락된다."""
    open_class1(sess, path=ekey() + DEFAULT_FO_PATH)


@known_defect("T11-8", "Electronic Key 를 검사하지 않고 건너뛴다. 사양은 vendor/product 0x0114, device type 0x0115, revision 0x0116")
@pytest.mark.parametrize("key,ext", [
    (dict(vendor=0x1234), 0x0114),
    (dict(dtype=0x0099), 0x0115),
    (dict(major=9), 0x0116),
], ids=["vendor", "device_type", "major_rev"])
def test_electronic_key_mismatch_rejected(sess, key, ext):
    rsp = sess.cip(fo_ex(next(_serial), path=ekey(**key) + DEFAULT_FO_PATH))
    assert (rsp[2], ext_status(rsp)) == (0x01, ext), rsp.hex()


@known_defect("T11-8", "연결 경로의 Simple Data Segment(0x80, config 데이터)를 0x05 로 거부한다. 사양은 config 데이터와 함께 수락")
def test_forward_open_with_config_data_segment(adapter_dut):
    d = adapter_dut("--config-size", "2")
    s = Session(d.port)
    try:
        rsp = s.cip(fo_ex(next(_serial), path=DEFAULT_FO_PATH + bytes([0x80, 0x01, 0xAA, 0xBB])))
    finally:
        s.close()
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()


# ---------------------------------------------------------------- 표준 객체 속성 (T11-10)
@known_defect("T11-10", "Exclusive Owner 연결 후 Identity Status 에 Owned(bit 0) 대신 Configured(bit 2)를 세운다")
def test_identity_status_owned_bit_after_forward_open(sess, driver):
    open_class1(sess, mult=5)
    status = get_attr(driver, 0x01, 1, 5, UINT)
    assert status & 0x0001, f"Status {status:#06x}"


@known_defect("T11-10", "QoS 속성 번호가 3 밀렸다 (attr 1~5 = DSCP Urgent~Explicit, 6~8 없음). 사양은 attr 1 = 802.1Q Tag Enable(0), 4~8 = DSCP Urgent 55/Scheduled 47/High 43/Low 31/Explicit 27")
def test_qos_attribute_numbers(driver):
    got = {a: get_attr(driver, 0x48, 1, a, USINT) for a in (1, 4, 5, 6, 7, 8)}
    assert got == {1: 0, 4: 55, 5: 47, 6: 43, 7: 31, 8: 27}, got


@known_defect("T11-10", "QoS DSCP 를 소켓에 적용하지 않아 Scheduled 우선순위 T→O 가 TOS 0 으로 나간다. 사양은 DSCP Scheduled 47 (TOS 0xBC)")
def test_t2o_packets_carry_dscp_scheduled(sess, eip_dut):
    u = io_socket()
    try:
        o2t_id, t2o_id, _ = open_class1(
            sess, items=[(0x8001, sockaddr_item("127.0.0.1", u.getsockname()[1]))], mult=5)
        u.sendto(o2t_packet(o2t_id, 1, bytes(4)), ("127.0.0.1", eip_dut.udp_port))
        got = recv_t2o(u, t2o_id, timeout=1.0, with_tos=True)
        assert got is not None, "T→O 없음"
        assert got[1] is not None and got[1] >> 2 == 47, f"TOS {got[1]}"
    finally:
        u.close()


@known_defect("T11-10", "TCP/IP Interface attr 2 에 ACD 가능을 bit 2(DHCP)로 표시한다. 사양은 bit 7 = ACD capable")
def test_tcpip_config_capability_acd_bit(adapter_dut):
    d = adapter_dut("--acd")
    drv = CIPDriver(f"127.0.0.1:{d.port}")
    drv.open()
    try:
        cap = get_attr(drv, 0xF5, 1, 2, UDINT)
    finally:
        drv.close()
    assert cap & 0x80, f"Configuration Capability {cap:#010x}"


@known_defect("T11-10", "TCP/IP Interface attr 10/11 이 UDINT(ACD 상태/횟수)다. 사양은 attr 10 SelectAcd BOOL(1B), attr 11 LastConflictDetected STRUCT(35B)")
def test_tcpip_acd_attribute_types(adapter_dut):
    d = adapter_dut("--acd")
    s = Session(d.port)
    try:
        a10 = s.cip(mr(0x0E, 0xF5, 1, 10))
        a11 = s.cip(mr(0x0E, 0xF5, 1, 11))
    finally:
        s.close()
    assert a10[2] == 0 and len(reply_data(a10)) == 1, a10.hex()
    assert a11[2] == 0 and len(reply_data(a11)) == 35, a11.hex()


@known_defect("T11-10", "TCP/IP Interface attr 5(Interface Configuration)가 없다. 사양은 IP·mask·gateway·DNS 2개·domain 구조체")
def test_tcpip_interface_configuration_attr5(sess):
    rsp = sess.cip(mr(0x0E, 0xF5, 1, 5))
    assert rsp[2] == 0x00, rsp.hex()
    data = reply_data(rsp)
    assert len(data) >= 22, data.hex()  # 5×UDINT + STRING(길이 2 + 문자)
    (dlen,) = struct.unpack_from("<H", data, 20)
    assert len(data) in (22 + dlen, 22 + dlen + (dlen & 1)), data.hex()


@known_defect("T11-10", "TCP/IP Interface attr 13(Encapsulation Inactivity Timeout)이 없다. 사양은 UINT, 기본 120 s")
def test_tcpip_encapsulation_inactivity_timeout_attr13(driver):
    assert get_attr(driver, 0xF5, 1, 13, UINT) == 120


@known_defect("T11-10", "Port 객체 attr 1(Port Type)이 0 이다. 사양은 TCP/IP 포트 = 4")
def test_port_object_type_tcpip(driver):
    assert get_attr(driver, 0xF4, 1, 1, UINT) == 4


@known_defect("T11-10", "클래스 레벨 속성(instance 0)이 없다. 사양은 attr 1 Revision (UINT, ≥1)")
def test_identity_class_revision_attribute(sess):
    rsp = sess.cip(mr(0x0E, 0x01, 0, 1))
    assert rsp[2] == 0x00, rsp.hex()
    (rev,) = struct.unpack_from("<H", reply_data(rsp))
    assert rev >= 1


@known_defect("T11-10", "읽기 전용 속성(Identity Vendor ID) Set 에 0x05 로 응답한다. 사양은 0x0E Attribute not settable")
def test_set_read_only_attribute_not_settable(sess):
    rsp = sess.cip(mr(Services.set_attribute_single[0], 0x01, 1, 1, struct.pack("<H", 0x1111)))
    assert rsp[0] == 0x90 and rsp[2] == 0x0E, rsp.hex()


# ---------------------------------------------------------------- Originator (T11-12)
# 스택의 Originator 경로는 사양 기반 가짜 Logix 대상(Target)으로 본다. 저장소 코드를 쓰지 않는다.
# Logix 태그 서비스: Read Tag 0x4C (data: 요소 수 UINT) → 0xCC + 타입 UINT + 값,
# Write Tag 0x4D (data: 타입 UINT, 요소 수 UINT, 값) → 0xCD. 경로는 ANSI Extended Symbolic 0x91.
class FakeLogix:
    """EtherNet/IP 대상(Logix 역할). RegisterSession + SendRRData(UCMM) 만 처리한다."""

    def __init__(self, tags=None, split_reply=False):
        self.tags = dict(tags or {})  # name -> (type code, value bytes)
        self.split_reply = split_reply
        self.requests = []  # (service, path, data)
        self.port = free_port()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(4)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def symbol(path: bytes):
        if len(path) >= 2 and path[0] == 0x91:
            return path[2:2 + path[1]].decode("ascii", "replace")
        return None

    def _cip(self, req: bytes) -> bytes:
        service, words = req[0], req[1]
        path, data = req[2:2 + 2 * words], req[2 + 2 * words:]
        self.requests.append((service, path, data))
        name = self.symbol(path)
        if service == Services.read_tag[0] and name in self.tags:
            typ, val = self.tags[name]
            return bytes([0xCC, 0, 0, 0]) + struct.pack("<H", typ) + val
        if service == Services.write_tag[0] and name in self.tags and len(data) >= 4:
            typ, count = struct.unpack_from("<HH", data)
            if typ != self.tags[name][0] or count != 1:
                return bytes([0xCD, 0, 0xFF, 1]) + struct.pack("<H", 0x2107)  # 타입 불일치
            self.tags[name] = (typ, data[4:])
            return bytes([0xCD, 0, 0, 0])
        if service == 0x0E and path == bytes([0x20, 0x01, 0x24, 0x01, 0x30, 0x01]):
            return bytes([0x8E, 0, 0, 0]) + struct.pack("<H", 0x0001)  # Identity Vendor ID
        return bytes([service | 0x80, 0, 0x08, 0])  # Service not supported

    def _serve(self, conn):
        with conn:
            while True:
                try:
                    pkt = recv_encap(conn)
                except (ConnectionError, OSError):
                    return
                cmd, _ln, _sess, _st, ctx = struct.unpack_from("<HHII8s", pkt, 0)
                body = pkt[24:]
                if cmd == 0x0065:
                    out = body
                    session = 0x1234ABCD
                elif cmd == 0x006F:
                    rsp = self._cip(unconnected_item(pkt))
                    out = (struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0)
                           + struct.pack("<HH", 0x00B2, len(rsp)) + rsp)
                    session = _sess
                else:
                    return
                reply = struct.pack("<HHII8sI", cmd, len(out), session, 0, ctx, 0) + out
                try:
                    if self.split_reply:  # 한 응답을 TCP 두 조각으로 (재조립 필요)
                        conn.sendall(reply[:10])
                        time.sleep(0.1)
                        conn.sendall(reply[10:])
                    else:
                        conn.sendall(reply)
                except OSError:
                    return

    def close(self):
        self._srv.close()


def run_originator(port, *args):
    out = subprocess.run([str(dut_path("eip_oracle_originator")), "--port", str(port), *args],
                         capture_output=True, text=True, timeout=20).stdout
    line = next((ln for ln in out.splitlines() if ln.startswith("RC ")), None)
    assert line, f"DUT 출력 없음: {out!r}"
    parts = line.split()
    return int(parts[1]), bytes.fromhex(parts[2]) if len(parts) > 2 else b""


def test_originator_get_attribute_single():
    """판정 헬퍼 확인: 가짜 대상과 Get_Attribute_Single 이 통한다."""
    plc = FakeLogix()
    try:
        assert run_originator(plc.port, "get", "1", "1", "1") == (0, struct.pack("<H", 1))
    finally:
        plc.close()


@known_defect("T11-12", "태그 읽기에 Logix Read Tag(0x4C) 대신 심볼 경로 Get_Attribute_Single(0x0E)을 보낸다")
def test_originator_tag_read_uses_logix_read_tag():
    plc = FakeLogix({"Sensor1": (0x00C4, struct.pack("<i", 42))})
    try:
        rc, data = run_originator(plc.port, "tag-read", "Sensor1")
    finally:
        plc.close()
    services = [r[0] for r in plc.requests]
    assert Services.read_tag[0] in services, f"요청 서비스 {[hex(x) for x in services]}"
    _, path, req_data = next(r for r in plc.requests if r[0] == Services.read_tag[0])
    assert FakeLogix.symbol(path) == "Sensor1" and req_data == struct.pack("<H", 1)
    assert rc == 0 and data.endswith(struct.pack("<i", 42)), (rc, data.hex())


@known_defect("T11-12", "태그 쓰기에 Logix Write Tag(0x4D) 대신 심볼 경로 Set_Attribute_Single(0x10)을 보낸다")
def test_originator_tag_write_uses_logix_write_tag():
    plc = FakeLogix({"Sensor1": (0x00C4, struct.pack("<i", 42))})
    try:
        rc, _ = run_originator(plc.port, "tag-write", "Sensor1", struct.pack("<i", 7).hex())
    finally:
        plc.close()
    assert rc == 0, [(hex(s), p.hex(), d.hex()) for s, p, d in plc.requests]
    assert plc.tags["Sensor1"] == (0x00C4, struct.pack("<i", 7))


@known_defect("T11-12", "응답을 recv 한 번으로만 읽어 TCP 로 나뉘어 온 응답을 -EIO 로 버린다. 사양은 encapsulation 길이만큼 재조립")
def test_originator_reassembles_split_tcp_reply():
    plc = FakeLogix(split_reply=True)
    try:
        assert run_originator(plc.port, "get", "1", "1", "1") == (0, struct.pack("<H", 1))
    finally:
        plc.close()


# ---------------------------------------------------------------- 기타 (T11-13)
@known_defect("T11-13", "FO 직후 워치독을 RPI×배수(80 ms)로 바로 무장해 첫 O→T 전에 연결을 끊는다. 관례는 첫 패킷까지 10 s 여유")
def test_first_o2t_grace_after_forward_open(sess, eip_dut):
    u = io_socket()
    try:
        o2t_id, t2o_id, _ = open_class1(
            sess, items=[(0x8001, sockaddr_item("127.0.0.1", u.getsockname()[1]))], mult=0)  # 20 ms × 4
        time.sleep(0.4)
        drain(u)
        u.sendto(o2t_packet(o2t_id, 1, bytes(4)), ("127.0.0.1", eip_dut.udp_port))
        assert recv_t2o(u, t2o_id, timeout=1.0) is not None, "400 ms 뒤 첫 O→T 에 연결이 이미 끊김"
    finally:
        u.close()


@known_defect("T11-13", "Identity Reset 의 타입 파라미터를 무시하고 성공한다. 사양은 지원하지 않는 타입(0xFF)에 0x20 Invalid parameter")
def test_identity_reset_unsupported_type_rejected(sess):
    rsp = sess.cip(mr(Services.reset[0], 0x01, 1, data=bytes([0xFF])))
    assert rsp[0] == 0x85 and rsp[2] == 0x20, rsp.hex()


@known_defect("T11-13", "큰 Assembly(1000B) Get 이 UCMM 응답 버퍼(568B) 때문에 0x02 로 실패한다. 사양은 전체 데이터 또는 0x11 Reply data too large")
def test_large_assembly_get_not_truncated(adapter_dut):
    d = adapter_dut("--input-size", "1000")
    s = Session(d.port)
    try:
        rsp = s.cip(mr(0x0E, 0x04, IN_ASM, 3))
    finally:
        s.close()
    if rsp[2] == 0x11:
        return
    assert rsp[2] == 0x00, rsp[:8].hex()
    assert reply_data(rsp) == bytes((i + 1) & 0xFF for i in range(1000)), f"{len(reply_data(rsp))}B"


@known_defect("T11-13", "8 KB 를 넘는 encapsulation 메시지에 TCP 연결을 끊는다. 사양은 최대 65511 바이트, 연결 유지")
def test_large_encapsulation_keeps_session(sess):
    big = mr(Services.set_attribute_single[0], 0x04, OUT_ASM, 3, bytes(9000))
    sess.sock.sendall(encap(0x006F, send_rr(big), sess.handle))
    sess.sock.settimeout(2)
    first = sess._recv()
    assert struct.unpack_from("<H", first, 0)[0] == 0x006F
    rsp = sess.cip(mr(0x0E, 0x01, 1, 1))
    assert rsp[2] == 0x00 and reply_data(rsp) == struct.pack("<H", DUT_VENDOR)


# ---------------------------------------------------------------- Forward Close 출발지 (A20261012-2)
# Forward Close 는 triad 로 연결을 찾지만, 독립 Target 구현은 그 Forward Close 를 보낸 IP 가
# Forward Open 을 보낸 originator IP 와 같은지도 본다. 다르면 연결을 닫지 않고 General 0x0F
# (Privilege violation) — OpENer cipconnectionmanager.c ForwardClose (`WrongCloser` → 0x0F),
# CIPster cipconnectionmanager.cc ("Vol2 3-3.10 Forward_Close" → kCipErrorPrivilegeViolation).
# 같은 IP 의 다른 TCP 세션(스캐너 재접속)은 허용해야 한다 (Class 1 은 TCP 세션에 묶이지 않는다).
class SessionFrom(Session):
    """출발지 IP 를 지정한 세션 (loopback 127.0.0.0/8 은 어느 주소든 bind 된다)."""

    def __init__(self, port, src_ip):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=2,
                                             source_address=(src_ip, 0))
        self.sock.sendall(encap(0x0065, struct.pack("<HH", 1, 0)))
        hdr = self._recv()
        self.handle = struct.unpack_from("<I", hdr, 4)[0]
        assert self.handle != 0


def forward_close(serial, vendor=ORIG_VENDOR, orig_serial=ORIG_SERIAL,
                  path=DEFAULT_FO_PATH):
    """Forward_Close (0x4E) — CIP Vol 1 Table 3-5.21: priority, ticks, triad, path size, reserved, path."""
    body = struct.pack("<BBHHIBB", 0x0A, 0x0E, serial, vendor, orig_serial, len(path) // 2, 0) + path
    return bytes([0x4E, 0x02, 0x20, 0x06, 0x24, 0x01]) + body


def _open_held(s):
    """mult=7 (RPI 20 ms × 4 × 128 ≈ 10 s) 로 열어 I/O 없이도 테스트 동안 워치독이 회수하지 않게 한다."""
    serial = next(_serial)
    rsp = cip_with_items(s, fo_ex(serial, mult=7), [])
    assert rsp[0] == 0xD4 and rsp[2] == 0x00, rsp.hex()
    return serial


def _still_open(s, serial):
    """같은 triad 의 Forward Open 이 0x01/0x0100 (중복) 이면 연결이 살아 있다."""
    rsp = s.cip(fo_ex(serial, mult=7))
    return rsp[2] == 0x01 and ext_status(rsp) == 0x0100, rsp.hex()


@known_defect("A20261012-2", "다른 IP 의 Forward Close 가 triad 만 맞으면 남의 Class 1 연결을 닫는다. "
              "OpENer·CIPster 는 연결을 두고 General 0x0F")
def test_forward_close_from_other_ip_rejected(sess, eip_dut):
    serial = _open_held(sess)
    other = SessionFrom(eip_dut.port, "127.0.0.2")
    try:
        rsp = other.cip(forward_close(serial))
    finally:
        other.close()
    alive, raw = _still_open(sess, serial)
    assert alive, f"연결이 닫힘 (다른 IP FC 응답 {rsp.hex()}, 중복 FO 응답 {raw})"
    assert rsp[0] == 0xCE and rsp[2] == 0x0F, rsp.hex()


def test_forward_close_same_ip_new_session_allowed(eip_dut):
    """대조군: 같은 IP 의 새 TCP 세션(재접속)에서 온 Forward Close 는 성공한다."""
    a = Session(eip_dut.port)
    serial = _open_held(a)
    a.close()
    time.sleep(0.1)
    b = Session(eip_dut.port)
    try:
        rsp = b.cip(forward_close(serial))
    finally:
        b.close()
    assert rsp[0] == 0xCE and rsp[2] == 0x00, rsp.hex()
    assert rsp[4:12] == struct.pack("<HHI", serial, ORIG_VENDOR, ORIG_SERIAL), rsp.hex()
