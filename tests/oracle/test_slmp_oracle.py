"""SLMP Binary 3E — 오라클: pymcprotocol (실제 TCP 로 slmp_oracle_server 에 접속).

pymcprotocol 은 실제 MELSEC PLC 와 쓰이는 클라이언트다. 비트 단위 데이터를 사양대로
1점=니블(앞 점이 상위 니블)로 인코딩한다.
slmp_oracle_server 시드: D0..D9 = 0x1000 + n.
어댑터 설정·포인트 배치는 mb_slmp_oracle_app(fb_api 앱, 서버 모드 어댑터)이 DUT 다.
"""
import json
import socket
import struct
import subprocess
import threading
import time

import pymcprotocol
import pytest

from conftest import dut_path, free_port, known_defect, wait_tcp


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


def test_bit_batch_write_then_read(plc):
    plc.batchwrite_bitunits(headdevice="M0", values=[1, 0, 1, 1])
    assert plc.batchread_bitunits(headdevice="M0", readsize=4) == [1, 0, 1, 1]


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


# ---------------------------------------------------------------- 클라이언트 경로
# pymcprotocol 은 클라이언트라서 스택의 클라이언트 경로는 사양 기반 가짜 PLC 로 본다.
# 가짜 PLC 는 0401 워드 읽기에 D[n] = 0x1000 + n 을 돌려주고, 첫 요청만 DELAY 초 늦게 답한다.
class FakePlc:
    """Binary 3E 서버 (MELSEC 역할). 저장소 코드를 쓰지 않는다."""

    def __init__(self, first_delay_s: float):
        self.first_delay_s = first_delay_s
        self.port = free_port()
        self._first = True
        self._lock = threading.Lock()
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(4)
        self.accepts = 0
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        with conn:
            while True:
                hdr = conn.recv(9)
                if len(hdr) < 9:
                    return
                (length,) = struct.unpack_from("<H", hdr, 7)
                body = b""
                while len(body) < length:
                    chunk = conn.recv(length - len(body))
                    if not chunk:
                        return
                    body += chunk
                # body: timer(2) command(2) subcommand(2) head(3) device(1) points(2)
                head = int.from_bytes(body[6:9], "little")
                (points,) = struct.unpack_from("<H", body, 10)
                data = b"".join(struct.pack("<H", 0x1000 + head + i) for i in range(points))
                rsp = bytes([0xD0, 0x00]) + hdr[2:7] + struct.pack("<HH", 2 + len(data), 0) + data
                with self._lock:
                    delay, self._first = (self.first_delay_s if self._first else 0.0), False
                if delay:
                    time.sleep(delay)
                try:
                    conn.sendall(rsp)
                except OSError:
                    return

    def close(self):
        self._srv.close()


def run_client(port, count, interval_ms=300, timeout_s=60):
    out = subprocess.run(
        [str(dut_path("slmp_oracle_client")), "--port", str(port),
         "--count", str(count), "--interval-ms", str(interval_ms)],
        capture_output=True, text=True, timeout=timeout_s,
    ).stdout
    reads = []
    for line in out.splitlines():
        if line.startswith("READ "):
            _, head, rc, value = line.split()
            reads.append((int(head), int(rc), int(value, 16)))
    return reads


def test_client_reads_correct_values():
    plc = FakePlc(first_delay_s=0)
    try:
        reads = run_client(plc.port, 5, interval_ms=50)
    finally:
        plc.close()
    assert [(h, rc, v) for h, rc, v in reads] == [(n, 0, 0x1000 + n) for n in range(1, 6)]


def test_client_never_returns_stale_value_after_timeout():
    """T10-2: 타임아웃 뒤 늦게 온 이전 응답을 다음 요청의 결과로 돌려주면 안 된다.

    첫 응답을 스택의 어떤 타임아웃(설정 1 s, 감시 타이머 4 s)보다 늦게 보낸다.
    실패(rc<0)는 허용하지만, 성공(rc==0)한 읽기는 반드시 자기 주소의 값이어야 한다.
    """
    plc = FakePlc(first_delay_s=6.0)
    try:
        reads = run_client(plc.port, 12, interval_ms=300)
    finally:
        plc.close()
    ok = [(h, v) for h, rc, v in reads if rc == 0]
    assert ok, f"성공한 읽기가 하나도 없음: {reads}"
    wrong = [(h, v) for h, v in ok if v != 0x1000 + h]
    assert not wrong, f"다른 주소의 값이 돌아옴 (head, value): {wrong}"


# ---------------------------------------------------------------- 어댑터 (fb_api 앱)
# mb_slmp_oracle_app 은 공개 fb_api.h 만 쓰는 앱이다. 서버 모드 어댑터에 앱이 값을 쓰면
# pymcprotocol 이 실제 MELSEC 클라이언트처럼 디바이스를 읽어 주소와 배치를 판정한다.
class AppPipe:
    """mb_slmp_oracle_app 줄 프로토콜 클라이언트."""

    def __init__(self, cfg_path):
        self.proc = subprocess.Popen(
            [str(dut_path("mb_slmp_oracle_app")), str(cfg_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.opened = self.proc.stdout.readline().split()

    def cmd(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self.proc.stdout.readline().split()

    def close(self):
        try:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture
def slmp_app(tmp_path):
    """points 로 서버 모드 SLMP 어댑터를 띄우고 (앱, pymcprotocol 클라이언트) 를 돌려준다."""
    apps = []

    def make(points, cycle_ms=5):
        port = free_port()
        cfg = {
            "protocol": "slmp",
            "device": {"name": "oracle", "role": "server"},
            "cycle_ms": cycle_ms,
            "protocol_params": {"role": "server", "ip": "127.0.0.1", "port": port},
            "points": points,
        }
        path = tmp_path / "slmp.json"
        path.write_text(json.dumps(cfg))
        app = AppPipe(path)
        apps.append(app)
        assert app.opened == ["OPEN", "0"], app.opened
        assert app.cmd("START") == ["START", "0"]
        wait_tcp(port)
        c = pymcprotocol.Type3E(plctype="Q")
        c.soc_timeout = 1
        c.connect("127.0.0.1", port)
        apps.append(c)
        return app, c

    yield make
    for a in reversed(apps):
        a.close()


def u16(values):
    return [v & 0xFFFF for v in values]


def test_adapter_word_point_roundtrip(slmp_app):
    """DUT 확인용: D 워드 포인트는 앱 쓰기 → pymcprotocol 읽기, pymcprotocol 쓰기 → 앱 읽기가 맞는다."""
    app, plc = slmp_app([
        {"name": "p", "access": "readwrite", "data_type": "uint16",
         "address": {"slmp": {"device_code": "D", "start": 320}}},
        {"name": "q", "access": "readwrite", "data_type": "uint16",
         "address": {"slmp": {"device_code": "D", "start": 321}}},
    ])
    assert app.cmd("WU32 p 0x2345") == ["W", "0"]
    assert u16(plc.batchread_wordunits(headdevice="D320", readsize=1)) == [0x2345]
    plc.batchwrite_wordunits(headdevice="D321", values=[0x0102])
    assert app.cmd("RU32 q") == ["R", "0", str(0x0102)]


@known_defect("T10-3", "A~F 로 시작하는 16진 디바이스 번호를 파싱하지 못해 포인트가 경고 없이 빠진다")
@pytest.mark.parametrize(
    "slmp,write,device,mask",
    [
        # pymcprotocol 은 "WA" 를 이름으로 오해하지 않도록 "W0A" 표기를 요구한다 (같은 W 10번).
        ({"start": "WA"}, "WU32 p 0x1234", "W0A", 0xFFFF),
        ({"device_code": "W", "start": "A"}, "WU32 p 0x1234", "W0A", 0xFFFF),
        ({"start": "XA"}, "WBOOL p 1", "X0", 0x0400),
    ],
    ids=["start=WA", "device_code=W,start=A", "start=XA"],
)
def test_adapter_hex_device_number_starting_with_letter(slmp_app, slmp, write, device, mask):
    """W/X 는 16진 번호 디바이스다 (사양 디바이스 표). "A" 는 10번이므로 WA = W 10번 워드, XA = X0~XF 워드의 bit 10.

    판정은 pymcprotocol 이 같은 디바이스를 읽은 값이다 (W0A / X0 워드).
    """
    data_type = "bool" if write.startswith("WBOOL") else "uint16"
    app, plc = slmp_app([{"name": "p", "access": "readwrite", "data_type": data_type,
                          "address": {"slmp": slmp}}])
    assert app.cmd(write) == ["W", "0"]
    got = u16(plc.batchread_wordunits(headdevice=device, readsize=1))[0]
    expect = 0x1234 if mask == 0xFFFF else mask
    assert got & mask == expect, f"{device} = {got:#06x}"


@known_defect("T10-4", "문자열 기본 배치가 앞 문자=상위 바이트다. MELSEC($MOV) 관례는 앞 문자=하위 바이트")
def test_adapter_string_default_is_melsec_order(slmp_app):
    app, plc = slmp_app([{"name": "s", "access": "readwrite", "data_type": "string", "length": 4,
                          "address": {"slmp": {"device_code": "D", "start": 300}}}])
    assert app.cmd("WSTR s ABCD") == ["W", "0"]
    words = u16(plc.batchread_wordunits(headdevice="D300", readsize=2))
    # PLC 워드 메모리를 바이트 순서(워드마다 하위 바이트 먼저)로 늘어놓으면 문자열이 그대로 읽혀야 한다.
    assert b"".join(struct.pack("<H", w) for w in words) == b"ABCD", [hex(w) for w in words]


@known_defect("T10-4", "32비트 기본 워드 순서가 ABCD(상위 워드 먼저)다. MELSEC(DMOV/DINT)은 하위 워드가 D(n)")
@pytest.mark.parametrize(
    "data_type,write,expect",
    [("int32", "WI32 v 0x12345678", [0x5678, 0x1234]), ("float32", "WF32 v 1.5", [0x0000, 0x3FC0])],
    ids=["int32", "float32"],
)
def test_adapter_32bit_default_is_low_word_first(slmp_app, data_type, write, expect):
    app, plc = slmp_app([{"name": "v", "access": "readwrite", "data_type": data_type,
                          "address": {"slmp": {"device_code": "D", "start": 310}}}])
    assert app.cmd(write) == ["W", "0"]
    assert u16(plc.batchread_wordunits(headdevice="D310", readsize=2)) == expect


# ===============================================================

# 2026-10-11 감사 (A20261011-3, -4, -5) — docs/reports/audits/20261011-slmp.md
# slmp_oracle_client 의 --start/--dev/--bit/--write 옵션을 쓴다 (기본값은 예전 동작 D1..DK 읽기).
# ======================================================================


# ---------------------------------------------------------------- 클라이언트: 큰 디바이스 번호
# 3E (Q 호환 서브커맨드 0000/0001) 의 선두 디바이스 번호는 3바이트(0~0xFFFFFF)다. MELSEC Q 기본 디바이스 점수만 해도
# D 12288, W 8192(W0~W1FFF) 이므로 D5000·W1000(16진)·ZR100000·M512 는 정상 주소다. 저장소 스택·어댑터의
# 로컬 맵 크기(map_words 4096, map_bits 8192)는 PLC 의 디바이스 범위와 무관한 구현 상수라서,
# 클라이언트가 PLC 에 정상 요청을 보내고 정상 응답을 받았다면 결과는 맵 크기와 상관없이 앱에 전달돼야 한다.
class SpecPlc:
    """Binary 3E 서버 (MELSEC 역할). 저장소 코드를 쓰지 않는다.

    0401/0000: 워드 n = (0x1000 + n) & 0xFFFF (디바이스 무관)
    0401/0001: 비트 n = n % 2 (사양 니블: 앞 점이 상위 니블)
    1401: (subcommand, head, device, points, data hex) 를 writes 에 기록하고 0000 으로 답한다.
    """

    def __init__(self):
        self.port = free_port()
        self.writes = []
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
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _serve(self, conn):
        with conn:
            while True:
                hdr = self._recv_exact(conn, 9)
                if hdr is None:
                    return
                (length,) = struct.unpack_from("<H", hdr, 7)
                body = self._recv_exact(conn, length)
                if body is None:
                    return
                # body: timer(2) command(2) subcommand(2) head(3) device(1) points(2) data
                command, sub = struct.unpack_from("<HH", body, 2)
                head = int.from_bytes(body[6:9], "little")
                device = body[9]
                (points,) = struct.unpack_from("<H", body, 10)
                end, data = 0, b""
                if command == 0x0401 and sub == 0x0000:
                    data = b"".join(struct.pack("<H", (0x1000 + head + i) & 0xFFFF) for i in range(points))
                elif command == 0x0401 and sub == 0x0001:
                    packed = bytearray((points + 1) // 2)
                    for i in range(points):
                        if (head + i) % 2:
                            packed[i // 2] |= 0x10 if i % 2 == 0 else 0x01
                    data = bytes(packed)
                elif command == 0x1401:
                    self.writes.append((sub, head, device, points, body[12:].hex()))
                else:
                    end = 0xC059
                rsp = bytes([0xD0, 0x00]) + hdr[2:7] + struct.pack("<HH", 2 + len(data), end) + data
                try:
                    conn.sendall(rsp)
                except OSError:
                    return

    def close(self):
        self._srv.close()


def run_client_one(port, *args):
    """slmp_oracle_client 로 한 점을 읽거나 쓰고 출력 한 줄을 나눠 돌려준다."""
    out = subprocess.run(
        [str(dut_path("slmp_oracle_client")), "--port", str(port), "--count", "1",
         "--interval-ms", "10", *args],
        capture_output=True, text=True, timeout=30,
    ).stdout
    lines = [l.split() for l in out.splitlines() if l.startswith(("READ ", "WRITE "))]
    assert len(lines) == 1, out
    return lines[0]


# 대조군 (지금도 통과): 스택 API 의 읽기는 맵 밖 주소에서도 PLC 값을 돌려준다.
@pytest.mark.parametrize(
    "args,expect",
    [
        (["--start", "5000"], ["READ", "5000", "0", "2388"]),                      # D5000 = 0x1000+5000
        (["--start", "100000", "--dev", "B0"], ["READ", "100000", "0", "96a0"]),   # ZR100000
        (["--start", "512", "--dev", "90"], ["READ", "512", "0", "1200"]),         # M512 워드 단위
        (["--start", "8193", "--dev", "90", "--bit"], ["READ", "8193", "0", "0001"]),  # M8193 비트 = 1
    ],
    ids=["D5000", "ZR100000", "M512-word", "M8193-bit"],
)
def test_client_stack_reads_high_device_numbers(args, expect):
    plc = SpecPlc()
    try:
        assert run_client_one(plc.port, *args) == expect
    finally:
        plc.close()


@known_defect("A20261011-3", "클라이언트 batch_write 가 로컬 맵(워드 4096·비트 8192, 비트 디바이스 워드 단위 512) 밖 주소면 -ERANGE 로 PLC 에 보내지도 않는다")
@pytest.mark.parametrize(
    "args,expect_write",
    [
        (["--start", "5001", "--write", "1234"], (0x0000, 5001, 0xA8, 1, "3412")),
        (["--start", "512", "--dev", "90", "--write", "1234"], (0x0000, 512, 0x90, 1, "3412")),
        (["--start", "8193", "--dev", "90", "--bit", "--write", "1"], (0x0001, 8193, 0x90, 1, "10")),
    ],
    ids=["D5001-word", "M512-word", "M8193-bit"],
)
def test_client_stack_writes_high_device_numbers(args, expect_write):
    plc = SpecPlc()
    try:
        line = run_client_one(plc.port, *args)
        time.sleep(0.1)
        writes = list(plc.writes)
    finally:
        plc.close()
    # 사양: 1401 요청 = 서브커맨드, 선두 번호 3바이트, 디바이스 코드, 점수, 데이터(워드 LE / 비트 니블)
    assert line == ["WRITE", args[1], "0"] and writes == [expect_write], (line, writes)


# ---------------------------------------------------------------- 어댑터 (클라이언트 모드)
@pytest.fixture
def slmp_client_app(tmp_path):
    """SpecPlc 에 붙는 클라이언트 모드 SLMP 어댑터 앱."""
    made = []

    def make(points):
        plc = SpecPlc()
        cfg = {
            "protocol": "slmp",
            "device": {"name": "oracle", "role": "client"},
            "cycle_ms": 5,
            "protocol_params": {"role": "client", "plc_ip": "127.0.0.1", "port": plc.port,
                                "timeout_ms": 300},
            "points": points,
        }
        path = tmp_path / "slmp_client.json"
        path.write_text(json.dumps(cfg))
        app = AppPipe(path)
        made.extend([plc, app])
        assert app.opened == ["OPEN", "0"], app.opened
        assert app.cmd("START") == ["START", "0"]
        return app, plc

    yield make
    for x in reversed(made):
        x.close()


def _u16_point(name, access, slmp):
    return {"name": name, "access": access, "data_type": "uint16", "address": {"slmp": slmp}}


# 대조군 (지금도 통과): 맵 안 주소는 클라이언트 어댑터가 읽고 쓴다.
def test_adapter_client_low_device_numbers(slmp_client_app):
    app, plc = slmp_client_app([
        _u16_point("in", "write", {"device_code": "D", "start": 4095}),
        _u16_point("out", "read", {"device_code": "D", "start": 4094}),
    ])
    assert app.cmd("POLL")[1] == "0"
    assert app.cmd("RU32 in") == ["R", "0", str(0x1000 + 4095)]
    assert app.cmd("WU32 out 0x1234") == ["W", "0"]
    assert plc.writes == [(0x0000, 4094, 0xA8, 1, "3412")]


@known_defect("A20261011-4", "클라이언트 어댑터가 PLC 응답을 로컬 맵을 거쳐 읽어, 맵 밖 주소(D5000·W1000·M512 워드)의 포인트는 fb_read 가 FB_ERR_IO")
@pytest.mark.parametrize(
    "slmp,expect",
    [
        ({"device_code": "D", "start": 5000}, 0x1000 + 5000),
        ({"device_code": "W", "start": "1000"}, 0x1000 + 0x1000),       # W 는 16진 번호
        ({"device_code": "M", "start": 512, "unit": "word"}, 0x1000 + 512),
    ],
    ids=["D5000", "W1000", "M512-word"],  # ZR 은 번호 기수(T10-7)가 미정이라 넣지 않는다
)
def test_adapter_client_reads_high_device_numbers(slmp_client_app, slmp, expect):
    app, _ = slmp_client_app([_u16_point("p", "write", slmp)])
    assert app.cmd("POLL")[1] == "0"
    assert app.cmd("RU32 p") == ["R", "0", str(expect)]


# 쓰기는 스택(A20261011-3)과 어댑터 둘 다 고쳐야 통과한다. 스택 PR 뒤에도 xfail 로 남는다.
@known_defect("A20261011-4", "클라이언트 어댑터가 로컬 맵 밖 주소(D5001)의 포인트 쓰기를 PLC 로 보내지 않고 FB_ERR_IO")
def test_adapter_client_writes_high_device_number(slmp_client_app):
    app, plc = slmp_client_app([_u16_point("p", "read", {"device_code": "D", "start": 5001})])
    wrote = app.cmd("WU32 p 0x1234")
    time.sleep(0.1)
    assert wrote == ["W", "0"] and plc.writes == [(0x0000, 5001, 0xA8, 1, "3412")], (wrote, plc.writes)


# ---------------------------------------------------------------- 서버: 비트 단위 점수 상한
# SLMP / MC 프로토콜 3E (Q 호환) 디바이스 일괄 읽기·쓰기(0401/1401) 처리 점수: 워드 단위 1~960, 비트 단위 1~7168.
# 저장소도 SLMP_QTY_BIT_MAX = 7168 로 두고 7169 를 C051 로 거부한다 (tests/test_slmp_stack.c). 7168 이하는 받아야 한다.
def raw_3e_frame(port, frame: bytes, timeout=2.0):
    """3E 요청 프레임을 보내고 (end_code, data) 를 돌려준다. 연결이 끊기면 None."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(frame)
        buf = b""
        try:
            while len(buf) < 9 or len(buf) < 9 + struct.unpack_from("<H", buf, 7)[0]:
                chunk = s.recv(65536)
                if not chunk:
                    return None
                buf += chunk
        except (ConnectionResetError, socket.timeout):
            return None
        (end,) = struct.unpack_from("<H", buf, 9)
        return end, buf[11:]


def bit_batch_frame(command: int, points: int, data: bytes = b"") -> bytes:
    """M0 부터 points 점 비트 단위(0001) 일괄 요청. 바이트 배치는 pymcprotocol 0.3.0 Type3E("Q") 와 같다."""
    body = struct.pack("<HHH", 0x0010, command, 0x0001) + (0).to_bytes(3, "little") + bytes([0x90]) \
        + struct.pack("<H", points) + data
    return bytes([0x50, 0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00]) + struct.pack("<H", len(body)) + body


def nibbles(points):
    out = bytearray((len(points) + 1) // 2)
    for i, v in enumerate(points):
        if v:
            out[i // 2] |= 0x10 if i % 2 == 0 else 0x01
    return bytes(out)


# 대조군 (지금도 통과)
@pytest.mark.parametrize("command,points", [(0x0401, 3840), (0x1401, 4054)], ids=["read-3840", "write-4054"])
def test_server_bit_batch_within_buffer(slmp_dut, command, points):
    data = nibbles([1] * points) if command == 0x1401 else b""
    got = raw_3e_frame(slmp_dut.port, bit_batch_frame(command, points, data))
    assert got is not None and got[0] == 0x0000, got


@known_defect("A20261011-5", "서버가 비트 단위 읽기 3841~7168 점에 C051, 쓰기 4055~7168 점에 응답 없이 연결을 끊는다 (사양 상한 7168)")
@pytest.mark.parametrize(
    "command,points",
    [(0x0401, 3841), (0x0401, 7168), (0x1401, 4055), (0x1401, 7168)],
    ids=["read-3841", "read-7168", "write-4055", "write-7168"],
)
def test_server_bit_batch_up_to_7168(slmp_dut, command, points):
    values = [i % 3 == 0 for i in range(points)]
    if command == 0x1401:
        got = raw_3e_frame(slmp_dut.port, bit_batch_frame(command, points, nibbles(values)))
        assert got == (0x0000, b""), f"{points}점 쓰기 응답: {got and hex(got[0])}"
        # 쓴 값을 pymcprotocol 로 되읽는다 (앞 3840 점, 응답이 한 번의 recv 에 들어오는 크기).
        c = pymcprotocol.Type3E(plctype="Q")
        c.soc_timeout = 2
        c.connect("127.0.0.1", slmp_dut.port)
        try:
            assert c.batchread_bitunits(headdevice="M0", readsize=min(points, 3840)) == \
                [int(v) for v in values[:3840]]
        finally:
            c.close()
    else:
        got = raw_3e_frame(slmp_dut.port, bit_batch_frame(command, points))
        assert got is not None and got[0] == 0x0000 and len(got[1]) == (points + 1) // 2, \
            f"{points}점 읽기 응답: {got and (hex(got[0]), len(got[1]))}"


# ---------------------------------------------------------------- 구동 모델 (docs/design.md 1장 5항)
# SLMP 는 요청-응답형이라 사이클이 없다. 서버(시뮬) 응답 지연은 cycle_ms 와 무관해야 한다.
# 판정: pymcprotocol 이 잰 왕복 시간 (cycle_ms=1000, 상한 100ms — Modbus 오라클과 같은 기준).
@known_defect("A20261008-3", "서버가 cycle_ms 마다만 요청을 확인한다 (cycle_ms=1000 이면 응답이 최대 ~1초 늦음). 요청-응답형은 도착 즉시 응답해야 한다")
def test_server_response_does_not_wait_for_cycle(slmp_app):
    app, plc = slmp_app([
        {"name": "p", "access": "readwrite", "data_type": "uint16",
         "address": {"slmp": {"device_code": "D", "start": 400}}},
    ], cycle_ms=1000)
    plc.soc_timeout = 3
    worst = 0.0
    for _ in range(5):
        time.sleep(0.137)  # 요청 시점을 사이클 경계와 어긋나게
        t0 = time.monotonic()
        plc.batchread_wordunits(headdevice="D400", readsize=1)
        worst = max(worst, time.monotonic() - t0)
    assert worst < 0.1, f"cycle_ms=1000 에서 최대 응답 {worst * 1000:.0f} ms"


# ---------------------------------------------------------------- 클라이언트 대기 vs 감시 타이머 (A20261012-1)
# 감시 타이머(요청 오프셋 9-10, 250 ms 단위)는 요청을 받은 모듈이 접근 대상에 처리를 넘기면서 시작한다.
# 그래서 모듈의 만료 이상 응답은 클라이언트 송신 뒤 항상 "타이머 + 왕복" 이후에 온다. 클라이언트가 타이머와
# 같은 시간만 기다리면 그 응답(엔드 코드)을 원리상 받지 못하고 연결을 버린다.
# 기대값 출처: pymcprotocol 0.3.0 type3e.py ("socket timeout is always set timer+1sec. To recieve Timeout
# answer"), gomcprotocol·node mcprotocol·HslCommunication 도 대기 > 타이머 (+0.5~7.5 s).
# 이 가짜 모듈은 요청의 타이머 필드를 읽어 첫 요청에만 "타이머 + late_s" 뒤 이상 응답(엔드 코드 + 에러 정보 9 B)을
# 보내고, 이후 요청은 정상으로 답한다. 저장소 코드를 쓰지 않는다.
class MonitorTimerPlc:
    def __init__(self, late_s, end=0xC0B5):
        self.late_s, self.end = late_s, end
        self.accepts, self.timers, self._first = 0, [], True
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
            self.accepts += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _serve(self, conn):
        with conn:
            while True:
                hdr = self._recv_exact(conn, 9)
                if hdr is None:
                    return
                body = self._recv_exact(conn, struct.unpack_from("<H", hdr, 7)[0])
                if body is None:
                    return
                (timer,) = struct.unpack_from("<H", body, 0)
                (points,) = struct.unpack_from("<H", body, 10)
                self.timers.append(timer)
                if self._first:
                    self._first = False
                    time.sleep(timer * 0.25 + self.late_s)  # 모듈의 감시 타이머가 만료된 뒤
                    end, data = self.end, bytes(9)
                else:
                    end, data = 0, b"\x34\x12" * points
                rsp = b"\xD0\x00" + hdr[2:7] + struct.pack("<HH", 2 + len(data), end) + data
                try:
                    conn.sendall(rsp)
                except OSError:
                    return

    def close(self):
        self._srv.close()


# 대조군 (지금도 통과): 타이머 안에 온 이상 응답은 엔드 코드로 받고 (-EIO) 연결을 유지한다.
def test_client_receives_abnormal_response_before_monitoring_timer():
    plc = MonitorTimerPlc(late_s=-0.3)
    try:
        reads = run_client(plc.port, 2, interval_ms=50)
    finally:
        plc.close()
    assert [rc for _, rc, _ in reads] == [-5, 0] and plc.accepts == 1, (reads, plc.accepts)


@known_defect("A20261012-1", "클라이언트 응답 대기가 감시 타이머와 같아 모듈의 만료 이상 응답을 받지 못하고 "
              "-ETIMEDOUT 으로 연결을 버린다 (다음 요청은 백오프 -EAGAIN)")
def test_client_waits_past_monitoring_timer_for_abnormal_response():
    plc = MonitorTimerPlc(late_s=0.15)
    try:
        reads = run_client(plc.port, 2, interval_ms=50)
    finally:
        plc.close()
    assert [rc for _, rc, _ in reads] == [-5, 0] and plc.accepts == 1, (reads, plc.accepts, plc.timers)
