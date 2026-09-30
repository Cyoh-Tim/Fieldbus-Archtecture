"""SLMP Binary 3E — 오라클: pymcprotocol (실제 TCP 로 slmp_oracle_server 에 접속).

pymcprotocol 은 실제 MELSEC PLC 와 쓰이는 클라이언트다. 비트 단위 데이터를 사양대로
1점=니블(앞 점이 상위 니블)로 인코딩한다.
slmp_oracle_server 시드: D0..D9 = 0x1000 + n.
"""
import socket
import struct
import subprocess
import threading
import time

import pymcprotocol
import pytest

from conftest import dut_path, free_port, known_defect


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
