"""Modbus TCP — 오라클: pymodbus (실제 TCP 로 mb_seeded_server 에 접속).

mb_seeded_server 시드: holding[i]=0xA000+i, input[i]=0xB000+i, coil[i]=i&1,
discrete[i]=(i>>1)&1 (i<256), holding 300..301 = float 1.5 (ABCD), holding 400.. = "ABCD".

클라이언트 경로는 mb_oracle_client(스택), 어댑터 설정·포인트 매핑은 mb_slmp_oracle_app(fb_api 앱)이
DUT 이고, 판정은 사양 기반 가짜 서버나 pymodbus 가 한다.
"""
import json
import os
import select
import socket
import struct
import subprocess
import threading
import time

import pytest
from pymodbus.client import ModbusTcpClient
from pymodbus.pdu import ExceptionResponse

from conftest import REPO, dut_path, free_port, known_defect, wait_tcp

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


# ================================================================ 서버 소켓 동작
def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise EOFError("연결이 닫힘")
        buf += chunk
    return buf


@known_defect("T9-7", "서버 소켓에 TCP_NODELAY 가 없어 파이프라인 두 번째 응답이 Nagle+지연 ACK 로 ~40ms 늦다")
def test_pipelined_responses_not_delayed_by_nagle(mb_dut):
    """파이프라인한 두 요청의 두 번째 응답이 상대의 지연 ACK(리눅스 최소 40ms)를 기다리지 않고 온다.

    구현 가이드는 파이프라이닝을 허용하고, 인수인계 T9-7 은 accept 소켓에 TCP_NODELAY 를 요구한다.
    quick-ACK 구간을 지나도록 먼저 30번 주고받은 뒤, 두 ADU 를 한 번에 보내 두 응답까지 걸린 시간을 잰다.
    """
    def req(tid):
        return struct.pack(">HHHBBHH", tid, 0, 6, UNIT, 0x03, 0, 1)

    with socket.create_connection(("127.0.0.1", mb_dut.port), timeout=2) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for i in range(30):
            s.sendall(req(i + 1))
            _recv_exact(s, 11)
        delays = []
        for k in range(5):
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)
            t0 = time.monotonic()
            s.sendall(req(0x100 + 2 * k) + req(0x101 + 2 * k))
            first = _recv_exact(s, 11)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 0)
            second = _recv_exact(s, 11)
            delays.append((time.monotonic() - t0) * 1000)
            assert first[:2] == struct.pack(">H", 0x100 + 2 * k)
            assert second[:2] == struct.pack(">H", 0x101 + 2 * k)
    delays.sort()
    # 수정 전 ~44ms (지연 ACK 대기), TCP_NODELAY 면 ~1ms. 중앙값으로 판정한다.
    assert delays[2] < 20, f"두 번째 응답까지 ms (정렬): {[round(d, 1) for d in delays]}"


@known_defect("T9-8", "non-blocking send 가 EAGAIN 이면 마스터 연결을 끊는다. 남은 응답은 다음 poll 에서 보내야 한다")
def test_slow_reader_keeps_connection(mb_dut):
    """마스터가 잠시 읽지 않아 서버 송신 버퍼가 차도 연결을 유지하고 모든 응답을 순서대로 보낸다.

    FC03 125워드 요청 60000개(응답 약 15MB)를 파이프라인하고 0.5 s 뒤에 읽기 시작한다.
    """
    n = 60000
    blob = b"".join(
        struct.pack(">HHHBBHH", i & 0xFFFF, 0, 6, UNIT, 0x03, 0, 125) for i in range(n)
    )
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    s.connect(("127.0.0.1", mb_dut.port))
    errors = []

    def sender():
        try:
            s.sendall(blob)
        except OSError as e:
            errors.append(e)

    threading.Thread(target=sender, daemon=True).start()
    time.sleep(0.5)
    s.settimeout(5.0)
    got, buf, bad_tid = 0, b"", None
    try:
        while got < n:
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= 6:
                (length,) = struct.unpack_from(">H", buf, 4)
                if len(buf) < 6 + length:
                    break
                (tid,) = struct.unpack_from(">H", buf, 0)
                if bad_tid is None and tid != (got & 0xFFFF):
                    bad_tid = (got, tid)
                buf = buf[6 + length:]
                got += 1
    except OSError as e:
        errors.append(e)
    finally:
        s.close()
    assert got == n and bad_tid is None, f"응답 {got}/{n}, TID 어긋남 {bad_tid}, 오류 {errors}"


# ================================================================ 클라이언트 경로 (스택)
# pymodbus 는 클라이언트라서 스택의 클라이언트 경로는 사양 기반 가짜 서버로 본다.
# 가짜 서버는 MBAP 의 TID/Unit 을 그대로 되돌리고 FC03/04 에 reg[a] = 0xC000 + a 를 돌려준다.
class FakeMbServer:
    """Modbus TCP 서버 (사양 기반, 저장소 코드를 쓰지 않는다).

    mode: "normal" (응답) 또는 "silent" (연결은 받고 요청도 읽지만 응답하지 않음).
    first_delay_s: 전체에서 첫 요청 하나만 이만큼 늦게 응답.
    """

    def __init__(self, mode="normal", first_delay_s=0.0):
        self.mode = mode
        self.first_delay_s = first_delay_s
        self.port = free_port()
        self.accepts = 0
        self.requests = []  # (연결 번호, TID, FC)
        self.times = []  # 요청 수신 시각 (monotonic s)
        self._first = True
        self._lock = threading.Lock()
        self._conns = []
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self.port))
        self._srv.listen(8)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                return
            with self._lock:
                idx = self.accepts
                self.accepts += 1
                self._conns.append(conn)
            threading.Thread(target=self._serve, args=(conn, idx), daemon=True).start()

    @staticmethod
    def _pdu_response(pdu):
        fc = pdu[0]
        if fc in (0x03, 0x04):  # byte count + registers
            addr, qty = struct.unpack_from(">HH", pdu, 1)
            data = b"".join(struct.pack(">H", (0xC000 + addr + i) & 0xFFFF) for i in range(qty))
            return bytes([fc, len(data)]) + data
        if fc in (0x01, 0x02):  # byte count + packed bits (all OFF)
            (qty,) = struct.unpack_from(">H", pdu, 3)
            return bytes([fc, (qty + 7) // 8]) + bytes((qty + 7) // 8)
        if fc in (0x05, 0x06, 0x0F, 0x10):  # echo address + value/quantity
            return pdu[:5]
        return bytes([fc | 0x80, 0x01])

    def _serve(self, conn, idx):
        with conn:
            while True:
                try:
                    hdr = _recv_exact(conn, 7)
                    tid, _, length, unit = struct.unpack(">HHHB", hdr)
                    pdu = _recv_exact(conn, length - 1)
                except (EOFError, OSError):
                    return
                with self._lock:
                    self.requests.append((idx, tid, pdu[0]))
                    self.times.append(time.monotonic())
                    delay, self._first = (self.first_delay_s if self._first else 0.0), False
                if self.mode == "silent":
                    continue
                rsp = self._pdu_response(pdu)
                if delay:
                    time.sleep(delay)
                try:
                    conn.sendall(struct.pack(">HHHB", tid, 0, len(rsp) + 1, unit) + rsp)
                except OSError:
                    return

    def close(self):
        self._srv.close()
        with self._lock:
            for c in self._conns:
                try:
                    c.close()
                except OSError:
                    pass


class LinePipe:
    """줄 프로토콜 DUT. 응답 한 줄을 timeout 안에 못 받으면 None 을 돌려준다."""

    def __init__(self, argv):
        self.proc = subprocess.Popen(
            [str(a) for a in argv],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        self._buf = b""

    def readline(self, timeout=10.0):
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buf:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            ready, _, _ = select.select([self.proc.stdout], [], [], left)
            if not ready:
                return None
            chunk = os.read(self.proc.stdout.fileno(), 4096)
            if not chunk:
                return None
            self._buf += chunk
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode().split()

    def cmd(self, line, timeout=10.0):
        self.proc.stdin.write((line + "\n").encode())
        self.proc.stdin.flush()
        return self.readline(timeout)

    def close(self):
        try:
            self.proc.stdin.write(b"QUIT\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=2)
        except Exception:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture
def mb_client_dut():
    p = LinePipe([dut_path("mb_oracle_client")])
    yield p
    p.close()


def test_client_reads_correct_values(mb_client_dut):
    srv = FakeMbServer()
    try:
        assert mb_client_dut.cmd(f"NEW {srv.port} 500") == ["NEW", "0"]
        assert mb_client_dut.cmd("START 0")[2] == "0"
        rsp = mb_client_dut.cmd("READ 0 h 5 3")
    finally:
        srv.close()
    assert rsp[2] == "0", rsp
    assert [int(v, 16) for v in rsp[4:]] == [0xC005, 0xC006, 0xC007]


def test_client_recovers_after_late_response(mb_client_dut):
    """첫 응답을 타임아웃(300ms)보다 늦게(500ms) 보낸 뒤에도 클라이언트는 다시 올바른 값을 읽어야 한다.

    어댑터처럼 매 사이클 poll → read 순서로 구동한다. 실패(rc<0)는 허용하지만 마지막 3번은 성공해야
    하고, 성공한 읽기는 반드시 자기 주소의 값이어야 한다 (사양: 응답은 TID 로 요청과 짝짓는다).

    시간 배치 (결정적으로 만들기 위함): 요청1 t=0 → 클라이언트 타임아웃 t=0.3 → 늦은 응답1 t=0.5 (혼자 도착)
    → 사이클 간격 600ms 뒤 요청2 t≈0.9. 늦은 응답이 다음 응답과 한 TCP 읽기에 붙어 오면 결함이 있는
    클라이언트도 우연히 정렬이 맞아 통과할 수 있어서(2026-10-01 main 에서 XPASS 1회), 두 응답이 겹치지 않게 했다.
    """
    srv = FakeMbServer(first_delay_s=0.5)
    reads = []
    try:
        mb_client_dut.cmd(f"NEW {srv.port} 300")
        mb_client_dut.cmd("START 0")
        for n in range(1, 11):
            mb_client_dut.cmd("POLL 0")
            rsp = mb_client_dut.cmd(f"READ 0 h {n} 1")
            reads.append((n, int(rsp[2]), int(rsp[4], 16) if len(rsp) > 4 else None))
            mb_client_dut.cmd("SLEEP 600")
    finally:
        srv.close()
    wrong = [(n, v) for n, rc, v in reads if rc == 0 and v != 0xC000 + n]
    assert not wrong, f"다른 주소의 값 (addr, value): {wrong}"
    assert all(rc == 0 for _, rc, _ in reads[-3:]), f"(addr, rc, value): {reads}"


def _black_hole_port():
    """SYN 에 답하지 않는 포트. backlog 0 listen 소켓의 accept 큐를 채워 두면 리눅스는 이후 SYN 을 버린다."""
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(0)
    port = lsock.getsockname()[1]
    keep = [lsock]
    for _ in range(3):
        c = socket.socket()
        c.setblocking(False)
        try:
            c.connect(("127.0.0.1", port))
        except BlockingIOError:
            pass
        keep.append(c)
    time.sleep(0.2)
    return port, keep


@known_defect("T9-5", "클라이언트 connect() 가 블로킹이고 타임아웃이 없어 SYN 무응답 상대에 커널 기본값(~2분)만큼 멈춘다")
def test_client_connect_to_silent_host_is_bounded(mb_client_dut):
    """SYN 에 답하지 않는 상대로 시작·재연결해도 호출이 3 s 안에 돌아와야 한다 (사이클이 막히지 않음)."""
    port, keep = _black_hole_port()
    try:
        mb_client_dut.cmd(f"NEW {port} 300")
        start = mb_client_dut.cmd("START 0", timeout=10)
        assert start is not None, "mb_stack_start 가 10 s 안에 돌아오지 않음 (블로킹 connect)"
        polls = [mb_client_dut.cmd("POLL 0", timeout=10) for _ in range(2)]
        assert None not in polls, f"mb_stack_poll(재연결)이 10 s 안에 돌아오지 않음: {polls}"
    finally:
        for s in keep:
            s.close()
    assert float(start[3]) <= 3000, start
    assert all(float(p[2]) <= 3000 for p in polls), polls


@known_defect("T9-9", "TID 카운터가 함수별 static 3개(인스턴스 간 공유)라 함수마다 TID 가 겹치고 새 인스턴스의 첫 TID 가 달라진다")
def test_client_tid_counter_per_instance(mb_client_dut):
    """TID 는 스택 인스턴스마다 하나의 카운터에서 나온다 (인수인계 T9-9).

    - 한 인스턴스(한 연결) 안의 연속 트랜잭션(읽기 2·레지스터 쓰기·코일 쓰기)은 TID 가 모두 다르다.
    - 다른 인스턴스의 트래픽은 새 인스턴스의 첫 TID 에 영향을 주지 않는다.
    """
    srv = FakeMbServer()
    try:
        mb_client_dut.cmd(f"NEW {srv.port} 500")
        mb_client_dut.cmd(f"NEW {srv.port} 500")
        assert mb_client_dut.cmd("START 0")[2] == "0"
        time.sleep(0.1)
        assert mb_client_dut.cmd("START 1")[2] == "0"
        time.sleep(0.1)
        for line in ("READ 0 h 1 1", "READ 0 h 2 1", "WREGS 0 5 1234", "WBITS 0 6 1",
                     "READ 1 h 3 1"):
            assert mb_client_dut.cmd(line)[2] == "0", line
    finally:
        srv.close()
    tids = {c: [t for i, t, _ in srv.requests if i == c] for c in (0, 1)}
    assert len(tids[0]) == 4 and len(tids[1]) == 1, tids
    assert len(set(tids[0])) == 4, f"연결 0 의 TID: {tids[0]}"
    assert tids[1][0] == tids[0][0], f"첫 TID: 연결0={tids[0][0]} 연결1={tids[1][0]}"


# ================================================================ 어댑터 (fb_api 앱)
# 설정 JSON 은 테스트가 만든다. 서버 모드에서는 앱이 쓴 값을 pymodbus 로 읽어 실제 레지스터 주소와
# 배치를 확인하고, 클라이언트 모드에서는 가짜 서버를 상대로 사이클 시간을 잰다.
class MbApp(LinePipe):
    def __init__(self, tmp_path, points, role="server", port=None, **params):
        self.port = port or free_port()
        cfg = {
            "protocol": "modbus_tcp",
            "device": {"name": "oracle", "role": role},
            "cycle_ms": 5,
            "protocol_params": {"role": role, "ip": "127.0.0.1", "port": self.port,
                                "unit_id": UNIT, **params},
            "points": points,
        }
        path = tmp_path / "modbus.json"
        path.write_text(json.dumps(cfg))
        super().__init__([dut_path("mb_slmp_oracle_app"), path])
        try:
            opened = self.readline(10)
            if opened != ["OPEN", "0"]:
                raise RuntimeError(f"fb_open 실패: {opened}")
            if role == "server":
                started = self.cmd("START")
                if started != ["START", "0"]:
                    raise RuntimeError(f"fb_start 실패: {started}")
                wait_tcp(self.port)
        except BaseException:
            self.close()
            raise


def holding_point(name, start, data_type="uint16", **extra):
    mb = {"register_type": "holding", "start": start, "zero_based": True}
    mb.update(extra.pop("modbus", {}))
    return {"name": name, "access": "readwrite", "data_type": data_type,
            "address": {"modbus": mb}, **extra}


@pytest.fixture
def mb_app_factory(tmp_path):
    apps = []

    def make(points, **kw):
        app = MbApp(tmp_path, points, **kw)
        apps.append(app)
        return app

    yield make
    for app in apps:
        app.close()


def pymodbus_read(port, addr, count):
    c = ModbusTcpClient("127.0.0.1", port=port, timeout=2, retries=0)
    assert c.connect()
    try:
        rr = c.read_holding_registers(addr, count=count, device_id=UNIT)
        assert not rr.isError(), rr
        return rr.registers
    finally:
        c.close()


def test_adapter_plain_point_roundtrip(mb_app_factory):
    """DUT 확인용: 숫자 주소 uint16 포인트는 앱 쓰기 → pymodbus 읽기, pymodbus 쓰기 → 앱 읽기가 맞는다."""
    app = mb_app_factory([holding_point("p", 7), holding_point("q", 8)])
    assert app.cmd("WU32 p 0x2345") == ["W", "0"]
    assert pymodbus_read(app.port, 7, 1) == [0x2345]
    c = ModbusTcpClient("127.0.0.1", port=app.port, timeout=2, retries=0)
    assert c.connect()
    try:
        assert not c.write_register(8, 0x0102, device_id=UNIT).isError()
    finally:
        c.close()
    assert app.cmd("RU32 q") == ["R", "0", str(0x0102)]


@known_defect("T9-3", "주소 문자열을 strtol(…, 0) 으로 읽어 앞자리 0 이 8진수가 된다 (\"00010\"→8, \"00009\"→0)")
@pytest.mark.parametrize("text,pdu", [("00010", 10), ("00009", 9)])
def test_adapter_address_string_is_decimal(mb_app_factory, text, pdu):
    """zero_based 포인트의 주소 문자열은 10진 PDU 주소다. 앱이 쓴 값이 그 레지스터에 있어야 한다."""
    app = mb_app_factory([holding_point("p", text)])
    assert app.cmd("WU32 p 0x1234") == ["W", "0"]
    regs = pymodbus_read(app.port, 0, 16)
    assert regs[pdu] == 0x1234, f"holding 0..15 = {[hex(r) for r in regs]}"


def _nibble_point():
    # uint16 포인트의 bit 4..7 (bit_count 4 ≤ 8). 예제 config 의 status_nibble 과 같은 형태.
    return holding_point("nib", 20, modbus={"bit": 4, "bit_count": 4})


@known_defect("T9-2", "bit_count≤8 비트필드 + uint16 쓰기가 값의 상위 바이트만 쓴다 (0x000A → 0)")
def test_adapter_bitfield_uint16_write(mb_app_factory):
    app = mb_app_factory([_nibble_point()])
    assert app.cmd("WU32 nib 10") == ["W", "0"]
    assert pymodbus_read(app.port, 20, 1) == [0x00A0]


@known_defect("T9-2", "bit_count≤8 비트필드 + uint16 읽기의 두 번째 바이트가 초기화되지 않은 메모리다")
def test_adapter_bitfield_uint16_read(mb_app_factory):
    app = mb_app_factory([_nibble_point()])
    c = ModbusTcpClient("127.0.0.1", port=app.port, timeout=2, retries=0)
    assert c.connect()
    try:
        assert not c.write_register(20, 0x5A3C, device_id=UNIT).isError()
    finally:
        c.close()
    # 0x5A3C 의 bit 4..7 = 0x3
    assert app.cmd("RU32 nib") == ["R", "0", "3"]


def _schema_chars_keys():
    schema = json.loads((REPO / "config" / "config.schema.json").read_text())
    props = schema["properties"]["points"]["items"]["properties"]
    return [k for k in props if k.startswith(("chars_per_", "char_per_"))]


@known_defect("T9-10", "스키마의 chars_per_word 를 Modbus 어댑터가 읽지 않는다 (chars_per_register 계열만)")
def test_adapter_honours_schema_chars_keys(mb_app_factory):
    """config.schema.json 이 문서화한 '레지스터당 문자 수' 키는 모두 Modbus 어댑터에서 효과가 있어야 한다.

    키 값 1 → 레지스터마다 한 글자. "ABCD" 는 4개 레지스터에 한 글자씩 순서대로 들어가야 한다
    (글자가 상위/하위 어느 바이트에 있는지는 판정하지 않는다).
    """
    keys = _schema_chars_keys()
    assert keys, "스키마에 문자 수 키가 없음"
    points = [
        {"name": f"s{i}", "access": "readwrite", "data_type": "string", "length": 4, key: 1,
         "address": {"modbus": {"register_type": "holding", "start": 100 + 10 * i,
                                "zero_based": True}}}
        for i, key in enumerate(keys)
    ]
    app = mb_app_factory(points)
    bad = {}
    for i, key in enumerate(keys):
        assert app.cmd(f"WSTR s{i} ABCD") == ["W", "0"], key
        regs = pymodbus_read(app.port, 100 + 10 * i, 4)
        chars = [bytes([b for b in r.to_bytes(2, "big") if b]) for r in regs]
        if chars != [b"A", b"B", b"C", b"D"]:
            bad[key] = [hex(r) for r in regs]
    assert not bad, f"한 글자/레지스터가 아닌 키: {bad}"


def test_adapter_client_cycle_fails_fast_and_backs_off(mb_app_factory):
    """응답 없는 서버 상대로 (인수인계 T3 1단계):

    (a) 한 사이클(fb_poll) 소요 시간이 timeout_ms 1회분 수준이다 (완료 조건). timeout 300ms·포인트 5개에서
        수정 전 ~1500ms. 판정 여유를 두어 2회분(600ms)까지 허용한다.
    (b) 실패 뒤에는 백오프(예: 100ms → 최대 2s) 동안 요청하지 않는다. 10ms 주기로 4 s 돌리는 동안
        서버가 받은 요청 사이 간격 중 가장 긴 것이 800ms(= 타임아웃 + 500ms) 이상이어야 한다.
        백오프가 없으면 간격은 타임아웃 한 번(~300ms)을 넘지 않는다.
    """
    srv = FakeMbServer(mode="silent")
    try:
        points = [
            {"name": f"p{i}", "access": "write", "data_type": "uint16",
             "address": {"modbus": {"register_type": "holding", "start": i, "zero_based": True}}}
            for i in range(5)
        ]
        app = mb_app_factory(points, role="client", port=srv.port, timeout_ms=300)
        cycles = [app.cmd("POLL", timeout=15) for _ in range(2)]
        loop = app.cmd("LOOP 4000 10", timeout=30)
    finally:
        srv.close()
    assert None not in cycles and loop is not None, (cycles, loop)
    ms = [float(c[2]) for c in cycles] + [float(loop[2])]
    gaps = [round((b - a) * 1000) for a, b in zip(srv.times, srv.times[1:])]
    assert max(ms) <= 600, f"(a) 사이클 ms (POLL 2회, LOOP 최대): {ms}"
    assert gaps and max(gaps) >= 800, f"(b) 요청 간격 ms: {gaps}"
