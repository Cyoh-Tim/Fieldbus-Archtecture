"""tests/oracle 공통 픽스처.

스택은 DUT 로만 띄우고, 판정은 저장소 코드를 공유하지 않는 독립 구현체가 한다.
DUT 실행 파일 위치는 ORACLE_BUILD_DIR (기본: <repo>/build).
"""
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BUILD = Path(os.environ.get("ORACLE_BUILD_DIR", REPO / "build"))


def dut_path(name: str) -> Path:
    p = BUILD / name
    if not p.exists():
        pytest.fail(f"DUT 실행 파일 없음: {p} (cmake --build 로 {name} 타깃을 빌드)")
    return p


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_tcp(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"DUT 가 127.0.0.1:{port} 에서 listen 하지 않음")


class Dut:
    """TCP 서버형 DUT 프로세스."""

    def __init__(self, argv, port):
        self.port = port
        self.proc = subprocess.Popen(
            [str(a) for a in argv],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        try:
            wait_tcp(port)
        except RuntimeError:
            self.stop()
            raise

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture
def mb_dut():
    port = free_port()
    d = Dut([dut_path("mb_seeded_server"), "--port", port], port)
    yield d
    d.stop()


@pytest.fixture
def slmp_dut():
    port = free_port()
    d = Dut([dut_path("slmp_oracle_server"), "--port", port], port)
    yield d
    d.stop()


@pytest.fixture
def eip_dut():
    tcp = free_port()
    udp = free_port()
    d = Dut([dut_path("eip_oracle_adapter"), "--tcp-port", tcp, "--udp-port", udp], tcp)
    d.udp_port = udp
    yield d
    d.stop()


class PnPipe:
    """pn_oracle_pipe 줄 프로토콜 클라이언트 (mock Ethernet)."""

    def __init__(self):
        self.proc = subprocess.Popen(
            [str(dut_path("pn_oracle_pipe"))],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.startup = self._read_until_end()

    def _read_until_end(self):
        out = []
        for line in self.proc.stdout:
            line = line.rstrip("\n")
            if line == "END":
                return out
            tag, _, hx = line.partition(" ")
            out.append((tag, bytes.fromhex(hx) if tag != "ERR" and hx else hx))
        raise RuntimeError("pn_oracle_pipe 가 종료됨")

    def cmd(self, line: str):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        return self._read_until_end()

    def eth(self, frame: bytes):
        return self.cmd("ETH " + frame.hex())

    def rpc(self, payload: bytes):
        return self.cmd("RPC " + payload.hex())

    def close(self):
        try:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()


@pytest.fixture
def pn_dut():
    p = PnPipe()
    yield p
    p.close()


def known_defect(t_id: str, why: str):
    """알려진 결함. 고쳐지면 XPASS 가 되어 strict 로 실패하므로, 수정 PR 이 이 표시를 지워야 한다."""
    return pytest.mark.xfail(strict=True, reason=f"{t_id}: {why}")
