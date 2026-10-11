"""EtherNet/IP 랩 상호운용 (veth + network namespace, 독립 스캐너 EIPScanner).

oracle job 의 기본 실행에서는 건너뛴다. 실행 조건:
- root (ip netns / veth 생성) 와 `ip` 명령
- EIP_LAB_SCANNER = tests/oracle/lab/build_eipscanner.sh 가 만든 eipscanner_originator 경로

DUT(eip_oracle_adapter --bind-ip --report-output)는 namespace 안의 veth 주소에서, 스캐너는 바깥 veth 에서
돈다. loopback 이 아니라 실제 이더넷 장치를 거치고, 양쪽이 각자 UDP 2222 를 쓴다 (실 네트워크와 같은 배치).
판정은 EIPScanner (실장비와 쓰이는 오픈소스 스캐너) 가 연결·I/O 를 성립시키는지와, DUT 가 받은 출력 이미지다.
"""
import os
import re
import shutil
import subprocess
import time
import uuid

import pytest

from conftest import dut_path, known_defect

SCANNER = os.environ.get("EIP_LAB_SCANNER", "")
RPI_US = 10000           # DUT 최소 RPI(8 ms) 이상
IN_DATA = "0102030405060708"   # eip_oracle_adapter input assembly 150 (8B)
OUT_DATA = "a1a2a3a4"          # eipscanner_originator 의 O->T 데이터


def _lab_ready():
    if not SCANNER or not os.path.exists(SCANNER):
        return "EIP_LAB_SCANNER 가 없다 (tests/oracle/lab/build_eipscanner.sh)"
    if os.geteuid() != 0 or not shutil.which("ip"):
        return "root 와 ip 명령이 필요하다 (netns/veth)"
    return None


pytestmark = pytest.mark.skipif(_lab_ready() is not None, reason=str(_lab_ready()))


def _ip(*args, ns=None):
    cmd = (["ip", "netns", "exec", ns] if ns else []) + ["ip", *args]
    subprocess.run(cmd, check=True, capture_output=True)


@pytest.fixture
def lab():
    """namespace 1개 + veth 1쌍: 바깥 10.77.N.1 (스캐너), 안쪽 10.77.N.2 (DUT)."""
    tag = uuid.uuid4().hex[:6]
    ns, outer, inner = f"eiplab{tag}", f"ve{tag}a", f"ve{tag}b"
    n = int(tag[:2], 16)
    subprocess.run(["ip", "netns", "add", ns], check=True)
    try:
        _ip("link", "add", outer, "type", "veth", "peer", "name", inner)
        _ip("link", "set", inner, "netns", ns)
        _ip("addr", "add", f"10.77.{n}.1/24", "dev", outer)
        _ip("link", "set", outer, "up")
        _ip("addr", "add", f"10.77.{n}.2/24", "dev", inner, ns=ns)
        _ip("link", "set", inner, "up", ns=ns)
        _ip("link", "set", "lo", "up", ns=ns)
        yield ns, f"10.77.{n}.2"
    finally:
        subprocess.run(["ip", "link", "del", outer], capture_output=True)
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)


def _run(lab, run_idle, seconds=3):
    ns, dut_ip = lab
    dut = subprocess.Popen(
        ["ip", "netns", "exec", ns, str(dut_path("eip_oracle_adapter")), "--bind-ip", dut_ip,
         "--tcp-port", "44818", "--udp-port", "2222", "--seconds", str(seconds + 4),
         "--report-output"],
        stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.5)
        scan = subprocess.run([SCANNER, dut_ip, str(seconds), str(RPI_US), "4", "8", str(run_idle)],
                              capture_output=True, text=True, timeout=seconds + 15)
    finally:
        dut.terminate()
        _, dut_err = dut.communicate(timeout=10)
    m = re.search(r"RESULT rx=(\d+) last=(\w*) open_at_end=(\d)", scan.stdout)
    assert m, f"스캐너 출력 해석 실패:\n{scan.stdout}\n{scan.stderr}"
    outs = re.findall(r"OUT up=(\d) (\w+)", dut_err)
    return {"fo_ok": "FO ok" in scan.stdout, "rx": int(m.group(1)), "last": m.group(2),
            "open_at_end": m.group(3) == "1", "dut_out": outs, "log": scan.stderr[-800:]}


# Logix 기본 형식: O->T = 데이터 + 2(seq) + 4(32-bit Run/Idle 헤더). EIPScanner 의 o2tRealTimeFormat.
# 장치는 Forward Open 을 받아들이고, 헤더를 벗긴 데이터(A1 A2 A3 A4)를 출력 이미지에 넣어야 한다.
# T11-1 (#109): Logix 형식 Forward Open 수락, Run/Idle 헤더를 벗겨 출력 이미지에 넣는다.
def test_lab_eipscanner_logix_run_idle_forward_open(lab):
    r = _run(lab, run_idle=1)
    assert r["fo_ok"], f"Forward Open 거부:\n{r['log']}"
    assert ("1", OUT_DATA) in r["dut_out"], f"DUT 출력 이미지 {r['dut_out']}"


# T->O 는 originator 의 UDP 2222 로 보낸다 (sockaddr 정보 항목이 없을 때). 독립 구현 OpENer
# cipioconnection.c 도 기본 목적지 포트가 kOpenerEipIoUdpPort(2222). EIPScanner 는 O->T 를 임의 포트에서
# 보내고 2222 에서 받으므로, 출발지 포트로 되돌려 보내는 장치와는 I/O 가 성립하지 않는다.
@known_defect("T11-6", "T->O 를 2222 가 아니라 O->T 의 출발지 포트로 보낸다 (EIPScanner 가 받지 못해 연결 타임아웃)")
def test_lab_eipscanner_class1_io_exchange(lab):
    r = _run(lab, run_idle=0)
    assert r["fo_ok"], f"Forward Open 거부:\n{r['log']}"
    assert ("1", OUT_DATA) in r["dut_out"], f"DUT 출력 이미지 {r['dut_out']}"
    assert r["rx"] >= 100 and r["last"] == IN_DATA and r["open_at_end"], \
        f"T->O rx={r['rx']} last={r['last']} open_at_end={r['open_at_end']}"
