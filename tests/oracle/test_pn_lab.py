"""PROFINET 랩 상호운용 (veth + network namespace, 실제 전송 경로).

test_pn_oracle.py 는 mock Ethernet 위에서 돈다. 이 파일은 같은 판정을 **스택의 실제 전송 경로**에서 한다:
DUT(pn_oracle_lab)는 namespace 안 veth 에서 AF_PACKET(DCP·RTC1)과 UDP 34964(DCE/RPC)로 돌고, 컨트롤러 역할은
바깥 veth 에서 scapy 가 한다 (실 컨트롤러처럼 DCP Identify 로 장치 MAC 을 배우고, Connect·PrmEnd 는 UDP 로,
O->T RTC1 은 협상 주기로 보낸다). mock 에서는 보이지 않는 것 — 장치 MAC, ApplicationReady 의 UDP 목적지,
선로 위 프레임 길이·태그·송신 간격 — 을 본다.

oracle job 의 기본 실행에서는 건너뛴다 (root 와 `ip` 가 필요). 실행:
  sudo ORACLE_BUILD_DIR=<build> python -m pytest tests/oracle/test_pn_lab.py
요청 인코딩과 판정 헬퍼는 test_pn_oracle.py 의 것을 쓴다 (scapy 기반, 저장소 스택 코드 미사용).
"""
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
import uuid

import pytest
from scapy.all import AsyncSniffer, Dot1Q, Ether, conf, raw, sendp
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import ProfinetDCP
from scapy.contrib.pnio_rpc import IODControlReq
from scapy.layers.dcerpc import DceRpc4

import test_pn_oracle as pn
from conftest import dut_path, known_defect

SCF, RR = 32, 16                       # connect_pdu 기본값: 32 × 16 × 31.25 µs = 16 ms
NEGOTIATED_MS = SCF * RR * 31.25 / 1000
RUN_S = 2.0


def _lab_ready():
    if os.geteuid() != 0 or not shutil.which("ip"):
        return "root 와 ip 명령이 필요하다 (netns/veth, AF_PACKET)"
    return None


pytestmark = pytest.mark.skipif(_lab_ready() is not None, reason=str(_lab_ready()))


def _sh(*args):
    subprocess.run(list(args), check=True, capture_output=True)


@pytest.fixture(scope="module")
def session():
    """랩 세션 1회: DCP Identify → Connect → O->T RTC1 시작 → PrmEnd → ApplicationReady 수신 → RTC1 수집."""
    tag = uuid.uuid4().hex[:6]
    ns, outer, inner = f"pnlab{tag}", f"vp{tag}a", f"vp{tag}b"
    n = int(tag[:2], 16)
    ctl_ip, dev_ip = f"10.78.{n}.1", f"10.78.{n}.2"
    _sh("ip", "netns", "add", ns)
    dut = None
    res = {}
    try:
        _sh("ip", "link", "add", outer, "type", "veth", "peer", "name", inner)
        _sh("ip", "link", "set", inner, "netns", ns)
        _sh("ip", "link", "set", "dev", outer, "address", pn.CONTROLLER_MAC)
        _sh("ip", "addr", "add", f"{ctl_ip}/24", "dev", outer)
        _sh("ip", "link", "set", outer, "up")
        _sh("ip", "netns", "exec", ns, "ip", "addr", "add", f"{dev_ip}/24", "dev", inner)
        _sh("ip", "netns", "exec", ns, "ip", "link", "set", inner, "up")
        _sh("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up")
        res["iface_mac"] = subprocess.run(
            ["ip", "netns", "exec", ns, "cat", f"/sys/class/net/{inner}/address"],
            check=True, capture_output=True, text=True).stdout.strip().lower()
        dut = subprocess.Popen(["ip", "netns", "exec", ns, str(dut_path("pn_oracle_lab")), inner, dev_ip, "15"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert dut.stdout.readline().strip() == "READY", "pn_oracle_lab 시작 실패"

        # 1) DCP Identify All (실 컨트롤러가 장치 MAC 을 배우는 방법)
        sn = AsyncSniffer(iface=outer, store=True,
                          lfilter=lambda p: p.haslayer(ProfinetIO) and p[ProfinetIO].frameID == 0xFEFF)
        sn.start()
        time.sleep(0.2)
        sendp(Ether(dst=pn.DCP_MCAST, src=pn.CONTROLLER_MAC, type=0x8892) / ProfinetIO(frameID=0xFEFE)
              / ProfinetDCP(service_id=0x05, service_type=0x00, xid=0x1234, reserved=1,
                            option=0xFF, sub_option=0xFF), iface=outer, verbose=False)
        time.sleep(1.3)  # response delay
        dcp = sn.stop()
        assert dcp, "DCP Identify 응답 없음"
        dev_mac = dcp[0].src.lower()
        res["dcp_mac"] = dev_mac

        # 2) Connect (UDP 34964 → 34964)
        rtc1 = AsyncSniffer(iface=outer, store=True,
                            lfilter=lambda p: p.haslayer(ProfinetIO) and 0x8000 <= p[ProfinetIO].frameID <= 0xBFFF
                            and p.src.lower() != pn.CONTROLLER_MAC)
        rtc1.start()
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.bind((ctl_ip, 34964))
        u.settimeout(1.0)
        u.sendto(raw(pn.connect_pdu(scf=SCF, rr=RR)), (dev_ip, 34964))
        data, src = u.recvfrom(4096)
        res["connect_status"], _ = pn.ndr_response(DceRpc4(data))

        # 3) O->T RTC1 (출력 CR FrameID 0x8000, C_SDU 40, DataStatus 0x35) 를 협상 주기로
        stop = threading.Event()

        l2 = conf.L2socket(iface=outer)

        def o2t():
            cc = 0
            nxt = time.monotonic()
            while not stop.is_set():
                l2.send(Ether(dst=dev_mac, src=pn.CONTROLLER_MAC, type=0x8892) / ProfinetIO(frameID=0x8000)
                        / (bytes(pn.C_SDU_LEN) + struct.pack(">HBB", cc & 0xFFFF, 0x35, 0)))
                cc += SCF * RR
                nxt += NEGOTIATED_MS / 1000
                time.sleep(max(0.0, nxt - time.monotonic()))

        th = threading.Thread(target=o2t, daemon=True)
        th.start()
        time.sleep(0.05)

        # 4) PrmEnd, 그 뒤 장치가 컨트롤러 RPC 포트(34964)로 보내는 ApplicationReady 를 받는다
        req = IODControlReq(ARUUID=pn.AR_UUID, SessionKey=pn.SESSION_KEY, ControlCommand_PrmEnd=1)
        u.sendto(raw(pn.pnio_request(4, [req], seqnum=20)), (dev_ip, 34964))
        res["app_ready"] = None
        end = time.time() + RUN_S
        while time.time() < end:
            try:
                d, _ = u.recvfrom(4096)
            except socket.timeout:
                continue
            r = DceRpc4(d)
            if r.ptype == 0 and str(r.if_id) == pn.PNIO_CONTROLLER_IF and res["app_ready"] is None:
                res["app_ready"] = r
        res["rtc1"] = rtc1.stop()
        u.close()
        # O->T 를 멈추기 전에 DUT 를 끝낸다 (멈춘 뒤 data-hold 만료 로그가 판정에 섞이지 않게)
        dut.terminate()
        res["dut_log"] = dut.communicate(timeout=10)[1]
        dut = None
        stop.set()
        th.join(timeout=2)
        l2.close()
    finally:
        if dut:
            dut.terminate()
            try:
                res["dut_log"] = dut.communicate(timeout=10)[1]
            except subprocess.TimeoutExpired:
                dut.kill()
        subprocess.run(["ip", "link", "del", outer], capture_output=True)
        subprocess.run(["ip", "netns", "del", ns], capture_output=True)
    return res


def test_pnlab_connect_over_udp(session):
    assert session["connect_status"] == 0, f"PNIOStatus {session['connect_status']:08x}"


def test_pnlab_application_ready_to_controller_rpc_port(session):
    """ApplicationReady(CControl, 블록 0x0112)가 컨트롤러 IP 의 UDP 34964 로 온다 (p-net PF_RPC_SERVER_PORT)."""
    r = session["app_ready"]
    assert r is not None, "UDP 34964 로 ApplicationReady 가 오지 않았다"
    fmt = "<" if r.endian == 1 else ">"
    stub = raw(r.payload)
    args_len = struct.unpack(fmt + "I", stub[4:8])[0]
    blk = IODControlReq(stub[20:20 + args_len])
    assert blk.block_type == 0x0112 and blk.ControlCommand_ApplicationReady == 1


def test_pnlab_ar_stays_up_with_o2t(session):
    frames = session["rtc1"]
    assert len(frames) >= RUN_S * 1000 / NEGOTIATED_MS / 2, f"RTC1 {len(frames)}개"
    assert "aborted" not in session.get("dut_log", ""), session.get("dut_log", "")[-400:]


def test_pnlab_rtc1_wire_min_length(session):
    lens = sorted({len(raw(f)) for f in session["rtc1"]})
    assert lens and lens[0] >= 60, f"RTC1 길이 {lens}"


def test_pnlab_rtc1_data_status_run(session):
    assert session["rtc1"] and raw(session["rtc1"][-1][ProfinetIO])[-2] == 0x35


# 장치 MAC 은 그 인터페이스의 MAC 이다: DCP·RTC1 의 출발지와 IP(ARP) 가 같은 주소를 써야 한다.
# 다른 MAC 을 알리면 실 NIC 의 유니캐스트 필터가 컨트롤러의 O->T(목적지 = DCP 로 배운 MAC)를 버려 AR 이 끊기고,
# 같은 기본값을 쓰는 장치 두 대는 MAC 이 충돌한다. p-net src/common/pf_eth.c 는 pnal_get_macaddress(netif_name) 로 인터페이스 MAC 을 쓴다.
@known_defect("A20261007-2", "인터페이스 MAC 대신 고정 기본값 02:FB:00:00:00:01 로 DCP·RTC1 을 보낸다 "
              "(pn_stack_create 가 mac_set 을 먼저 켜서 pn_eth_open 의 SIOCGIFHWADDR 분기가 죽어 있다)")
def test_pnlab_device_uses_interface_mac(session):
    assert session["dcp_mac"] == session["iface_mac"], \
        f"DCP 출발지 {session['dcp_mac']} / 인터페이스 {session['iface_mac']}"
    srcs = {f.src.lower() for f in session["rtc1"]}
    assert srcs == {session["iface_mac"]}, f"RTC1 출발지 {srcs}"


@known_defect("T12-8", "RTC1 에 802.1Q 태그(PCP 6, VID 0)가 없다 (선로 위 확인)")
def test_pnlab_rtc1_vlan_tag(session):
    f = session["rtc1"][-1]
    assert f.haslayer(Dot1Q) and f[Dot1Q].prio == 6 and f[Dot1Q].vlan == 0


@known_defect("T4", "RT 송신 간격이 협상값(SCF×RR×31.25µs = 16 ms)이 아니라 cycle_us(8 ms)다 (선로 위 측정)")
def test_pnlab_rtc1_interval_negotiated(session):
    ts = [float(f.time) for f in session["rtc1"]]
    dt = sorted(b - a for a, b in zip(ts, ts[1:]))
    med = dt[len(dt) // 2] * 1000
    assert 0.75 * NEGOTIATED_MS <= med <= 1.25 * NEGOTIATED_MS, f"중앙값 {med:.2f} ms (협상 {NEGOTIATED_MS} ms)"
