"""PROFINET IO Device — 오라클: scapy (contrib.pnio, pnio_dcp, pnio_rpc, dcerpc, lldp, snmp, msrpce ept).

scapy 의 PROFINET 모듈은 Wireshark 디섹터와 같은 사양 필드 정의를 따르는 독립 구현체다.
요청은 scapy 로 만들고, 스택의 응답도 scapy 로 해석해서 사양 형태로 읽히는지 본다.
DUT 는 pn_oracle_pipe (mock Ethernet, 스테이션 이름 "oracle-dut", vendor 0xABCD, device 0x0001).
어댑터 수준 항목(T12-9, T2)은 pn_oracle_app (fb_api + adapters/profinet, BUILD_DAEMON=ON 빌드에만 있음).
"""
import json
import struct
import subprocess
import uuid
import xml.etree.ElementTree as ET

import pytest
from scapy.all import Dot1Q, Ether, raw
from scapy.contrib.lldp import LLDPDU, LLDPDUGenericOrganisationSpecific
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import DCPNameOfStationBlock, DCPDeviceRoleBlock, ProfinetDCP
from scapy.contrib.pnio_rpc import (
    AlarmCRBlockReq,
    AlarmCRBlockRes,
    Alarm_Low,
    ARBlockReq,
    ARBlockRes,
    ExpectedSubmodule,
    ExpectedSubmoduleAPI,
    ExpectedSubmoduleBlockReq,
    ExpectedSubmoduleDataDescription,
    IOCRAPI,
    IOCRAPIObject,
    IM0Block,
    IM1Block,
    IOCRBlockReq,
    IODControlReq,
    IODControlRes,
    IODReadReq,
    IODReadRes,
    IODWriteReq,
    IODWriteRes,
    PNIOServiceReqPDU,
    PNIOServiceResPDU,
)
from scapy.layers.dcerpc import DceRpc4, NDRContextHandle
from scapy.layers.msrpce.raw.ept import ept_lookup_Request
from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind

from conftest import REPO, PnPipe, dut_path, known_defect

CONTROLLER_MAC = "00:11:22:33:44:55"
DCP_MCAST = "01:0e:cf:00:00:00"
PNIO_DEVICE_IF = "dea00001-6c97-11d1-8271-00a02442df7d"
AR_UUID = "a0a1a2a3-a4a5-a6a7-a8a9-aaabacadaeaf"


def tx_frames(lines):
    return [Ether(b) for tag, b in lines if tag == "TX"]


def identify_all(pn):
    req = (Ether(dst=DCP_MCAST, src=CONTROLLER_MAC, type=0x8892)
           / ProfinetIO(frameID=0xFEFE)
           / ProfinetDCP(service_id=0x05, service_type=0x00, xid=0x1234,
                         reserved=1, option=0xFF, sub_option=0xFF))
    out = pn.eth(raw(req))
    out += pn.cmd("POLL 1100")  # response delay 반영
    for f in tx_frames(out):
        if f.haslayer(ProfinetIO) and f[ProfinetIO].frameID == 0xFEFF:
            return f
    return None


# 입력 IOCR (Device → Controller) 의 C_SDU 배치. 사양대로 IOCRBlockReq 의 FrameOffset 이 정한다.
#   (0,1) DAP, (0,0x8000) 인터페이스, (0,0x8001) 포트: 데이터 0바이트 → IOPS 1바이트씩 @0,@1,@2
#   (1,1) IO 서브모듈 입력 32바이트 @3..@34, IOPS @35
#   출력 부분에 대한 IOCS (1,1) @36
IN_LAYOUT_DATA = [(0, 1, 0), (0, 0x8000, 1), (0, 0x8001, 2), (1, 1, 3)]
IN_LAYOUT_IOCS = [(1, 1, 36)]
# 출력 IOCR (Controller → Device): (1,1) 출력 32바이트 @0..@31, IOPS @32,
#   입력 쪽 서브모듈 4개의 IOCS @33..@36
OUT_LAYOUT_DATA = [(1, 1, 0)]
OUT_LAYOUT_IOCS = [(0, 1, 33), (0, 0x8000, 34), (0, 0x8001, 35), (1, 1, 36)]
IO_DATA_LEN = 32
C_SDU_LEN = 40  # IOCRBlockReq DataLength (RT_CLASS_1 최소 40)
CM_INITIATOR_OBJECT_UUID = "dea00000-6c97-11d1-8271-00640001abcd"
SESSION_KEY = 1


def _iocr_objects(entries):
    return [IOCRAPIObject(SlotNumber=sl, SubslotNumber=ss, FrameOffset=off) for sl, ss, off in entries]


DEFAULT_LAYOUT = (IN_LAYOUT_DATA, IN_LAYOUT_IOCS, OUT_LAYOUT_DATA, OUT_LAYOUT_IOCS)


def connect_pdu(station=b"controller", scf=32, rr=16, slot1_module=0x00000010,
                alarm_ref=1, layout=DEFAULT_LAYOUT, startup_mode=0,
                iocr_prio=6, alarm_tag_low=0xA000, alarm_tag_high=0xC000):
    """사양 형태의 Connect.req (ARBlockReq + 입력/출력 IOCR + AlarmCR + ExpectedSubmodule).

    기본 주기는 SCF=32 × RR=16 × 31.25µs = 16ms (GSDML 이 허용해야 하는 값, 장치 최소 8ms 이상).
    alarm_ref 는 컨트롤러의 LocalAlarmReference (장치 알람의 AlarmDstEndpoint 가 된다).
    layout 은 (입력 IODataObjects, 입력 IOCS, 출력 IODataObjects, 출력 IOCS) 의 (slot, subslot, FrameOffset) 목록.
    startup_mode 는 ARProperties.StartupMode (bit 30): 0 Legacy, 1 Advanced.
    iocr_prio / alarm_tag_low / alarm_tag_high 는 IOCRTagHeader 우선순위와 AlarmCRTagHeaderLow/High (사양 고정값 6 / 0xA000 / 0xC000, 거부 시험용).
    """
    in_data, in_iocs, out_data, out_iocs = layout
    common = dict(LT=0x8892, IOCRProperties_RTClass=2, DataLength=C_SDU_LEN,
                  SendClockFactor=scf, ReductionRatio=rr, Phase=1, WatchdogFactor=3,
                  DataHoldFactor=3, IOCRTagHeader_IOUserPriority=iocr_prio,
                  IOCRMulticastMACAdd="01:0e:cf:00:00:00")
    in_iocr = IOCRBlockReq(
        IOCRType=1, IOCRReference=1, FrameID=0x8001, **common,
        APIs=[IOCRAPI(API=0, IODataObjects=_iocr_objects(in_data),
                      IOCSs=_iocr_objects(in_iocs))])
    out_iocr = IOCRBlockReq(
        IOCRType=2, IOCRReference=2, FrameID=0x8000, **common,
        APIs=[IOCRAPI(API=0, IODataObjects=_iocr_objects(out_data),
                      IOCSs=_iocr_objects(out_iocs))])
    ar = ARBlockReq(ARType=1, ARUUID=AR_UUID, SessionKey=SESSION_KEY,
                    CMInitiatorMacAdd=CONTROLLER_MAC,
                    CMInitiatorObjectUUID=CM_INITIATOR_OBJECT_UUID,
                    ARProperties_State=1, ARProperties_ParametrizationServer=0,
                    ARProperties_StartupMode=startup_mode,
                    CMInitiatorActivityTimeoutFactor=600, CMInitiatorUDPRTPort=0x8892,
                    CMInitiatorStationName=station)
    alarm = AlarmCRBlockReq(AlarmCRType=1, LT=0x8892, RTATimeoutFactor=1, RTARetries=3,
                            LocalAlarmReference=alarm_ref, MaxAlarmDataLength=200,
                            AlarmCRTagHeaderHigh=alarm_tag_high, AlarmCRTagHeaderLow=alarm_tag_low)
    # NO_IO(Type 0) 서브모듈에도 Input DataDescription 1개(길이 0, IOCS 1, IOPS 1)가 따라온다:
    # Wireshark dissect_ExpectedSubmoduleBlockReq case 0x00 "one Input DataDescription Block follows",
    # p-net pf_get_exp_submodule "At least one submodule data descriptor", scapy count_from (2 if Type==3 else 1).
    # scapy 는 빌드할 때 count_from 을 쓰지 않으므로 직접 넣어야 한다 (없으면 scapy 자신도 되읽지 못한다).
    no_io = [ExpectedSubmoduleDataDescription(DataDescription=1, SubmoduleDataLength=0, LengthIOCS=1, LengthIOPS=1)]
    exp = ExpectedSubmoduleBlockReq(APIs=[
        ExpectedSubmoduleAPI(API=0, SlotNumber=0, ModuleIdentNumber=0x00000001, Submodules=[
            ExpectedSubmodule(SubslotNumber=1, SubmoduleIdentNumber=0x00000001,
                              SubmoduleProperties_Type=0, DataDescription=list(no_io)),
            ExpectedSubmodule(SubslotNumber=0x8000, SubmoduleIdentNumber=0x00000002,
                              SubmoduleProperties_Type=0, DataDescription=list(no_io)),
            ExpectedSubmodule(SubslotNumber=0x8001, SubmoduleIdentNumber=0x00000003,
                              SubmoduleProperties_Type=0, DataDescription=list(no_io))]),
        ExpectedSubmoduleAPI(API=0, SlotNumber=1, ModuleIdentNumber=slot1_module, Submodules=[
            ExpectedSubmodule(SubslotNumber=1, SubmoduleIdentNumber=0x00000011,
                              SubmoduleProperties_Type=3,
                              DataDescription=[
                                  ExpectedSubmoduleDataDescription(DataDescription=1, SubmoduleDataLength=IO_DATA_LEN, LengthIOCS=1, LengthIOPS=1),
                                  ExpectedSubmoduleDataDescription(DataDescription=2, SubmoduleDataLength=IO_DATA_LEN, LengthIOCS=1, LengthIOPS=1)])]),
    ])
    return pnio_request(0, [ar, in_iocr, out_iocr, alarm, exp], seqnum=1)


def pnio_request(opnum, blocks, seqnum):
    """PNIO Device 인터페이스로 가는 DCE/RPC 요청 (opnum 0 Connect, 2 Read, 3 Write, 4 Control)."""
    rpc = DceRpc4(ptype="request", flags1=0x20, opnum=opnum, if_id=PNIO_DEVICE_IF,
                  object="dea00000-6c97-11d1-8271-0001abcd0001",
                  act_id=str(uuid.UUID(int=1)), seqnum=seqnum)
    return rpc / PNIOServiceReqPDU(args_max=16384, blocks=blocks)


def ndr_response(rsp):
    """응답 NDR: PNIOStatus(4) ArgsLength(4) MaxCount(4) Offset(4) ActualCount(4) Blocks.

    정수 필드는 DCE/RPC 헤더의 drep 바이트 순서를 따른다 (PNIOStatus 도 32비트 정수로 읽는다.
    Wireshark dissect_PNIO_status 와 scapy PNIOServiceResPDU 가 같은 규칙).
    반환: (PNIOStatus 정수, blocks 바이트).
    """
    stub = raw(rsp.payload)
    fmt = "<" if rsp.endian == 1 else ">"
    status, args_len = struct.unpack(fmt + "II", stub[:8])
    return status, stub[20:20 + args_len]


def split_blocks(data):
    """BlockHeader(BlockType(2) BlockLength(2) Version(2)) 로 블록을 나눈다. 블록 필드는 항상 빅 엔디안."""
    out = []
    off = 0
    while off + 4 <= len(data):
        btype, blen = struct.unpack(">HH", data[off:off + 4])
        out.append((btype, data[off:off + 4 + blen]))
        off += 4 + blen
    return out


def rpc_response(lines):
    for tag, b in lines:
        if tag == "RSP":
            return DceRpc4(b)
    return None


# ---------------------------------------------------------------- DCP
def test_dcp_identify_is_answered(pn_dut):
    f = identify_all(pn_dut)
    assert f is not None, "Identify.Res 없음"
    dcp = f[ProfinetDCP]
    assert dcp.service_id == 0x05 and dcp.service_type == 0x01
    assert dcp.xid == 0x1234


def test_dcp_identify_name_of_station(pn_dut):
    f = identify_all(pn_dut)
    names = [bytes(b.name_of_station) for b in f[ProfinetDCP].dcp_blocks
             if isinstance(b, DCPNameOfStationBlock)]
    assert names == [b"oracle-dut"]


@known_defect("T12-22", "DeviceRole 을 0x02(IO Controller)로 응답한다. IO Device 는 0x01 "
              "(T12-2 가 고쳐지기 전에는 블록 해석 자체가 안 돼서 빈 목록이 나온다)")
def test_dcp_identify_device_role(pn_dut):
    # T12-2 가 먼저 고쳐져야 블록 해석이 맞는다.
    f = identify_all(pn_dut)
    roles = [b.device_role_details for b in f[ProfinetDCP].dcp_blocks
             if isinstance(b, DCPDeviceRoleBlock)]
    assert roles == [0x01]


# ---------------------------------------------------------------- LLDP
@known_defect("T12-11", "PROFINET 조직 TLV 의 OUI 가 00-0C-CF 다. PNO OUI 는 00-0E-CF")
def test_lldp_pno_oui(pn_dut):
    frames = [f for f in tx_frames(pn_dut.startup) if f.type == 0x88CC]
    assert frames, "시작 시 LLDP 송신 없음"
    ouis = {t.org_code for t in frames[0].getlayer(LLDPDU).iterpayloads()
            if isinstance(t, LLDPDUGenericOrganisationSpecific)}
    assert 0x000ECF in ouis


# ---------------------------------------------------------------- RPC
def test_connect_is_answered(pn_dut):
    rsp = rpc_response(pn_dut.rpc(raw(connect_pdu())))
    assert rsp is not None, "Connect 응답 없음"
    assert rsp.ptype == 2  # response


def test_connect_response_pniostatus_ok(pn_dut):
    rsp = rpc_response(pn_dut.rpc(raw(connect_pdu())))
    res = PNIOServiceResPDU(raw(rsp.payload))
    assert res.status == 0


# ---------------------------------------------------------------- RTC1
def is_rtc1(f):
    # VLAN 태그(T12-8)가 붙어도 찾도록 EtherType 대신 ProfinetIO 계층과 FrameID 로 고른다.
    return f.haslayer(ProfinetIO) and 0x8000 <= f[ProfinetIO].frameID <= 0xBFFF


def rtc1_frames(pn, poll_ms=60, **connect_kw):
    pn.rpc(raw(connect_pdu(**connect_kw)))
    out = pn.cmd(f"POLL {poll_ms}")
    return [f for f in tx_frames(out) if is_rtc1(f)]


def c_sdu(f):
    """RTC1 APDU 에서 C_SDU 만 뗀다: [FrameID(2)] C_SDU [CycleCounter(2) DataStatus(1) TransferStatus(1)]."""
    apdu = raw(f[ProfinetIO])
    return apdu[2:-4]


def cycle_counter(f):
    return struct.unpack(">H", raw(f[ProfinetIO])[-4:-2])[0]


def test_rtc1_data_status_run(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    tail = raw(frames[-1])[-4:]  # CycleCounter(2) DataStatus(1) TransferStatus(1)
    assert tail[2] == 0x35


def test_rtc1_minimum_frame_length(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames
    assert len(raw(frames[-1])) >= 60


def test_rtc1_frame_offsets_follow_iocr(pn_dut):
    pattern = bytes(range(0x10, 0x10 + IO_DATA_LEN))
    pn_dut.cmd("INPUT " + pattern.hex())
    frames = rtc1_frames(pn_dut)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    sdu = c_sdu(frames[-1])
    assert len(sdu) == C_SDU_LEN, f"C_SDU 길이 {len(sdu)} (IOCR DataLength {C_SDU_LEN})"
    iops_good = 0x80  # DataState=Good
    # DAP·인터페이스·포트 IOPS(@0..@2)의 값은 보지 않는다: 그 서브모듈 ident 는 GSDML 에 아직 없어서
    # (T12-13) 기대 ident 가 추측이고, 불일치면 장치가 IOPS 를 Bad 로 낼 수 있다.
    data_off = IN_LAYOUT_DATA[3][2]
    assert sdu[data_off:data_off + IO_DATA_LEN] == pattern
    assert sdu[data_off + IO_DATA_LEN] == iops_good, "IOPS (1,1)"


def test_rtc1_vlan_priority_tag(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    f = frames[-1]
    assert f.haslayer(Dot1Q), "VLAN 태그 없음"
    assert f[Dot1Q].prio == 6 and f[Dot1Q].vlan == 0
    assert f[Dot1Q].type == 0x8892


def test_rtc1_cycle_counter_step(pn_dut):
    frames = rtc1_frames(pn_dut, poll_ms=80, scf=32, rr=16)
    assert len(frames) >= 2, "비교할 RTC1 프레임이 2개 미만"
    steps = {(cycle_counter(b) - cycle_counter(a)) & 0xFFFF for a, b in zip(frames, frames[1:])}
    assert steps == {32 * 16}


def test_rtc1_send_interval_is_negotiated(pn_dut):
    # 16ms 로 협상하고 400ms 동안 센다. 16ms 면 약 25개, 8ms 로 보내면 약 50개.
    frames = rtc1_frames(pn_dut, poll_ms=400, scf=32, rr=16)
    assert 15 <= len(frames) <= 32, f"400ms 동안 RTC1 {len(frames)}개 (16ms 주기면 약 25개)"


# ---------------------------------------------------------------- Connect 응답 블록
def connect_blocks(pn, **connect_kw):
    rsp = rpc_response(pn.rpc(raw(connect_pdu(**connect_kw))))
    assert rsp is not None, "Connect 응답 없음"
    status, blocks = ndr_response(rsp)
    return status, split_blocks(blocks)


# ARServerBlock(0x8106)은 ARProperties.StartupMode=Advanced 일 때만 Connect.res 에 들어간다 (Advanced 에서는 필수,
# Legacy 에서는 넣지 않는다). p-net pf_cmrpc.c "Additional blocks in advanced start mode: {ARServerBlockRes, …}",
# Siemens CM 컨트롤러 cm_cl30.c cm_cl_parse_connect_response: Legacy 에 이 블록이 오면 CM_AR_REASON_PROT 로 AR 중단,
# Advanced 에 없으면 역시 중단. (2026-10-05 오라클 수정: 전에는 Legacy Connect 에 이 블록을 요구했다.)
def test_connect_response_has_ar_server_block(pn_dut):
    status, blocks = connect_blocks(pn_dut, startup_mode=1)
    assert status == 0
    servers = [b for t, b in blocks if t == 0x8106]
    assert len(servers) == 1, f"블록 타입 {[hex(t) for t, _ in blocks]}"
    # ARServerBlock: BlockHeader(6) StationNameLength(2) CMResponderStationName
    name_len = struct.unpack(">H", servers[0][6:8])[0]
    assert servers[0][8:8 + name_len] == b"oracle-dut"


def test_connect_legacy_response_has_no_ar_server_block(pn_dut):
    """Legacy(StartupMode=0) Connect.res 에는 ARServerBlock 이 없어야 한다 (위 근거, Siemens 컨트롤러는 AR 을 끊는다)."""
    status, blocks = connect_blocks(pn_dut, startup_mode=0)
    assert status == 0
    assert 0x8106 not in [t for t, _ in blocks], f"블록 타입 {[hex(t) for t, _ in blocks]}"


def test_connect_response_module_diff_on_wrong_module(pn_dut):
    # GSDML 의 slot 1 모듈은 0x00000010. 없는 모듈 번호를 기대하면 ModuleDiffBlock 으로 알려야 한다.
    status, blocks = connect_blocks(pn_dut, slot1_module=0xDEADBEEF)
    assert status == 0
    assert 0x8104 in [t for t, _ in blocks], f"블록 타입 {[hex(t) for t, _ in blocks]}"


# ---------------------------------------------------------------- 최소 주기 (T5)
def test_connect_rejects_cycle_below_device_minimum(pn_dut):
    rsp = rpc_response(pn_dut.rpc(raw(connect_pdu(scf=32, rr=4))))
    assert rsp is not None, "Connect 응답 없음"
    status, _ = ndr_response(rsp)
    # ErrorCode2 11 (0x0B) "ReductionRatio": Wireshark packet-pn.c pn_io_error_code2_pnio_2, p-net pf_cmdev.c
    # (MinDeviceInterval > SCF×RR → FAULTY_IOCR_BLOCK_REQ, 11). 0x0E(14) 는 FrameSendOffset 이다 (2026-10-09 정정).
    assert status == 0xDB81020B, f"PNIOStatus {status:08x}"
    out = pn_dut.cmd("POLL 50")
    assert not [f for f in tx_frames(out) if is_rtc1(f)], "거부한 Connect 뒤에 RTC1 을 보낸다"


# IOCRTagHeader 와 AlarmCRTagHeaderHigh/Low 는 사양 고정값이다: IOCR VID 0·우선순위 6 (0xC000), 알람 High 0xC000,
# 알람 Low 0xA000 (VID 0·우선순위 5). 다른 값의 Connect 는 거부한다.
# - p-net src/device/pf_cmdev.c: iocr_tag_header.vlan_id != 0 또는 iocr_user_priority != 6 → CONNECT / PNIO /
#   FAULTY_IOCR_BLOCK_REQ(0x02) / 17, alarm_cr_tag_header_high/low 의 VID·우선순위(6/5) 불일치 → FAULTY_ALARM_BLOCK_REQ(0x04) / 11·12.
#   상수 include/pnet_api.h: CONNECT 0xDB, PNIO 0x81, FAULTY_IOCR_BLOCK_REQ 0x02, FAULTY_ALARM_BLOCK_REQ 0x04.
# - Siemens CM cm_argr.c: IOCRTagHeader != 0xC000 → 17, AlarmCRTagHeaderHigh != 0xC000 → 11, Low != 0xA000 → 12.
# ErrorCode2 번호는 10진이다 (Wireshark packet-pn.c 표): 17 = 0x11, 11 = 0x0B, 12 = 0x0C.
# (2026-10-09 정정: 알람 Low 를 0x12 로 잘못 옮겼었다.)
@known_defect("A20261007-1", "Connect 의 IOCRTagHeader·AlarmCRTagHeader 값을 검사하지 않고 받아들인다. "
              "사양: 우선순위 6 이 아닌 IOCR 태그는 DB 81 02 11, 0xA000 이 아닌 알람 Low 태그는 DB 81 04 0C 로 거부")
@pytest.mark.parametrize("kw,expected", [
    (dict(iocr_prio=5), 0xDB810211),          # IOCRTagHeader 0xA000 (우선순위 5)
    (dict(alarm_tag_low=0xC000), 0xDB81040C),  # AlarmCRTagHeaderLow 우선순위 6 → ErrorCode2 12 (0x0C)
    (dict(alarm_tag_high=0xA000), 0xDB81040B), # AlarmCRTagHeaderHigh 우선순위 5 → ErrorCode2 11 (0x0B)
], ids=["iocr-prio5", "alarm-low-prio6", "alarm-high-prio5"])
def test_connect_rejects_nonstandard_tag_header(pn_dut, kw, expected):
    rsp = rpc_response(pn_dut.rpc(raw(connect_pdu(**kw))))
    assert rsp is not None, "Connect 응답 없음"
    status, _ = ndr_response(rsp)
    assert status == expected, f"PNIOStatus {status:08x} (기대 {expected:08x})"


# ---------------------------------------------------------------- 두 번째 컨트롤러 Connect 거부 (A20261002-1)
OTHER_AR_UUID = "b0b1b2b3-b4b5-b6b7-b8b9-babbbcbdbebf"
OTHER_CM_INITIATOR_OBJECT_UUID = "dea00000-6c97-11d1-8271-00640002abcd"
OTHER_CONTROLLER_MAC = "00:11:22:33:44:66"


@known_defect("A20261002-1", "AR 이 있는 동안 다른 컨트롤러의 Connect 를 PNIOStatus 바이트 81 00 00 00 "
              "(LE drep 정수 0x00000081, ErrorCode=0x00 'OK') 로 거부한다. "
              "사양: DB 81 40 04 (IODConnectRes, PNIO, CMRPC, Out of AR resources)")
def test_connect_second_controller_out_of_ar_resources(pn_dut):
    first = rpc_response(pn_dut.rpc(raw(connect_pdu())))
    assert first is not None and ndr_response(first)[0] == 0, "첫 Connect 가 수립되지 않음"
    # 다른 컨트롤러: ARUUID·CMInitiatorObjectUUID·MAC·스테이션 이름이 모두 다르다.
    # (같은 ARUUID 재사용은 p-net 에서 CMDEV 상태 충돌 DB 81 3D 00 이라 다른 경우다.)
    req = connect_pdu(station=b"other-controller")
    ar = req[ARBlockReq]
    ar.ARUUID = OTHER_AR_UUID
    ar.CMInitiatorObjectUUID = OTHER_CM_INITIATOR_OBJECT_UUID
    ar.CMInitiatorMacAdd = OTHER_CONTROLLER_MAC
    rsp = rpc_response(pn_dut.rpc(raw(req)))
    assert rsp is not None, "두 번째 Connect 응답 없음"
    # PNIOStatus 는 drep 순서 32비트 정수: ErrorCode<<24 | ErrorDecode<<16 | ErrorCode1<<8 | ErrorCode2
    # (Wireshark packet-pn.c dissect_PNIO_status, scapy PNIOServiceResPDU EField, p-net pf_put_pnet_status).
    # 0xDB IODConnectRes, 0x81 PNIO, 0x40 CMRPC, 0x04 Out of AR resources
    # (Wireshark pn_io_error_code2_pnio_64, p-net PNET_ERROR_CODE_2_CMRPC_NO_AR_RESOURCES).
    status, blocks = ndr_response(rsp)
    assert status == 0xDB814004, f"PNIOStatus {status:08x}"
    assert blocks == b"", f"거부 응답에 블록 {blocks.hex()}"
    # 거부는 기존 AR 을 건드리지 않는다: 첫 컨트롤러로 RTC1 이 계속 나간다.
    out = pn_dut.cmd("POLL 60")
    assert [f for f in tx_frames(out) if is_rtc1(f)], "두 번째 Connect 거부 뒤 기존 AR 의 RTC1 이 멈췄다"


# ---------------------------------------------------------------- Record Read/Write (T12-3)
IM0_INDEX = 0xAFF0
IM1_INDEX = 0xAFF1


def record_read(pn, index, seqnum):
    req = IODReadReq(seqNum=seqnum, ARUUID=AR_UUID, API=0, slotNumber=0, subslotNumber=1,
                     index=index, recordDataLength=4096)
    rsp = rpc_response(pn.rpc(raw(pnio_request(2, [req], seqnum=10 + seqnum))))
    assert rsp is not None, "Read 응답 없음"
    return ndr_response(rsp)


def record_write(pn, index, data, seqnum):
    req = IODWriteReq(seqNum=seqnum, ARUUID=AR_UUID, API=0, slotNumber=0, subslotNumber=1,
                      index=index, recordDataLength=len(data)) / data
    rsp = rpc_response(pn.rpc(raw(pnio_request(3, [req], seqnum=10 + seqnum))))
    assert rsp is not None, "Write 응답 없음"
    return ndr_response(rsp)


def read_res_record(blocks):
    """IODReadResHeader(0x8009, 64바이트) 뒤의 레코드 데이터."""
    assert blocks[:2] == b"\x80\x09", f"첫 블록 타입 {blocks[:2].hex()} (IODReadResHeader 0x8009 기대)"
    hdr = IODReadRes(blocks[:64])
    assert hdr.block_length == 60
    return blocks[64:64 + hdr.recordDataLength]


def test_record_read_im0(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    status, blocks = record_read(pn_dut, IM0_INDEX, seqnum=1)
    assert status == 0
    im0 = IM0Block(read_res_record(blocks))
    assert im0.block_type == 0x0020
    assert (im0.VendorIDHigh << 8 | im0.VendorIDLow) == 0xABCD


@known_defect("A20261004-1", "I&M0 OrderID 20번째 바이트가 NUL 이다 (19자 리터럴 + 종단 NUL). "
              "사양: VisibleString[20], 남는 자리는 공백 0x20")
def test_record_read_im0_visible_strings(pn_dut):
    # I&M0 OrderID 는 VisibleString 20옥텟, IM_Serial_Number 는 16옥텟 고정 길이 (Wireshark packet-dcerpc-pn-io.c
    # dissect_IandM0_block: OrderID c8[20], IMSerialNumber c8[16]). VisibleString 은 0x20–0x7E 만 허용하고,
    # 독립 구현 p-net pf_put_str(pf_block_writer.c) 은 짧은 문자열 뒤를 공백으로 채운다 (NUL 을 쓰지 않음).
    # GSDML DeviceAccessPointItem OrderNumber "FB-ARCH-PN-DEV" 와 같은 값이어야 한다.
    pn_dut.rpc(raw(connect_pdu()))
    status, blocks = record_read(pn_dut, IM0_INDEX, seqnum=1)
    assert status == 0
    im0 = IM0Block(read_res_record(blocks))
    assert im0.block_type == 0x0020
    for name, n in (("OrderID", 20), ("IMSerialNumber", 16)):
        v = bytes(getattr(im0, name))
        assert len(v) == n and all(0x20 <= b <= 0x7E for b in v), f"{name} {v!r}"
    assert bytes(im0.OrderID) == b"FB-ARCH-PN-DEV".ljust(20)


def test_record_write_im1_roundtrip(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    im1 = raw(IM1Block(IMTagFunction=b"ORACLE-FUNCTION".ljust(32),
                       IMTagLocation=b"ORACLE-LOCATION".ljust(22)))
    status, blocks = record_write(pn_dut, IM1_INDEX, im1, seqnum=1)
    assert status == 0
    assert blocks[:2] == b"\x80\x08", f"첫 블록 타입 {blocks[:2].hex()} (IODWriteResHeader 0x8008 기대)"
    assert IODWriteRes(blocks[:64]).status == 0
    status, blocks = record_read(pn_dut, IM1_INDEX, seqnum=2)
    assert status == 0
    back = IM1Block(read_res_record(blocks))
    assert back.block_type == 0x0021
    assert back.IMTagFunction == b"ORACLE-FUNCTION".ljust(32)
    assert back.IMTagLocation == b"ORACLE-LOCATION".ljust(22)


# ---------------------------------------------------------------- PrmEnd / ApplicationReady (T12-5)
PNIO_CONTROLLER_IF = "dea00002-6c97-11d1-8271-00a02442df7d"


def prm_end(pn):
    req = IODControlReq(ARUUID=AR_UUID, SessionKey=SESSION_KEY, ControlCommand_PrmEnd=1)
    rsp = rpc_response(pn.rpc(raw(pnio_request(4, [req], seqnum=20))))
    assert rsp is not None, "PrmEnd 응답 없음"
    return ndr_response(rsp)


def test_prm_end_response_done(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    status, blocks = prm_end(pn_dut)
    assert status == 0
    res = IODControlRes(blocks)
    assert res.block_type == 0x8110
    assert str(res.ARUUID) == AR_UUID and res.SessionKey == SESSION_KEY
    # BlockHeader(6) Padding(2) ARUUID(16) SessionKey(2) AlarmSequenceNumber(2) ControlCommand(2)
    assert raw(res)[28:30] == b"\x00\x08", f"ControlCommand {raw(res)[28:30].hex()} (Done 0x0008 기대)"


def test_application_ready_request(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    prm_end(pn_dut)
    pn_dut.cmd("POLL 50")
    sent = [b for tag, b in pn_dut.cmd("TAKE") if tag == "RPCTX"]
    assert sent, "PrmEnd 뒤에 ApplicationReady 요청을 만들지 않는다"
    rpc = DceRpc4(sent[0])
    assert rpc.rpc_vers == 4 and rpc.ptype == 0 and rpc.opnum == 4
    assert str(rpc.object) == CM_INITIATOR_OBJECT_UUID
    assert str(rpc.if_id) == PNIO_CONTROLLER_IF
    fmt = "<" if rpc.endian == 1 else ">"
    stub = raw(rpc.payload)
    args_len = struct.unpack(fmt + "I", stub[4:8])[0]  # 요청 NDR: ArgsMaximum ArgsLength MaxCount Offset ActualCount
    req = IODControlReq(stub[20:20 + args_len])
    assert req.block_type == 0x0112
    assert str(req.ARUUID) == AR_UUID and req.SessionKey == SESSION_KEY
    assert req.ControlCommand_ApplicationReady == 1


# ---------------------------------------------------------------- GSDML (T12-13, T5)
# GSDML 스키마·GSDML Checker 는 오픈소스가 없다. 인수인계 문서 T5·T12-13 (Fable 사양 검토)의
# 기대값만 본다: 필수 요소 존재, DAP MinDeviceInterval, SendClock/ReductionRatio 목록.
GSDML_DIR = REPO / "stacks" / "profinet" / "gsdml"


def gsdml_root():
    files = sorted(GSDML_DIR.glob("GSDML-*.xml"))
    assert len(files) == 1, f"GSDML 파일이 하나가 아니다: {[f.name for f in files]}"
    return ET.parse(files[0]).getroot()


def test_gsdml_required_elements():
    dap = gsdml_root().find(".//{*}DeviceAccessPointItem")
    assert dap is not None
    assert dap.find("{*}VirtualSubmoduleList/{*}VirtualSubmoduleItem") is not None, "DAP VirtualSubmoduleItem"
    sysdef = dap.find("{*}SystemDefinedSubmoduleList")
    assert sysdef is not None, "SystemDefinedSubmoduleList"
    iface = sysdef.find("{*}InterfaceSubmoduleItem")
    assert iface is not None and iface.get("SubslotNumber") == "32768", "InterfaceSubmoduleItem 32768"
    ports = [p.get("SubslotNumber") for p in sysdef.findall("{*}PortSubmoduleItem")]
    assert "32769" in ports, f"PortSubmoduleItem 32769 (있는 것: {ports})"
    assert iface.find("{*}ApplicationRelations/{*}TimingProperties") is not None, "TimingProperties"
    assert dap.find("{*}CertificationInfo") is not None, "CertificationInfo"


def test_gsdml_timing_matches_device_minimum():
    dap = gsdml_root().find(".//{*}DeviceAccessPointItem")
    assert dap.get("MinDeviceInterval") == "256"
    timing = dap.find(".//{*}InterfaceSubmoduleItem/{*}ApplicationRelations/{*}TimingProperties")
    assert timing is not None, "TimingProperties"
    assert timing.get("SendClock", "32").split() == ["32"]
    rrs = [int(v) for v in timing.get("ReductionRatio", "").split()]
    assert rrs, "ReductionRatio 목록 없음"
    for rr in rrs:
        assert rr & (rr - 1) == 0, f"RR {rr} 는 2의 거듭제곱이 아니다"
        assert 32 * rr >= 256, f"RR {rr} → {32 * rr * 31.25 / 1000}ms < 8ms"


# ---------------------------------------------------------------- Connect 응답 블록 형식 (T12-12)
def connect_res_blocks(pn, **connect_kw):
    """Connect 응답의 블록 목록. PNIOStatus 는 보지 않는다 (ArgsLength @4 는 T12-1 과 무관하게 같은 자리)."""
    rsp = rpc_response(pn.rpc(raw(connect_pdu(**connect_kw))))
    assert rsp is not None, "Connect 응답 없음"
    _, blocks = ndr_response(rsp)
    return split_blocks(blocks)


@known_defect("T12-12", "AlarmCRBlockRes 본문이 8바이트다 (BlockLength 10). 사양: AlarmCRType·LocalAlarmReference·"
              "MaxAlarmDataLength 6바이트 (BlockLength 8)")
def test_connect_alarm_cr_block_res_length(pn_dut):
    blocks = [b for t, b in connect_res_blocks(pn_dut) if t == 0x8103]
    assert len(blocks) == 1, "AlarmCRBlockRes(0x8103) 없음"
    res = AlarmCRBlockRes(blocks[0])
    assert res.block_length == 8, f"BlockLength {res.block_length}"
    assert res.AlarmCRType == 1


@known_defect("T12-12", "ARBlockRes 의 CMResponderUDPRTPort 가 0x8894(RPC 포트)다. RT_CLASS_1 (UDP 아님) 은 0x8892")
def test_connect_ar_block_res_udp_rt_port(pn_dut):
    blocks = [b for t, b in connect_res_blocks(pn_dut) if t == 0x8101]
    assert len(blocks) == 1, "ARBlockRes(0x8101) 없음"
    res = ARBlockRes(blocks[0])
    assert str(res.ARUUID) == AR_UUID and res.SessionKey == SESSION_KEY
    assert res.CMResponderUDPRTPort == 0x8892, f"CMResponderUDPRTPort 0x{res.CMResponderUDPRTPort:04x}"


# ---------------------------------------------------------------- Alarm RTA-PDU (T12-10)
ALARM_LOW_FID = 0xFE01


def alarm_rta(pn, frame_id=ALARM_LOW_FID):
    """장치가 보낸 알람 프레임의 RTA-PDU (FrameID 뒤). VLAN 태그(T12-8) 유무와 관계없이 ProfinetIO 로 찾는다."""
    out = pn.cmd(f"ALARM {frame_id:04x}")
    frames = [f for f in tx_frames(out)
              if f.haslayer(ProfinetIO) and f[ProfinetIO].frameID == frame_id]
    assert frames, f"FrameID 0x{frame_id:04x} 알람 프레임 없음"
    assert frames[0].dst == CONTROLLER_MAC
    return raw(frames[0][ProfinetIO])[2:]


@known_defect("T12-10", "알람 RTA-PDU 가 PDUType 0x01(버전 0)·AddFlags 0 이고 AlarmNotification 블록 헤더가 깨져 있다. "
              "사양: PDUType 0x11 (DATA-RTA, 버전 1), AddFlags WindowSize=1, VarPartLen = BlockHeader 포함 블록 길이")
def test_alarm_rta_pdu_format(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    rta = alarm_rta(pn_dut)
    # RTA-PDU 헤더 (scapy PNIORealTimeAcyclicPDUHeader):
    #   AlarmDstEndpoint(2) AlarmSrcEndpoint(2) PDUType(1) AddFlags(1) SendSeqNum(2) AckSeqNum(2) VarPartLen(2)
    # PDUType: Type(DATA=1) 와 Version(1) 두 니블 → 0x11. AddFlags 하위 니블 WindowSize = 1.
    # 헤더는 필드 순서대로 직접 읽는다 (본문이 깨져 있으면 scapy Alarm_Low 전체 해석이 예외로 끝나므로).
    assert rta[4] == 0x11, f"PDUType 0x{rta[4]:02x} (Type DATA=1, Version 1)"
    assert rta[5] & 0x0F == 1, f"AddFlags 0x{rta[5]:02x} (WindowSize=1)"
    var_len = struct.unpack(">H", rta[10:12])[0]  # VarPartLen
    assert 12 + var_len <= len(rta), f"VarPartLen {var_len} > 남은 {len(rta) - 12}"
    block = Alarm_Low(rta[:12 + var_len]).RTA_SDU  # AlarmNotification-Low 블록 (scapy)
    assert block.block_type == 0x0002, f"BlockType 0x{block.block_type:04x} (AlarmNotification-Low 0x0002)"
    assert block.block_length == var_len - 4, f"BlockLength {block.block_length}, VarPartLen {var_len}"


@known_defect("T12-10", "AlarmCRBlockReq 를 파싱하지 않아 AlarmDstEndpoint 가 1 고정이다. "
              "사양: 컨트롤러 LocalAlarmReference")
def test_alarm_dst_endpoint_from_alarm_cr_req(pn_dut):
    pn_dut.rpc(raw(connect_pdu(alarm_ref=0x0007)))
    rta = alarm_rta(pn_dut)
    dst = struct.unpack(">H", rta[0:2])[0]  # AlarmDstEndpoint (PNIORealTimeAcyclicPDUHeader 첫 필드)
    assert dst == 0x0007, f"AlarmDstEndpoint {dst}"


# ---------------------------------------------------------------- DCE/RPC 헤더 (T12-14)
EPM_IF = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"


def cl_header(pdu):
    """CL DCE/RPC 헤더를 drep 대로 읽는다 (drep[0] 상위 니블: 0 = 빅 엔디안, 1 = 리틀 엔디안).

    반환: (ptype, 정수 fmt, fragment length @74, body @80).
    """
    fmt = "<" if pdu[4] >> 4 == 1 else ">"
    frag_len = struct.unpack(fmt + "H", pdu[74:76])[0]
    return pdu[1], fmt, frag_len, pdu[80:]


def raw_rsp(lines):
    for tag, b in lines:
        if tag == "RSP":
            return b
    return None


@known_defect("T12-14", "drep 을 무시하고 LE 로 고정한다. 빅 엔디안 drep 요청의 응답 헤더 fragment length·NDR 이 "
              "응답 drep 과 맞지 않는다")
def test_rpc_big_endian_drep_connect(pn_dut):
    req = connect_pdu()
    req.endian = 0  # drep: 빅 엔디안 정수. scapy 가 RPC 헤더·NDR 을 BE 로 만든다.
    rsp = raw_rsp(pn_dut.rpc(raw(req)))
    assert rsp is not None, "BE drep Connect 응답 없음"
    ptype, fmt, frag_len, body = cl_header(rsp)
    assert ptype == 2
    assert frag_len == len(body), f"fragment length {frag_len}, 실제 body {len(body)}"
    args_len, _, offset, actual = struct.unpack(fmt + "IIII", body[4:20])
    assert offset == 0 and args_len == actual and 20 + args_len <= len(body), \
        f"NDR (drep {fmt}) ArgsLength {args_len} Offset {offset} ActualCount {actual}"
    types = [t for t, _ in split_blocks(body[20:20 + args_len])]
    assert types[:1] == [0x8101], f"블록 타입 {[hex(t) for t in types]}"


@known_defect("T12-14", "인터페이스 UUID 를 검사하지 않아 모르는 인터페이스의 opnum 2 를 PNIO Read 로 처리하고 응답한다. "
              "사양: reject (nca_unk_if) 또는 무응답")
def test_rpc_unknown_interface_not_served(pn_dut):
    rd = IODReadReq(seqNum=1, ARUUID=AR_UUID, API=0, slotNumber=0, subslotNumber=1,
                    index=IM0_INDEX, recordDataLength=4096)
    req = pnio_request(2, [rd], seqnum=30)
    req.if_id = "0badc0de-0000-1000-8000-00a02442df7d"
    rsp = raw_rsp(pn_dut.rpc(raw(req)))
    assert rsp is None or rsp[1] in (3, 6), f"ptype {rsp[1]} (fault 3 / reject 6 또는 무응답이어야 한다)"


@known_defect("T12-14", "EPM(ept_lookup) 이 없다. 인터페이스를 보지 않아 EPM opnum 2 를 PNIO Read 로 처리하고 I&M0 를 "
              "돌려준다. 사양: 0x8894 의 EPM 이 PNIO Device 인터페이스 tower 를 돌려준다")
def test_rpc_epm_lookup_lists_pnio_interface(pn_dut):
    # ept_lookup (EPM v3, opnum 2) 요청 스텁은 scapy msrpce (NDR 32비트) 로 만든다.
    stub = raw(ept_lookup_Request(inquiry_type=0, object=None, Ifid=None, vers_option=1,
                                  entry_handle=NDRContextHandle(), max_ents=4, ndr64=False))
    req = DceRpc4(ptype="request", flags1=0x20, opnum=2, if_id=EPM_IF, if_vers=3,
                  object=str(uuid.UUID(int=0)), act_id=str(uuid.UUID(int=2)), seqnum=1) / stub
    rsp = raw_rsp(pn_dut.rpc(raw(req)))
    assert rsp is not None, "EPM lookup 응답 없음"
    ptype, fmt, _, body = cl_header(rsp)
    assert ptype == 2
    # 응답: entry_handle(20) num_ents(4) entries[] status(4). tower floor 1 에 인터페이스 UUID (LE 인코딩)가 있다.
    assert len(body) >= 28, f"응답 스텁 {len(body)}바이트"
    num_ents = struct.unpack(fmt + "I", body[20:24])[0]
    assert num_ents >= 1, f"num_ents {num_ents}"
    assert uuid.UUID(PNIO_DEVICE_IF).bytes_le in body, "PNIO Device 인터페이스 tower 없음"
    assert struct.unpack(fmt + "I", body[-4:])[0] == 0, "ept_lookup status"


@known_defect("T12-14", "단편화를 지원하지 않는다. 첫 단편만으로 Connect 를 처리해 응답한다. "
              "사양: 마지막 단편까지 모아서 한 번 처리")
def test_rpc_fragmented_connect(pn_dut):
    whole = connect_pdu()
    stub = raw(whole.payload)
    cut = (len(stub) // 2) & ~7  # 마지막이 아닌 단편 body 는 8의 배수
    common = dict(ptype="request", opnum=0, if_id=PNIO_DEVICE_IF, object=whole.object,
                  act_id=whole.act_id, seqnum=whole.seqnum)
    # flags1: 0x20 idempotent | 0x08 no fack | 0x04 frag | 0x02 last frag
    first = DceRpc4(flags1=0x2C, fragnum=0, **common) / stub[:cut]
    last = DceRpc4(flags1=0x2E, fragnum=1, **common) / stub[cut:]
    rsp0 = raw_rsp(pn_dut.rpc(raw(first)))
    assert rsp0 is None or rsp0[1] == 9, f"첫 단편에 ptype {rsp0[1]} 로 응답 (무응답 또는 fack 9 여야 한다)"
    rsp = raw_rsp(pn_dut.rpc(raw(last)))
    assert rsp is not None, "마지막 단편 뒤 Connect 응답 없음"
    ptype, fmt, _, body = cl_header(rsp)
    assert ptype == 2
    args_len = struct.unpack(fmt + "I", body[4:8])[0]
    types = [t for t, _ in split_blocks(body[20:20 + args_len])]
    assert types.count(0x8101) == 1 and types.count(0x8102) == 2 and types.count(0x8103) == 1, \
        f"블록 타입 {[hex(t) for t in types]}"


# ---------------------------------------------------------------- DCP Set (T12-16)
DEVICE_MAC = "02:fb:00:00:00:01"  # pn_oracle_pipe 기본 MAC (locally administered)


def dcp_set(pn, blocks, xid):
    """DCP Set.req (FrameID 0xFEFD). scapy ProfinetDCP 요청은 블록 1개만 만들 수 있어 사양대로 직접 인코딩한다.

    DCP 헤더: ServiceID(1)=4 ServiceType(1)=0 Xid(4) Reserved(2) DCPDataLength(2)
    Set 블록: Option(1) Suboption(1) DCPBlockLength(2) BlockQualifier(2)=1 값, 홀수면 패딩 1 (DCPDataLength 에만 포함)
    반환: 같은 Xid 의 Set.res DCP PDU (FrameID 뒤), 없으면 None.
    """
    body = b""
    for opt, sub, value in blocks:
        blk = struct.pack(">BBHH", opt, sub, 2 + len(value), 0x0001) + value
        body += blk + (b"\x00" if len(blk) % 2 else b"")
    dcp = struct.pack(">BBIHH", 0x04, 0x00, xid, 0, len(body)) + body
    frame = (Ether(dst=DEVICE_MAC, src=CONTROLLER_MAC, type=0x8892)
             / ProfinetIO(frameID=0xFEFD) / dcp)
    for f in tx_frames(pn.eth(raw(frame))):
        if f.haslayer(ProfinetIO) and f[ProfinetIO].frameID == 0xFEFD:
            p = raw(f[ProfinetIO])[2:]
            if p[0] == 0x04 and struct.unpack(">I", p[2:6])[0] == xid:
                return p
    return None


def dcp_set_results(p):
    """Set.res → (ServiceType, {(Option, Suboption): BlockError}). Control/Response 블록 (5, 4) 만 모은다."""
    dlen = struct.unpack(">H", p[8:10])[0]
    blocks = p[10:10 + dlen]
    out = {}
    off = 0
    while off + 4 <= len(blocks):
        opt, sub, blen = struct.unpack(">BBH", blocks[off:off + 4])
        data = blocks[off + 4:off + 4 + blen]
        if (opt, sub) == (0x05, 0x04) and blen >= 3:
            out[(data[0], data[1])] = data[2]
        off += 4 + blen + (blen & 1)
    return p[1], out


NAME_BLOCK = (0x02, 0x02, b"oracle-set")
IP_BLOCK = (0x01, 0x02, bytes([192, 168, 0, 60, 255, 255, 255, 0, 192, 168, 0, 1]))


@known_defect("T12-16", "Set.req 블록이 여러 개여도 Control/Response 블록을 하나만 돌려준다. 사양: 블록마다 하나")
def test_dcp_set_answers_every_block(pn_dut):
    p = dcp_set(pn_dut, [NAME_BLOCK, IP_BLOCK], xid=0x5101)
    assert p is not None, "Set.res 없음"
    stype, res = dcp_set_results(p)
    assert stype == 0x01, f"ServiceType {stype}"
    assert res == {(0x02, 0x02): 0x00, (0x01, 0x02): 0x00}, f"응답 블록 {res}"


@known_defect("T12-16", "설정할 수 없는 블록(DeviceVendor 2/1, 읽기 전용)에도 성공을 답한다. "
              "사양: 그 블록의 BlockError 가 0 이 아니어야 한다")
def test_dcp_set_read_only_block_reports_error(pn_dut):
    p = dcp_set(pn_dut, [(0x02, 0x01, b"OtherVendor")], xid=0x5102)
    assert p is not None, "Set.res 없음"
    _, res = dcp_set_results(p)
    assert (0x02, 0x01) in res, f"DeviceVendor 에 대한 응답 블록 없음 {res}"
    assert res[(0x02, 0x01)] != 0x00


@known_defect("T12-16", "AR 이 있는 동안에도 NameOfStation Set 을 받아들인다. "
              "사양: BlockError 0x06 (In operation, SET not possible)")
def test_dcp_set_name_rejected_during_ar(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    p = dcp_set(pn_dut, [NAME_BLOCK], xid=0x5103)
    assert p is not None, "Set.res 없음"
    _, res = dcp_set_results(p)
    assert res.get((0x02, 0x02)) == 0x06, f"응답 블록 {res}"


# ---------------------------------------------------------------- DCP Get (A20261003-2)
def dcp_get(pn, selectors, xid):
    """DCP Get.req (FrameID 0xFEFD) → 같은 Xid 의 Get.res 를 scapy ProfinetDCP 로 해석해 돌려준다. 없으면 None.

    Get.req 블록은 길이 필드 없이 Option(1) Suboption(1) 쌍의 목록이다 (Wireshark packet-pn-dcp.c
    dissect_PNDCP_PDU: Get+Request 이면 블록 대신 "Selectors" 로 dissect_PNDCP_Option 만 읽는다).
    scapy ProfinetDCP 요청은 DCPBlockLength 를 붙이므로 사양대로 직접 인코딩한다.
    DCP 헤더: ServiceID(1)=3 ServiceType(1)=0 Xid(4) Reserved(2) DCPDataLength(2).
    Get.res 는 Identify.res 와 같은 DCP 블록 형식이라 scapy dcp_blocks 로 읽는다.
    """
    body = b"".join(struct.pack(">BB", opt, sub) for opt, sub in selectors)
    dcp = struct.pack(">BBIHH", 0x03, 0x00, xid, 0, len(body)) + body
    frame = (Ether(dst=DEVICE_MAC, src=CONTROLLER_MAC, type=0x8892)
             / ProfinetIO(frameID=0xFEFD) / dcp)
    for f in tx_frames(pn.eth(raw(frame))):
        if f.haslayer(ProfinetDCP) and f[ProfinetIO].frameID == 0xFEFD:
            d = f[ProfinetDCP]
            if d.service_id == 0x03 and d.xid == xid:
                return d
    return None


def dcp_block_ids(d):
    return [(b.option, b.sub_option) for b in d.dcp_blocks]


@known_defect("A20261003-2", "Get.req 가 무엇을 요청하든 Identify 와 같은 블록 7개 전체를 돌려준다. "
              "사양: Get.res 는 요청한 Option/Suboption 의 블록만 담는다")
def test_dcp_get_returns_only_requested_blocks(pn_dut):
    # IEC 61158-6-10 DCP Get: 요청한 GetReqBlock(Option, Suboption) 마다 응답 블록 하나.
    # 독립 구현 p-net pf_dcp.c 도 요청 쌍마다 pf_dcp_get_req 를 한 번씩 불러 그 블록만 넣는다.
    cases = [
        ([(0x02, 0x02)], 0x6001),                # NameOfStation 만
        ([(0x01, 0x02)], 0x6002),                # IP Parameter 만
        ([(0x02, 0x02), (0x01, 0x02)], 0x6003),  # 둘
    ]
    for sel, xid in cases:
        d = dcp_get(pn_dut, sel, xid)
        assert d is not None, f"Get.res 없음 (요청 {sel})"
        assert d.service_type == 0x01, f"ServiceType {d.service_type} (요청 {sel})"
        got = dcp_block_ids(d)
        assert sorted(got) == sorted(sel), f"요청 {sel} 에 응답 블록 {got}"
    d = dcp_get(pn_dut, [(0x02, 0x02)], 0x6004)
    assert bytes(d.dcp_blocks[0].name_of_station) == b"oracle-dut"


@known_defect("A20261003-2", "지원하지 않는 옵션(0x04 reserved)을 Get 해도 Identify 블록 전체를 성공으로 돌려준다. "
              "사양: 그 옵션에 대한 Control/Response(5/4) 블록 하나, BlockError 0x01 Option unsupp.(또는 0x02)")
def test_dcp_get_unsupported_option_reports_block_error(pn_dut):
    # GetNegResBlock = Option Control(0x05), Suboption Response(0x04), DCPBlockLength=3,
    #   ResponseStatus = 요청 Option(1) Suboption(1) BlockError(1) — 블록 앞 BlockInfo 없음.
    # 근거: Wireshark packet-pn-dcp.c dissect_PNDCP_Suboption_Control (PNDCP_SUBOPTION_CONTROL_RESPONSE,
    #   hf_pn_dcp_block_error, pn_dcp_block_error 0x01 "Option unsupp." 0x02 "Suboption unsupp. ..."),
    #   scapy DCPControlBlock (response, response_sub_option, block_error), p-net pf_dcp_get_req 의 GetNegResBlock.
    # 서비스 자체(Get)는 지원하므로 ServiceType 은 Success(1) 이다 (5 는 ServiceID not supported).
    d = dcp_get(pn_dut, [(0x04, 0x01)], 0x6011)
    assert d is not None, "Get.res 없음"
    assert d.service_type == 0x01, f"ServiceType {d.service_type}"
    got = dcp_block_ids(d)
    assert got == [(0x05, 0x04)], f"응답 블록 {got} (Control/Response 하나 기대)"
    blk = d.dcp_blocks[0]
    assert (blk.response, blk.response_sub_option) == (0x04, 0x01), \
        f"ResponseStatus 옵션 {(blk.response, blk.response_sub_option)}"
    assert blk.block_error in (0x01, 0x02), f"BlockError {blk.block_error}"


# ---------------------------------------------------------------- Release (T12-17)
@known_defect("T12-17", "표준 Release(블록 0x0114) 의 ARUUID 를 찾지 못해 거부한다. 응답이 없고 AR·RTC1 이 유지된다. "
              "사양: 0x8114 ControlCommand Done 응답 후 AR 해제")
def test_release_standard_block(pn_dut):
    assert rtc1_frames(pn_dut, poll_ms=40), "AR 수립 후 RTC1 프레임 없음"
    rel = IODControlReq(ARUUID=AR_UUID, SessionKey=SESSION_KEY, ControlCommand_Release=1)
    assert raw(rel)[:2] == b"\x01\x14"  # scapy 가 ReleaseBlockReq 0x0114 로 만든다
    rsp = rpc_response(pn_dut.rpc(raw(pnio_request(1, [rel], seqnum=40))))
    assert rsp is not None, "Release 응답 없음"
    _, blocks = ndr_response(rsp)
    res = IODControlRes(blocks)
    assert res.block_type == 0x8114, f"블록 0x{res.block_type:04x}"
    assert str(res.ARUUID) == AR_UUID and res.SessionKey == SESSION_KEY
    assert raw(res)[28:30] == b"\x00\x08", f"ControlCommand {raw(res)[28:30].hex()} (Done 0x0008 기대)"
    out = pn_dut.cmd("POLL 60")
    assert not [f for f in tx_frames(out) if is_rtc1(f)], "Release 뒤에도 RTC1 을 보낸다"


# ---------------------------------------------------------------- 미지원 레코드 index (T12-18)
UNSUPPORTED_INDEX = 0x7777  # GSDML 의 slot 1 파라미터 레코드는 index 1 뿐


@known_defect("T12-18", "미지원 index Read 에 4바이트 0 을 정상 데이터로 돌려준다. "
              "사양: PNIOStatus DE 80 B0 00 (IODReadRes, PNIORW, invalid index). 선행: T12-1")
def test_record_read_unsupported_index_error(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    req = IODReadReq(seqNum=1, ARUUID=AR_UUID, API=0, slotNumber=1, subslotNumber=1,
                     index=UNSUPPORTED_INDEX, recordDataLength=4096)
    rsp = rpc_response(pn_dut.rpc(raw(pnio_request(2, [req], seqnum=50))))
    assert rsp is not None, "Read 응답 없음"
    status, _ = ndr_response(rsp)
    assert status == 0xDE80B000, f"PNIOStatus {status:08x}"


@known_defect("T12-18", "미지원 index Write 를 성공으로 처리한다. "
              "사양: PNIOStatus DF 80 B0 00 (IODWriteRes, PNIORW, invalid index). 선행: T12-1")
def test_record_write_unsupported_index_error(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    data = b"\x01\x02\x03\x04"
    req = IODWriteReq(seqNum=1, ARUUID=AR_UUID, API=0, slotNumber=1, subslotNumber=1,
                      index=UNSUPPORTED_INDEX, recordDataLength=len(data)) / data
    rsp = rpc_response(pn_dut.rpc(raw(pnio_request(3, [req], seqnum=51))))
    assert rsp is not None, "Write 응답 없음"
    status, _ = ndr_response(rsp)
    assert status == 0xDF80B000, f"PNIOStatus {status:08x}"


# ---------------------------------------------------------------- SNMP (T12-19)
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"


def snmp_get(pn, oid, req_id):
    """SNMPv1 GetRequest (scapy SNMP) 를 UDP 161 페이로드로 넣고 GetResponse PDU 를 scapy 로 해석한다."""
    req = SNMP(version=0, community=b"public",
               PDU=SNMPget(id=req_id, varbindlist=[SNMPvarbind(oid=oid)]))
    b = raw_rsp(pn.cmd("SNMP " + raw(req).hex()))
    assert b is not None, "SNMP 응답 없음"
    rsp = SNMP(b)
    assert isinstance(rsp.PDU, SNMPresponse), f"PDU {type(rsp.PDU).__name__}"
    return rsp.PDU


@known_defect("T12-19", "request-id 를 요청에서 복사하지 않고 항상 1 로 응답한다")
def test_snmp_request_id_echo(pn_dut):
    pdu = snmp_get(pn_dut, SYS_NAME, req_id=0x1234)
    assert pdu.id.val == 0x1234, f"request-id {pdu.id.val}"


@known_defect("T12-19", "요청 OID 와 관계없이 sysName.0 을 돌려준다. 사양: 요청한 OID 의 varbind (없으면 noSuchName)")
def test_snmp_answers_requested_oid(pn_dut):
    pdu = snmp_get(pn_dut, SYS_DESCR, req_id=1)
    oids = [vb.oid.val for vb in pdu.varbindlist]
    assert oids == [SYS_DESCR], f"varbind OID {oids}"


# ---------------------------------------------------------------- 예제 config ↔ GSDML (T12-21)
GSDML_TYPE_SIZE = {"Unsigned8": 1, "Integer8": 1, "Unsigned16": 2, "Integer16": 2, "Unsigned32": 4,
                   "Integer32": 4, "Float32": 4, "Unsigned64": 8, "Integer64": 8, "Float64": 8}


def gsdml_item_len(d):
    """DataItem 바이트 수: Length 속성 (OctetString 등), 없으면 DataType 의 고정 크기."""
    return int(d.get("Length") or GSDML_TYPE_SIZE[d.get("DataType")])


def gsdml_io_lengths():
    """GSDML IO 서브모듈마다 (입력 바이트, 출력 바이트)."""
    out = set()
    for sub in gsdml_root().findall(".//{*}VirtualSubmoduleItem"):
        io = sub.find("{*}IOData")
        if io is None:
            continue
        n_in = sum(gsdml_item_len(d) for d in io.findall("{*}Input/{*}DataItem"))
        n_out = sum(gsdml_item_len(d) for d in io.findall("{*}Output/{*}DataItem"))
        if n_in or n_out:
            out.add((n_in, n_out))
    return out


@known_defect("T12-21", "CODESYS·fake-sensor 예제 config 는 input_len 40 인데 GSDML IO 서브모듈 입력은 32바이트다")
def test_example_configs_match_gsdml_io_length():
    lengths = gsdml_io_lengths()
    assert lengths, "GSDML 에 IO 서브모듈이 없다"
    bad = {}
    for path in sorted((REPO / "config").glob("example*profinet*.json")):
        params = json.loads(path.read_text())["protocol_params"]
        pair = (params.get("input_len"), params.get("output_len"))
        if pair not in lengths:
            bad[path.name] = pair
    assert not bad, f"GSDML IO 길이 {sorted(lengths)} 와 다른 config: {bad}"


# ---------------------------------------------------------------- 어댑터 수준 (T12-9, T2)
# pn_oracle_app: fb_api 로 config 를 열고, 어댑터가 만든 스택에 mock Ethernet 을 붙인 DUT.
# cJSON 이 필요해 BUILD_DAEMON=ON 빌드에만 있다. 없으면 dut_path 가 실행 전체를 멈춘다.
class PnApp(PnPipe):
    def __init__(self, config_path):
        exe = dut_path("pn_oracle_app")
        self.proc = subprocess.Popen([str(exe), str(config_path)], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
        self.startup = self._read_until_end()

    def opened(self):
        return not [x for tag, x in self.startup if tag == "ERR"]


@pytest.fixture
def pn_app(tmp_path):
    apps = []

    def start(protocol_params, points=()):
        cfg = {"protocol": "profinet", "device": {"name": "oracle-app", "role": "server"},
               "cycle_ms": 8, "protocol_params": protocol_params, "points": list(points)}
        path = tmp_path / f"pn_app_{len(apps)}.json"
        path.write_text(json.dumps(cfg))
        app = PnApp(path)
        apps.append(app)
        return app

    yield start
    for a in apps:
        a.close()


APP_BASE_PARAMS = {"iface": "mock", "device_name": "oracle-dut", "vendor_id": 0xABCD, "device_id": 1,
                   "ip": "192.168.0.50", "netmask": "255.255.255.0", "input_len": 32, "output_len": 32,
                   "cycle_us": 8000}


def test_adapter_default_config_accepts_standard_connect(pn_app):
    app = pn_app(dict(APP_BASE_PARAMS))  # security_class / psk_hex 없음
    assert app.opened(), f"기본 config 로 fb_open 실패: {app.startup}"
    frames = rtc1_frames(app, poll_ms=60)
    assert frames, "보안 블록 없는 표준 Connect 뒤에 RTC1 이 없다 (Connect 거부)"


# T2 (PN): 공학값 ↔ 원시값 (T0 A안: 어댑터가 scale/offset 적용). uint16, scale 0.1, byte_offset 0.
# 입력 IOCR 에서 IO 서브모듈 (1,1) 데이터를 FrameOffset 0 에 두어, 고정 배치(현재)와 IOCR 배치(T12-4 수정 후)
# 어느 쪽이든 C_SDU[0:2] 가 이 포인트다.
T2_LAYOUT = (
    [(1, 1, 0), (0, 1, 33), (0, 0x8000, 34), (0, 0x8001, 35)],  # (1,1) 데이터 @0..31 IOPS @32, DAP·IF·포트 IOPS
    [(1, 1, 36)],                                                # 출력 서브모듈 (1,1) 의 IOCS
    OUT_LAYOUT_DATA,
    OUT_LAYOUT_IOCS,
)
T2_POINT = {"name": "level", "access": "read", "data_type": "uint16", "length": 2, "scale": 0.1,
            "address": {"profinet": {"slot": 1, "subslot": 1, "index": 1, "byte_offset": 0, "length": 2}}}


def t2_app(pn_app):
    # security_class 0 을 명시한다 (T12-9 와 섞이지 않게).
    app = pn_app(dict(APP_BASE_PARAMS, security_class=0), [T2_POINT])
    assert app.opened(), f"fb_open 실패: {app.startup}"
    errs = [x for tag, x in app.cmd("WU32 level 300") if tag == "ERR"]
    assert not errs, f"fb_write_u32 실패 {errs}"
    return app


def test_adapter_scaled_point_rtc1_bytes(pn_app):
    app = t2_app(pn_app)
    frames = rtc1_frames(app, poll_ms=60, layout=T2_LAYOUT)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    assert c_sdu(frames[-1])[0:2] == b"\x0b\xb8", f"IO 데이터 {c_sdu(frames[-1])[0:2].hex()}"


def test_adapter_scaled_point_read_roundtrip(pn_app):
    app = t2_app(pn_app)
    vals = [x for tag, x in app.cmd("RF32 level") if tag == "F32"]
    assert vals, "fb_read_f32 실패"
    v = struct.unpack(">f", vals[0])[0]
    assert abs(v - 300.0) < 1e-3, f"읽은 값 {v}"
