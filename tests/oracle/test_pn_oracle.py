"""PROFINET IO Device — 오라클: scapy (contrib.pnio, pnio_dcp, pnio_rpc, dcerpc, lldp).

scapy 의 PROFINET 모듈은 Wireshark 디섹터와 같은 사양 필드 정의를 따르는 독립 구현체다.
요청은 scapy 로 만들고, 스택의 응답도 scapy 로 해석해서 사양 형태로 읽히는지 본다.
DUT 는 pn_oracle_pipe (mock Ethernet, 스테이션 이름 "oracle-dut", vendor 0xABCD, device 0x0001).
"""
import struct
import uuid
import xml.etree.ElementTree as ET

import pytest
from scapy.all import Dot1Q, Ether, raw
from scapy.contrib.lldp import LLDPDU, LLDPDUGenericOrganisationSpecific
from scapy.contrib.pnio import ProfinetIO
from scapy.contrib.pnio_dcp import DCPNameOfStationBlock, DCPDeviceRoleBlock, ProfinetDCP
from scapy.contrib.pnio_rpc import (
    AlarmCRBlockReq,
    ARBlockReq,
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
from scapy.layers.dcerpc import DceRpc4

from conftest import REPO, known_defect

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


def connect_pdu(station=b"controller", scf=32, rr=16, slot1_module=0x00000010):
    """사양 형태의 Connect.req (ARBlockReq + 입력/출력 IOCR + AlarmCR + ExpectedSubmodule).

    기본 주기는 SCF=32 × RR=16 × 31.25µs = 16ms (GSDML 이 허용해야 하는 값, 장치 최소 8ms 이상).
    """
    common = dict(LT=0x8892, IOCRProperties_RTClass=2, DataLength=C_SDU_LEN,
                  SendClockFactor=scf, ReductionRatio=rr, Phase=1, WatchdogFactor=3,
                  DataHoldFactor=3, IOCRTagHeader_IOUserPriority=6,
                  IOCRMulticastMACAdd="01:0e:cf:00:00:00")
    in_iocr = IOCRBlockReq(
        IOCRType=1, IOCRReference=1, FrameID=0x8001, **common,
        APIs=[IOCRAPI(API=0, IODataObjects=_iocr_objects(IN_LAYOUT_DATA),
                      IOCSs=_iocr_objects(IN_LAYOUT_IOCS))])
    out_iocr = IOCRBlockReq(
        IOCRType=2, IOCRReference=2, FrameID=0x8000, **common,
        APIs=[IOCRAPI(API=0, IODataObjects=_iocr_objects(OUT_LAYOUT_DATA),
                      IOCSs=_iocr_objects(OUT_LAYOUT_IOCS))])
    ar = ARBlockReq(ARType=1, ARUUID=AR_UUID, SessionKey=SESSION_KEY,
                    CMInitiatorMacAdd=CONTROLLER_MAC,
                    CMInitiatorObjectUUID=CM_INITIATOR_OBJECT_UUID,
                    ARProperties_State=1, ARProperties_ParametrizationServer=0,
                    CMInitiatorActivityTimeoutFactor=600, CMInitiatorUDPRTPort=0x8892,
                    CMInitiatorStationName=station)
    alarm = AlarmCRBlockReq(AlarmCRType=1, LT=0x8892, RTATimeoutFactor=1, RTARetries=3,
                            LocalAlarmReference=1, MaxAlarmDataLength=200,
                            AlarmCRTagHeaderHigh=0xC000, AlarmCRTagHeaderLow=0xA000)
    exp = ExpectedSubmoduleBlockReq(APIs=[
        ExpectedSubmoduleAPI(API=0, SlotNumber=0, ModuleIdentNumber=0x00000001, Submodules=[
            ExpectedSubmodule(SubslotNumber=1, SubmoduleIdentNumber=0x00000001,
                              SubmoduleProperties_Type=0),
            ExpectedSubmodule(SubslotNumber=0x8000, SubmoduleIdentNumber=0x00000002,
                              SubmoduleProperties_Type=0),
            ExpectedSubmodule(SubslotNumber=0x8001, SubmoduleIdentNumber=0x00000003,
                              SubmoduleProperties_Type=0)]),
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


@known_defect("T12-2", "DCP 응답 블록에 BlockInfo(2바이트)가 없어 NameOfStation 앞 2글자가 잘린다")
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


@known_defect("T12-1", "RPC 응답 NDR 첫 워드에 PNIOStatus 가 아니라 인자 길이를 쓴다")
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


@known_defect("T12-6", "DataStatus 를 0x25 로 보낸다 (ProviderState=Stop). 정상 운전값은 0x35")
def test_rtc1_data_status_run(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    tail = raw(frames[-1])[-4:]  # CycleCounter(2) DataStatus(1) TransferStatus(1)
    assert tail[2] == 0x35


@known_defect("T12-7", "C_SDU 최소 길이 패딩이 없어 프레임이 60바이트 미만이다")
def test_rtc1_minimum_frame_length(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames
    assert len(raw(frames[-1])) >= 60


@known_defect("T12-4", "IOCRBlockReq 의 FrameOffset 을 무시하고 입력 데이터를 C_SDU 0번부터 고정 배치한다")
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


@known_defect("T12-8", "RTC1 프레임에 802.1Q VLAN 태그(PCP 6, VID 0)가 없다")
def test_rtc1_vlan_priority_tag(pn_dut):
    frames = rtc1_frames(pn_dut)
    assert frames, "AR 수립 후 RTC1 프레임 없음"
    f = frames[-1]
    assert f.haslayer(Dot1Q), "VLAN 태그 없음"
    assert f[Dot1Q].prio == 6 and f[Dot1Q].vlan == 0
    assert f[Dot1Q].type == 0x8892


@known_defect("T12-15", "CycleCounter 가 프레임마다 +1 이다. 사양은 SendClockFactor × ReductionRatio 씩 증가")
def test_rtc1_cycle_counter_step(pn_dut):
    frames = rtc1_frames(pn_dut, poll_ms=80, scf=32, rr=16)
    assert len(frames) >= 2, "비교할 RTC1 프레임이 2개 미만"
    steps = {(cycle_counter(b) - cycle_counter(a)) & 0xFFFF for a, b in zip(frames, frames[1:])}
    assert steps == {32 * 16}


@known_defect("T4", "RT 송신 주기가 협상값(SCF×RR×31.25µs)이 아니라 config cycle_us(8ms) 이다")
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


@known_defect("T12-4", "Connect 응답에 ARServerBlock(0x8106)이 없다 (T12-1 전에는 NDR 해석부터 틀린다)")
def test_connect_response_has_ar_server_block(pn_dut):
    status, blocks = connect_blocks(pn_dut)
    assert status == 0
    servers = [b for t, b in blocks if t == 0x8106]
    assert len(servers) == 1, f"블록 타입 {[hex(t) for t, _ in blocks]}"
    # ARServerBlock: BlockHeader(6) StationNameLength(2) CMResponderStationName
    name_len = struct.unpack(">H", servers[0][6:8])[0]
    assert servers[0][8:8 + name_len] == b"oracle-dut"


@known_defect("T12-4", "ExpectedSubmodule 과 실제 모듈이 달라도 ModuleDiffBlock(0x8104)을 보내지 않는다")
def test_connect_response_module_diff_on_wrong_module(pn_dut):
    # GSDML 의 slot 1 모듈은 0x00000010. 없는 모듈 번호를 기대하면 ModuleDiffBlock 으로 알려야 한다.
    status, blocks = connect_blocks(pn_dut, slot1_module=0xDEADBEEF)
    assert status == 0
    assert 0x8104 in [t for t, _ in blocks], f"블록 타입 {[hex(t) for t, _ in blocks]}"


# ---------------------------------------------------------------- 최소 주기 (T5)
@known_defect("T5 (PN)", "장치 최소 주기(8ms)보다 짧은 4ms 협상을 받아들인다. "
              "사양: PNIOStatus DB 81 02 0E (IODConnectRes, PNIO, Faulty IOCRBlockReq, ReductionRatio)")
def test_connect_rejects_cycle_below_device_minimum(pn_dut):
    rsp = rpc_response(pn_dut.rpc(raw(connect_pdu(scf=32, rr=4))))
    assert rsp is not None, "Connect 응답 없음"
    status, _ = ndr_response(rsp)
    assert status == 0xDB81020E, f"PNIOStatus {status:08x}"
    out = pn_dut.cmd("POLL 50")
    assert not [f for f in tx_frames(out) if is_rtc1(f)], "거부한 Connect 뒤에 RTC1 을 보낸다"


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


@known_defect("T12-3", "Read 응답에 IODReadResHeader(0x8009)가 없고 I&M0 에 BlockHeader(0x0020)가 없다")
def test_record_read_im0(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    status, blocks = record_read(pn_dut, IM0_INDEX, seqnum=1)
    assert status == 0
    im0 = IM0Block(read_res_record(blocks))
    assert im0.block_type == 0x0020
    assert (im0.VendorIDHigh << 8 | im0.VendorIDLow) == 0xABCD


@known_defect("T12-3", "Write 데이터를 64바이트 IODWriteReqHeader 뒤가 아니라 헤더 안쪽에서 읽어 I&M1 을 0 으로 덮고, "
              "Write 응답에 IODWriteResHeader(0x8008)가 없다")
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


@known_defect("T12-5", "PrmEnd 응답이 블록 0x0111 + 커맨드 echo 다. 사양은 0x8110 + ControlCommand Done(0x0008)")
def test_prm_end_response_done(pn_dut):
    pn_dut.rpc(raw(connect_pdu()))
    status, blocks = prm_end(pn_dut)
    assert status == 0
    res = IODControlRes(blocks)
    assert res.block_type == 0x8110
    assert str(res.ARUUID) == AR_UUID and res.SessionKey == SESSION_KEY
    # BlockHeader(6) Padding(2) ARUUID(16) SessionKey(2) AlarmSequenceNumber(2) ControlCommand(2)
    assert raw(res)[28:30] == b"\x00\x08", f"ControlCommand {raw(res)[28:30].hex()} (Done 0x0008 기대)"


@known_defect("T12-5", "ApplicationReady 요청이 rpc_vers=1, UUID 0, 블록 0x0110 이다. "
              "사양: rpc_vers=4, object=CMInitiatorObjectUUID, 인터페이스=PNIO Controller, 블록 0x0112")
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


@known_defect("T12-13", "GSDML 에 DAP VirtualSubmoduleItem, InterfaceSubmoduleItem(32768), "
              "PortSubmoduleItem(32769), TimingProperties, CertificationInfo 가 없다")
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


@known_defect("T5 (PN)", "GSDML MinDeviceInterval=32(1ms) 이 8ms 구현과 모순. 256(8ms) 이어야 하고 "
              "TimingProperties 는 SCF 32 × RR ≥ 8 만 광고해야 한다")
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
