"""PROFINET IO Device — 오라클: scapy (contrib.pnio, pnio_dcp, pnio_rpc, dcerpc, lldp).

scapy 의 PROFINET 모듈은 Wireshark 디섹터와 같은 사양 필드 정의를 따르는 독립 구현체다.
요청은 scapy 로 만들고, 스택의 응답도 scapy 로 해석해서 사양 형태로 읽히는지 본다.
DUT 는 pn_oracle_pipe (mock Ethernet, 스테이션 이름 "oracle-dut", vendor 0xABCD, device 0x0001).
"""
import uuid

import pytest
from scapy.all import Ether, raw
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
    IOCRBlockReq,
    PNIOServiceReqPDU,
    PNIOServiceResPDU,
)
from scapy.layers.dcerpc import DceRpc4

from conftest import known_defect

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


def connect_pdu(station=b"controller"):
    """사양 형태의 Connect.req (ARBlockReq + 입력/출력 IOCR + AlarmCR + ExpectedSubmodule)."""
    in_iocr = IOCRBlockReq(
        IOCRType=1, IOCRReference=1, LT=0x8892, IOCRProperties_RTClass=2,
        DataLength=40, FrameID=0x8001, SendClockFactor=32, ReductionRatio=256,
        Phase=1, WatchdogFactor=3, DataHoldFactor=3, IOCRTagHeader_IOUserPriority=6,
        IOCRMulticastMACAdd="01:0e:cf:00:00:00",
        APIs=[IOCRAPI(API=0,
                      IODataObjects=[IOCRAPIObject(SlotNumber=0, SubslotNumber=1, FrameOffset=0),
                                     IOCRAPIObject(SlotNumber=1, SubslotNumber=1, FrameOffset=1)],
                      IOCSs=[IOCRAPIObject(SlotNumber=1, SubslotNumber=1, FrameOffset=33)])])
    out_iocr = IOCRBlockReq(
        IOCRType=2, IOCRReference=2, LT=0x8892, IOCRProperties_RTClass=2,
        DataLength=40, FrameID=0x8000, SendClockFactor=32, ReductionRatio=256,
        Phase=1, WatchdogFactor=3, DataHoldFactor=3, IOCRTagHeader_IOUserPriority=6,
        IOCRMulticastMACAdd="01:0e:cf:00:00:00",
        APIs=[IOCRAPI(API=0,
                      IODataObjects=[IOCRAPIObject(SlotNumber=1, SubslotNumber=1, FrameOffset=0)],
                      IOCSs=[IOCRAPIObject(SlotNumber=0, SubslotNumber=1, FrameOffset=33),
                             IOCRAPIObject(SlotNumber=1, SubslotNumber=1, FrameOffset=34)])])
    ar = ARBlockReq(ARType=1, ARUUID=AR_UUID, SessionKey=1,
                    CMInitiatorMacAdd=CONTROLLER_MAC,
                    CMInitiatorObjectUUID="dea00000-6c97-11d1-8271-00640001abcd",
                    ARProperties_State=1, ARProperties_ParametrizationServer=0,
                    CMInitiatorActivityTimeoutFactor=600, CMInitiatorUDPRTPort=0x8892,
                    CMInitiatorStationName=station)
    alarm = AlarmCRBlockReq(AlarmCRType=1, LT=0x8892, RTATimeoutFactor=1, RTARetries=3,
                            LocalAlarmReference=1, MaxAlarmDataLength=200,
                            AlarmCRTagHeaderHigh=0xC000, AlarmCRTagHeaderLow=0xA000)
    exp = ExpectedSubmoduleBlockReq(APIs=[
        ExpectedSubmoduleAPI(API=0, SlotNumber=0, ModuleIdentNumber=0x00000001, Submodules=[
            ExpectedSubmodule(SubslotNumber=1, SubmoduleIdentNumber=0x00000001,
                              SubmoduleProperties_Type=0)]),
        ExpectedSubmoduleAPI(API=0, SlotNumber=1, ModuleIdentNumber=0x00000010, Submodules=[
            ExpectedSubmodule(SubslotNumber=1, SubmoduleIdentNumber=0x00000011,
                              SubmoduleProperties_Type=3,
                              DataDescription=[
                                  ExpectedSubmoduleDataDescription(DataDescription=1, SubmoduleDataLength=32, LengthIOCS=1, LengthIOPS=1),
                                  ExpectedSubmoduleDataDescription(DataDescription=2, SubmoduleDataLength=32, LengthIOCS=1, LengthIOPS=1)])]),
    ])
    rpc = DceRpc4(ptype="request", flags1=0x20, opnum=0, if_id=PNIO_DEVICE_IF,
                  object="dea00000-6c97-11d1-8271-0001abcd0001",
                  act_id=str(uuid.UUID(int=1)), seqnum=1)
    return rpc / PNIOServiceReqPDU(args_max=16384, blocks=[ar, in_iocr, out_iocr, alarm, exp])


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
def rtc1_frames(pn):
    pn.rpc(raw(connect_pdu()))
    out = pn.cmd("POLL 60")
    return [f for f in tx_frames(out)
            if f.type == 0x8892 and 0x8000 <= f[ProfinetIO].frameID <= 0xBFFF]


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
