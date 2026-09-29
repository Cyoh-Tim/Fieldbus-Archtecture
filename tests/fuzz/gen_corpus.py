#!/usr/bin/env python3
"""Write small libFuzzer seed corpora (valid-ish PDUs)."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent / "corpus"


def w(subdir: str, name: str, data: bytes) -> None:
    d = ROOT / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(data)


def le16(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF))


def le24(v: int) -> bytes:
    return bytes((v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF))


def be16(v: int) -> bytes:
    return bytes(((v >> 8) & 0xFF, v & 0xFF))


def mbap(tid: int, unit: int, pdu: bytes, proto: int = 0) -> bytes:
    return be16(tid) + be16(proto) + be16(1 + len(pdu)) + bytes([unit]) + pdu


def main() -> None:
    # Modbus TCP FC03
    mb = be16(1) + be16(0) + be16(6) + bytes([1, 3]) + be16(0) + be16(2)
    w("mb_adu", "fc03.bin", mb)
    w("mb_adu", "short.bin", b"\x00\x01")
    mb_w = be16(2) + be16(0) + be16(9) + bytes([1, 16]) + be16(0) + be16(1) + bytes([2, 0x12, 0x34])
    w("mb_adu", "fc16.bin", mb_w)
    # Stateful harness: byte0 = mode (see fuzz_mb_adu.c).
    w("mb_adu", "mode0_raw_fc03.bin", bytes([0]) + mb)
    w("mb_adu", "mode1_fc01.bin", bytes([1, 0]) + bytes(8))
    w("mb_adu", "mode1_fc0f.bin", bytes([1, 6]) + bytes(8))
    w("mb_adu", "mode2_mask.bin", bytes([2, 0, 0, 0, 0xFF, 0xFF, 0, 1]))
    w("mb_adu", "mode2_rw.bin", bytes([2, 1, 0, 2, 0, 8, 0, 1, 2, 0xAA, 0xBB]))
    w("mb_adu", "mode3_diag.bin", bytes([3, 1]))  # FC 0x08 illegal function
    w("mb_adu", "mode3_mei.bin", bytes([3, 4]))  # FC 0x2B
    w("mb_adu", "mode4_qty0.bin", bytes([4, 0]))
    w("mb_adu", "mode4_oob.bin", bytes([4, 2]))
    w("mb_adu", "mode4_badcoil.bin", bytes([4, 3]))
    w("mb_adu", "mode5_unit2.bin", bytes([5, 0]))
    w("mb_adu", "mode5_unit0.bin", bytes([5, 1]))
    w("mb_adu", "mode5_proto.bin", bytes([5, 2]))
    w("mb_adu", "mode6_seq.bin", bytes([6, 0, 0, 0x12, 0x34]))
    fc01 = mbap(1, 1, bytes([1]) + be16(0) + be16(8))
    fc03 = mbap(2, 1, bytes([3]) + be16(0) + be16(2))
    fc17 = mbap(3, 1, bytes([0x17]) + be16(0) + be16(2) + be16(4) + be16(1) + bytes([2, 0x00, 0x01]))
    w("mb_adu", "mode7_multi.bin", bytes([7]) + fc01 + fc03 + fc17)
    w("mb_adu", "mode0_multi_raw.bin", bytes([0]) + fc03 + mbap(9, 1, bytes([6]) + be16(1) + be16(0xABCD)))

    # SLMP Binary 3E batch read D100 qty=2
    slmp = bytearray()
    slmp += le16(0x0050)
    slmp += bytes([0, 0xFF]) + le16(0x03FF) + bytes([0])
    slmp += le16(12) + le16(0x0010) + le16(0x0401) + le16(0) + le24(100) + bytes([0xA8]) + le16(2)
    w("slmp_request", "batch_read.bin", bytes(slmp))
    slmp_w = bytearray(slmp)
    slmp_w[11] = 0x14  # cmd 0x1401 LE at offset 11
    slmp_w[12] = 0x01
    slmp_w += bytes([0x34, 0x12, 0xCD, 0xAB])
    # fix data length
    slmp_w[7] = 16
    slmp_w[8] = 0
    w("slmp_request", "batch_write.bin", bytes(slmp_w))
    w("slmp_request", "qty_over.bin", bytes(slmp[:19]) + le16(1013))
    w("slmp_request", "short.bin", b"\x50\x00")
    # Stateful harness: byte0 = mode (see fuzz_slmp_request.c).
    w("slmp_request", "mode0_raw.bin", bytes([0]) + bytes(slmp))
    w("slmp_request", "mode1_d.bin", bytes([1, 0, 0, 0, 2, 0]))
    w("slmp_request", "mode1_zr.bin", bytes([1, 3]))  # ZR
    w("slmp_request", "mode2_write.bin", bytes([2, 0]) + bytes([0x11, 0x22, 0x33, 0x44]))
    w("slmp_request", "mode3_bit_read.bin", bytes([3, 0, 0, 8]))
    w("slmp_request", "mode3_bit_write.bin", bytes([3, 1, 0, 8, 0xFF, 0x00]))
    w("slmp_request", "mode4_random.bin", bytes([4, 0]))
    w("slmp_request", "mode4_monitor.bin", bytes([4, 2]))
    w("slmp_request", "mode5_baddev.bin", bytes([5, 1]))
    w("slmp_request", "mode5_badsub.bin", bytes([5, 0]))
    w("slmp_request", "mode6_qty0.bin", bytes([6, 0]))
    w("slmp_request", "mode6_qty961.bin", bytes([6, 1]))
    w("slmp_request", "mode7_seq.bin", bytes([7, 0, 10, 0, 2, 0]))

    # EIP RegisterSession
    enc = bytearray(24 + 4)
    enc[0] = 0x65
    enc[2] = 4
    enc[24] = 1
    w("eip_encap", "register.bin", bytes(enc))
    # NOP
    nop = bytearray(24)
    w("eip_encap", "nop.bin", bytes(nop))
    # SendRRData empty CIP item
    srr = bytearray(24)
    srr[0] = 0x6F
    body = bytearray()
    body += bytes(4) + le16(0) + le16(2)
    body += le16(0) + le16(0)  # null addr
    body += le16(0x00B2) + le16(0)  # unconnected len 0
    srr[2] = len(body) & 0xFF
    srr[3] = (len(body) >> 8) & 0xFF
    w("eip_encap", "sendrr_empty_cip.bin", bytes(srr) + bytes(body))
    w("eip_encap", "short.bin", b"\x6f\x00")
    # Stateful harness: byte0 = mode (see fuzz_eip_encap.c).
    w("eip_encap", "mode0_raw_reg.bin", bytes([0]) + bytes(enc))
    w("eip_encap", "mode1_id.bin", bytes([1, 0, 0]))  # Identity GetAttr
    w("eip_encap", "mode1_asm.bin", bytes([1, 2, 0]))
    w("eip_encap", "mode1_tcpip.bin", bytes([1, 3, 0]))
    w("eip_encap", "mode1_qos.bin", bytes([1, 5, 0]))
    w("eip_encap", "mode1_secobj.bin", bytes([1, 7, 0]))
    w("eip_encap", "mode1_lldp.bin", bytes([1, 8, 0]))
    w("eip_encap", "mode2_getattrall.bin", bytes([2, 0]))
    w("eip_encap", "mode2_reset.bin", bytes([2, 1, 0]))
    w("eip_encap", "mode2_unconnected.bin", bytes([2, 2]))
    w("eip_encap", "mode3_set_prot.bin", bytes([3, 0]))
    w("eip_encap", "mode3_set_asm.bin", bytes([3, 1, 0x5A, 0x5A]))
    w("eip_encap", "mode3_set_qos.bin", bytes([3, 2, 0x1B]))
    w("eip_encap", "mode4_fo.bin", bytes([4, 0]))
    w("eip_encap", "mode4_large_close.bin", bytes([4, 0xFF]))
    w("eip_encap", "mode5_listid.bin", bytes([5, 0]))
    w("eip_encap", "mode5_listsvc.bin", bytes([5, 1]))
    w("eip_encap", "mode5_listif.bin", bytes([5, 2]))
    w("eip_encap", "mode6_unreg.bin", bytes([6, 1]))
    w("eip_encap", "mode6_unitdata.bin", bytes([6, 0]))
    w("eip_encap", "mode7_sec.bin", bytes([7, 0]))

    # EIP IO two items (raw CPF, harness mode 2)
    io = le16(2)
    io += le16(0x8002) + le16(8) + bytes(8)
    io += le16(0x00B1) + le16(4) + bytes(4)
    w("eip_io", "seq_data.bin", io)
    w("eip_io", "short.bin", b"\x02\x00")
    # Stateful harness: byte0 = mode. Mode 0 stitches live O->T conn id.
    cpf = le16(2)
    cpf += le16(0x8002) + le16(8) + bytes(4) + le16(1) + le16(0)
    cpf += le16(0x00B1) + le16(10) + le16(1) + bytes([0x5A] * 8)
    w("eip_io", "mode0_stitch.bin", bytes([0]) + cpf)
    w("eip_io", "mode1_wrap.bin", bytes([1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]))
    w("eip_io", "mode4_close.bin", bytes([4]))
    w("eip_io", "mode5_poll.bin", bytes([5]))
    w("eip_io", "mode5_watchdog.bin", bytes([5, 0xFF]))
    w("eip_io", "mode7_large_fo.bin", bytes([7, 0xA5, 0x5A]))
    # Connected data with 4-byte header (seq + run/idle-ish) + 8-byte image
    ri = le16(2)
    ri += le16(0x8002) + le16(8) + bytes(8)
    ri += le16(0x00B1) + le16(12) + bytes([1, 0, 1, 0]) + bytes([0x5A] * 8)
    w("eip_io", "mode0_runidle.bin", bytes([0]) + ri)

    # PN eth DCP Identify All + name filter + Set
    eth = bytes([0x01, 0x0E, 0xCF, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x88, 0x92])
    ident = bytes([0xFE, 0xFE, 0x05, 0x00]) + bytes(4) + bytes([0, 0, 0, 4, 0xFF, 0xFF, 0, 0])
    w("pn_eth", "dcp_id.bin", eth + ident)
    nam = bytes([0xFE, 0xFE, 0x05, 0x00]) + bytes(4) + bytes([0, 0, 0, 8, 0x02, 0x02, 0, 4]) + b"fuzz"
    w("pn_eth", "dcp_id_name.bin", eth + nam)
    setp = bytes([0xFE, 0xFD, 0x04, 0x00]) + bytes(4) + bytes([0, 0, 0, 12, 0x02, 0x02, 0, 8, 0, 1]) + b"bad-name"
    w("pn_eth", "dcp_set_name.bin", eth[:6] + bytes([0x02, 0xFB, 0, 0, 0, 1]) + eth[12:] + setp)
    w("pn_eth", "short.bin", b"\x00" * 10)

    # PN RPC header only
    rpc = bytearray(80)
    rpc[0] = 1
    rpc[1] = 0
    w("pn_rpc", "hdr.bin", bytes(rpc))
    w("pn_rpc", "short.bin", b"\x01\x00")
    print("wrote", ROOT)


if __name__ == "__main__":
    main()
