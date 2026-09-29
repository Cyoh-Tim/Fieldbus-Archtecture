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


def main() -> None:
    # Modbus TCP FC03
    mb = be16(1) + be16(0) + be16(6) + bytes([1, 3]) + be16(0) + be16(2)
    w("mb_adu", "fc03.bin", mb)
    w("mb_adu", "short.bin", b"\x00\x01")
    mb_w = be16(2) + be16(0) + be16(9) + bytes([1, 16]) + be16(0) + be16(1) + bytes([2, 0x12, 0x34])
    w("mb_adu", "fc16.bin", mb_w)

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
