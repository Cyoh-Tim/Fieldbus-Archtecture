#!/usr/bin/env python3
"""In-repo software masters: cyclic IO against our device/server stacks.

Not CODESYS. Not PREEMPT_RT. Not PI / ODVA / Modbus.org / Mitsubishi
certification. Default path is live TCP (and EIP Class 1 UDP) loopback —
no CAP_NET_RAW, no privileged 502/5000/44818.

Protocols:
  modbus      TCP master FC03 + FC16 against our Modbus TCP server
  slmp        Binary 3E client batch read/write against our lab server
  ethernetip  Scanner-shaped: RegisterSession + Forward Open + Class 1 UDP
              (fallback: cyclic explicit Get_Attribute_Single of assembly 150)

PROFINET is intentionally absent as a live master (L2 / CAP_NET_RAW).

See docs/sw_master_io.md.
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

BANNER = (
    "software master soak (not CODESYS, not certification, no PREEMPT_RT)"
)

# CIP / EtherNet/IP
EIP_CMD_REGISTERSESSION = 0x0065
EIP_CMD_UNREGISTERSESSION = 0x0066
EIP_CMD_SENDRRDATA = 0x006F
EIP_ITEM_NULL_ADDR = 0x0000
EIP_ITEM_UNCONNECTED_DATA = 0x00B2
EIP_ITEM_SEQ_ADDR = 0x8002
EIP_ITEM_CONNECTED_DATA = 0x00B1
CIP_SVC_GET_ATTR_SINGLE = 0x0E
CIP_SVC_SET_ATTR_SINGLE = 0x10
CIP_SVC_FORWARD_OPEN = 0x54
CIP_SVC_FORWARD_CLOSE = 0x4E
CIP_SVC_REPLY = 0x80
CIP_CLASS_IDENTITY = 0x01
CIP_CLASS_ASSEMBLY = 0x04
CIP_CLASS_CONN_MANAGER = 0x06
CIP_STATUS_SUCCESS = 0x00

# SLMP Binary 3E
SLMP_SUBHEADER_REQ = 0x0050
SLMP_SUBHEADER_RES = 0x00D0
SLMP_CMD_BATCH_READ = 0x0401
SLMP_CMD_BATCH_WRITE = 0x1401
SLMP_SUB_WORD = 0x0000
SLMP_DEV_D = 0xA8
SLMP_END_OK = 0x0000


@dataclass
class Stats:
    ok: int = 0
    fail: int = 0
    cycles: int = 0
    warmup: int = 0
    t0: float = 0.0
    stamps: list[float] = field(default_factory=list)
    last_error: str = ""

    def mark_ok(self) -> None:
        self.ok += 1
        self.stamps.append(time.monotonic())

    def mark_fail(self, err: str) -> None:
        self.fail += 1
        self.last_error = err

    def period_stats_ms(self, nominal_ms: float) -> tuple[float, float, float]:
        """Return (avg_period_ms, jitter_max_ms, n_intervals)."""
        if len(self.stamps) < 2:
            return 0.0, 0.0, 0.0
        dts = [
            (self.stamps[i] - self.stamps[i - 1]) * 1000.0
            for i in range(1, len(self.stamps))
        ]
        avg = sum(dts) / len(dts)
        jitter = max(abs(dt - nominal_ms) for dt in dts)
        return avg, jitter, float(len(dts))


def be16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def le16(v: int) -> bytes:
    return struct.pack("<H", v & 0xFFFF)


def le32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def connect_tcp(host: str, port: int, timeout: float = 3.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    last: OSError | None = None
    while time.time() < end:
        try:
            s = connect_tcp(host, port, timeout=1.0)
            s.close()
            return
        except OSError as e:
            last = e
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not open ({last})")


def unpack_barcode_be_chars(raw: bytes) -> str:
    """High-byte-then-low-byte per 16-bit register/word (Modbus / SLMP map)."""
    chars: list[str] = []
    for i in range(0, len(raw), 2):
        chars.append(chr(raw[i]))
        if i + 1 < len(raw):
            chars.append(chr(raw[i + 1]))
    s = "".join(chars)
    return s.split("\x00", 1)[0].rstrip()


def slmp_words_le_to_be_chars(wire: bytes) -> bytes:
    """SLMP word payload is little-endian on the wire; map is high-byte first."""
    out = bytearray(len(wire))
    for i in range(0, len(wire) - 1, 2):
        lo, hi = wire[i], wire[i + 1]
        out[i] = hi
        out[i + 1] = lo
    return bytes(out)


def check_sensor_barcode_temp(
    barcode: str, temp_c: float, t0: float, wait_s: float
) -> str | None:
    """Return None if ok, 'warmup' if still empty, else an error string."""
    if not barcode.startswith("LOT-A-"):
        if time.monotonic() - t0 < wait_s and not barcode:
            return "warmup"
        return f"unexpected barcode {barcode!r}"
    if temp_c < 20.0 or temp_c > 40.0:
        return f"temperature out of fake-sensor range: {temp_c}"
    return None


def print_result(
    protocol: str,
    transport: str,
    stats: Stats,
    period_ms: float,
    extra: str = "",
) -> None:
    avg, jitter, nint = stats.period_stats_ms(period_ms)
    elapsed = time.monotonic() - stats.t0 if stats.t0 else 0.0
    line = (
        f"sw_master result protocol={protocol} transport={transport} "
        f"ok={stats.ok} fail={stats.fail} cycles={stats.cycles} "
        f"warmup={stats.warmup} period_ms={period_ms:.1f} "
        f"period_avg_ms={avg:.2f} jitter_max_ms={jitter:.2f} "
        f"intervals={int(nint)} elapsed_s={elapsed:.2f}"
    )
    if extra:
        line += f" {extra}"
    print(line, flush=True)


def run_until(
    args: argparse.Namespace,
    cycle_fn: Callable[[int], str | None],
    stats: Stats,
    on_fail: Callable[[Exception], None] | None = None,
) -> None:
    stats.t0 = time.monotonic()
    period = max(args.period_ms, 1) / 1000.0
    n = 0
    next_t = time.monotonic()
    while True:
        n += 1
        stats.cycles = n
        try:
            status = cycle_fn(n)
            if status == "warmup":
                stats.warmup += 1
                if not args.quiet:
                    print(f"cycle={n} warmup", flush=True)
            elif status:
                stats.mark_fail(status)
                print(f"FAIL cycle={n}: {status}", flush=True)
            else:
                stats.mark_ok()
        except (OSError, IOError, TimeoutError, struct.error, ValueError) as e:
            stats.mark_fail(str(e))
            print(f"FAIL cycle={n}: {e}", flush=True)
            if on_fail:
                on_fail(e)
        elapsed = time.monotonic() - stats.t0
        if args.seconds > 0:
            if elapsed >= args.seconds:
                break
        elif args.cycles > 0 and n >= args.cycles:
            break
        next_t += period
        delay = next_t - time.monotonic()
        if delay > 0:
            time.sleep(delay)
        else:
            next_t = time.monotonic()


# ---- Modbus TCP (live loopback) -------------------------------------------


def mb_txn(sock: socket.socket, unit: int, pdu: bytes, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    tid = int(time.time() * 1000) & 0xFFFF
    mbap = struct.pack(">HHHB", tid, 0, 1 + len(pdu), unit) + pdu
    sock.sendall(mbap)
    hdr = recvall(sock, 7)
    if len(hdr) < 7:
        raise IOError(f"short MBAP {hdr!r}")
    length = struct.unpack(">H", hdr[4:6])[0]
    if length < 1:
        raise IOError("bad MBAP length")
    body = recvall(sock, length - 1)
    if len(body) < length - 1:
        raise IOError("eof in PDU")
    return body


def mb_fc03(sock: socket.socket, unit: int, start: int, qty: int) -> bytes:
    pdu = bytes([0x03]) + be16(start) + be16(qty)
    body = mb_txn(sock, unit, pdu)
    if not body or body[0] != 0x03:
        raise IOError(f"FC03 exception/unexpected: {body!r}")
    n = body[1]
    return body[2 : 2 + n]


def mb_fc16(sock: socket.socket, unit: int, start: int, regs: list[int]) -> None:
    qty = len(regs)
    pdu = bytes([0x10]) + be16(start) + be16(qty) + bytes([qty * 2])
    for r in regs:
        pdu += be16(r)
    body = mb_txn(sock, unit, pdu)
    if not body or body[0] != 0x10:
        raise IOError(f"FC16 exception/unexpected: {body!r}")


def run_modbus(args: argparse.Namespace) -> int:
    wait_port(args.host, args.port, timeout=args.wait_s)
    sock = connect_tcp(args.host, args.port)
    stats = Stats()

    def reconnect(_e: Exception) -> None:
        nonlocal sock
        try:
            sock.close()
        except OSError:
            pass
        sock = connect_tcp(args.host, args.port)

    def cycle(n: int) -> str | None:
        data = mb_fc03(sock, args.unit, 0, 17)
        if len(data) < 34:
            return f"short holding payload {len(data)}"
        barcode = unpack_barcode_be_chars(data[0:32])
        temp_raw = struct.unpack(">H", data[32:34])[0]
        temp_c = temp_raw * 0.1
        err = check_sensor_barcode_temp(barcode, temp_c, stats.t0, args.wait_s)
        if err:
            return err
        mb_fc16(sock, args.unit, 20, [n & 0xFFFF])
        back = mb_fc03(sock, args.unit, 20, 1)
        got = struct.unpack(">H", back[:2])[0]
        if got != (n & 0xFFFF):
            return f"holding[20] writeback {got} != {n & 0xFFFF}"
        if not args.quiet:
            print(
                f"cycle={n} barcode={barcode!r} temperature={temp_c:.1f} "
                f"holding20={got}  [tcp_loopback]",
                flush=True,
            )
        return None

    try:
        run_until(args, cycle, stats, on_fail=reconnect)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print_result("modbus", "tcp_loopback", stats, float(args.period_ms))
    return 0 if stats.fail == 0 and stats.ok > 0 else 1


# ---- SLMP Binary 3E (live TCP loopback) -----------------------------------


def slmp_encode_batch_read(
    network: int,
    pc: int,
    dest_io: int,
    monitor: int,
    device: int,
    head: int,
    qty: int,
) -> bytes:
    data_len = 12
    hdr = bytearray(9)
    struct.pack_into("<H", hdr, 0, SLMP_SUBHEADER_REQ)
    hdr[2] = network & 0xFF
    hdr[3] = pc & 0xFF
    struct.pack_into("<H", hdr, 4, dest_io & 0xFFFF)
    hdr[6] = 0
    struct.pack_into("<H", hdr, 7, data_len)
    body = bytearray(12)
    struct.pack_into("<H", body, 0, monitor & 0xFFFF)
    struct.pack_into("<H", body, 2, SLMP_CMD_BATCH_READ)
    struct.pack_into("<H", body, 4, SLMP_SUB_WORD)
    body[6] = head & 0xFF
    body[7] = (head >> 8) & 0xFF
    body[8] = (head >> 16) & 0xFF
    body[9] = device & 0xFF
    struct.pack_into("<H", body, 10, qty & 0xFFFF)
    return bytes(hdr) + bytes(body)


def slmp_encode_batch_write(
    network: int,
    pc: int,
    dest_io: int,
    monitor: int,
    device: int,
    head: int,
    be_words: bytes,
) -> bytes:
    qty = len(be_words) // 2
    need = qty * 2
    data_len = 12 + need
    hdr = bytearray(9)
    struct.pack_into("<H", hdr, 0, SLMP_SUBHEADER_REQ)
    hdr[2] = network & 0xFF
    hdr[3] = pc & 0xFF
    struct.pack_into("<H", hdr, 4, dest_io & 0xFFFF)
    hdr[6] = 0
    struct.pack_into("<H", hdr, 7, data_len)
    body = bytearray(12 + need)
    struct.pack_into("<H", body, 0, monitor & 0xFFFF)
    struct.pack_into("<H", body, 2, SLMP_CMD_BATCH_WRITE)
    struct.pack_into("<H", body, 4, SLMP_SUB_WORD)
    body[6] = head & 0xFF
    body[7] = (head >> 8) & 0xFF
    body[8] = (head >> 16) & 0xFF
    body[9] = device & 0xFF
    struct.pack_into("<H", body, 10, qty & 0xFFFF)
    # Canonical BE map bytes → SLMP LE words on the wire.
    for i in range(qty):
        hi, lo = be_words[i * 2], be_words[i * 2 + 1]
        body[12 + i * 2] = lo
        body[12 + i * 2 + 1] = hi
    return bytes(hdr) + bytes(body)


def slmp_transact(sock: socket.socket, req: bytes, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    sock.sendall(req)
    hdr = recvall(sock, 9)
    if len(hdr) < 9:
        raise IOError(f"short SLMP header {hdr!r}")
    sub = struct.unpack_from("<H", hdr, 0)[0]
    if sub != SLMP_SUBHEADER_RES:
        raise IOError(f"not a 3E response subheader=0x{sub:04x}")
    length = struct.unpack_from("<H", hdr, 7)[0]
    rest = recvall(sock, length)
    if len(rest) < length:
        raise IOError("eof in SLMP response")
    return hdr + rest


def slmp_decode_resp(frame: bytes) -> tuple[int, bytes]:
    if len(frame) < 11:
        raise IOError("short SLMP response")
    resp_len = struct.unpack_from("<H", frame, 7)[0]
    end = struct.unpack_from("<H", frame, 9)[0]
    data = frame[11 : 9 + resp_len] if resp_len > 2 else b""
    return end, data


def run_slmp(args: argparse.Namespace) -> int:
    wait_port(args.host, args.slmp_port, timeout=args.wait_s)
    sock = connect_tcp(args.host, args.slmp_port)
    stats = Stats()
    net, pc, dest, mon = 0, 0xFF, 0x03FF, 0x10

    def reconnect(_e: Exception) -> None:
        nonlocal sock
        try:
            sock.close()
        except OSError:
            pass
        sock = connect_tcp(args.host, args.slmp_port)

    def cycle(n: int) -> str | None:
        req = slmp_encode_batch_read(net, pc, dest, mon, SLMP_DEV_D, 100, 17)
        end, data = slmp_decode_resp(slmp_transact(sock, req))
        if end != SLMP_END_OK:
            return f"batch_read end_code=0x{end:04x}"
        if len(data) < 34:
            return f"short D100 payload {len(data)}"
        be = slmp_words_le_to_be_chars(data[:34])
        barcode = unpack_barcode_be_chars(be[0:32])
        temp_raw = struct.unpack(">H", be[32:34])[0]
        temp_c = temp_raw * 0.1
        err = check_sensor_barcode_temp(barcode, temp_c, stats.t0, args.wait_s)
        if err:
            return err
        wr = struct.pack(">H", n & 0xFFFF)
        wreq = slmp_encode_batch_write(net, pc, dest, mon, SLMP_DEV_D, 200, wr)
        wend, _ = slmp_decode_resp(slmp_transact(sock, wreq))
        if wend != SLMP_END_OK:
            return f"batch_write D200 end_code=0x{wend:04x}"
        rreq = slmp_encode_batch_read(net, pc, dest, mon, SLMP_DEV_D, 200, 1)
        rend, rdata = slmp_decode_resp(slmp_transact(sock, rreq))
        if rend != SLMP_END_OK:
            return f"batch_read D200 end_code=0x{rend:04x}"
        got_be = slmp_words_le_to_be_chars(rdata[:2])
        got = struct.unpack(">H", got_be)[0]
        if got != (n & 0xFFFF):
            return f"D200 writeback {got} != {n & 0xFFFF}"
        if not args.quiet:
            print(
                f"cycle={n} barcode={barcode!r} temperature={temp_c:.1f} "
                f"D200={got}  [tcp_loopback Binary 3E]",
                flush=True,
            )
        return None

    try:
        run_until(args, cycle, stats, on_fail=reconnect)
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print_result("slmp", "tcp_loopback", stats, float(args.period_ms))
    return 0 if stats.fail == 0 and stats.ok > 0 else 1


# ---- EtherNet/IP (live TCP + Class 1 UDP, or cyclic explicit) -------------


def eip_encap(cmd: int, session: int, payload: bytes, context: bytes = b"\x00" * 8) -> bytes:
    hdr = struct.pack(
        "<HHII8sI", cmd, len(payload), session, 0, context, 0
    )
    return hdr + payload


def eip_send_recv(sock: socket.socket, frame: bytes, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    sock.sendall(frame)
    hdr = recvall(sock, 24)
    if len(hdr) < 24:
        raise IOError(f"short Encaps {hdr!r}")
    length = struct.unpack_from("<H", hdr, 2)[0]
    body = recvall(sock, length) if length else b""
    if len(body) < length:
        raise IOError("eof in Encaps body")
    status = struct.unpack_from("<I", hdr, 8)[0]
    if status != 0:
        raise IOError(f"Encaps status={status}")
    return hdr + body


def eip_register_session(sock: socket.socket) -> int:
    payload = struct.pack("<HH", 1, 0)
    resp = eip_send_recv(sock, eip_encap(EIP_CMD_REGISTERSESSION, 0, payload))
    cmd, _length, session, status = struct.unpack_from("<HHII", resp, 0)
    if cmd != EIP_CMD_REGISTERSESSION or status != 0 or session == 0:
        raise IOError(f"RegisterSession failed cmd={cmd:#x} st={status} sess={session}")
    return session


def eip_sendrr(sock: socket.socket, session: int, cip: bytes) -> bytes:
    body = bytearray()
    body += le32(0)  # interface handle
    body += le16(10)  # timeout ticks
    body += le16(2)  # item count
    body += le16(EIP_ITEM_NULL_ADDR) + le16(0)
    body += le16(EIP_ITEM_UNCONNECTED_DATA) + le16(len(cip))
    body += cip
    resp = eip_send_recv(sock, eip_encap(EIP_CMD_SENDRRDATA, session, bytes(body)))
    # Walk CPF items for unconnected data.
    length = struct.unpack_from("<H", resp, 2)[0]
    cpf = resp[24 : 24 + length]
    if len(cpf) < 8:
        raise IOError("short SendRRData")
    off = 6  # iface + timeout
    items = struct.unpack_from("<H", cpf, off)[0]
    off += 2
    payload = None
    for _ in range(items):
        if off + 4 > len(cpf):
            break
        itype, ilen = struct.unpack_from("<HH", cpf, off)
        off += 4
        chunk = cpf[off : off + ilen]
        off += ilen
        if itype == EIP_ITEM_UNCONNECTED_DATA:
            payload = chunk
    if not payload or len(payload) < 4:
        raise IOError(f"no CIP payload {payload!r}")
    status = payload[2]
    extra = payload[3]
    data_off = 4 + 2 * extra
    if status != CIP_STATUS_SUCCESS:
        ext = 0
        if extra and len(payload) >= 6:
            ext = struct.unpack_from("<H", payload, 4)[0]
        raise IOError(f"CIP status=0x{status:02x} ext=0x{ext:04x} svc=0x{payload[0]:02x}")
    return payload[data_off:]


def cip_get_attr(class_id: int, instance: int, attr: int) -> bytes:
    return bytes(
        [
            CIP_SVC_GET_ATTR_SINGLE,
            3,
            0x20,
            class_id & 0xFF,
            0x24,
            instance & 0xFF,
            0x30,
            attr & 0xFF,
        ]
    )


def cip_set_attr(class_id: int, instance: int, attr: int, data: bytes) -> bytes:
    return (
        bytes(
            [
                CIP_SVC_SET_ATTR_SINGLE,
                3,
                0x20,
                class_id & 0xFF,
                0x24,
                instance & 0xFF,
                0x30,
                attr & 0xFF,
            ]
        )
        + data
    )


def cip_forward_open(
    o2t_size: int,
    t2o_size: int,
    rpi_us: int,
    conn_serial: int,
    vendor: int,
    orig_serial: int,
) -> bytes:
    fo = bytearray()
    fo.append(0x0A)
    fo.append(0x05)
    fo += le32(0)  # O->T conn id (adapter assigns)
    fo += le32(0)  # T->O conn id
    fo += le16(conn_serial)
    fo += le16(vendor)
    fo += le32(orig_serial)
    fo.append(0)  # timeout multiplier
    fo += b"\x00\x00\x00"
    fo += le32(rpi_us)
    fo += le16(o2t_size)
    fo += le32(rpi_us)
    fo += le16(t2o_size)
    fo.append(0x01)  # class 1
    fo.append(0)  # empty connection path (our DUT accepts this)
    path = bytes([0x20, CIP_CLASS_CONN_MANAGER, 0x24, 1])
    return bytes([CIP_SVC_FORWARD_OPEN, 2]) + path + bytes(fo)


def cip_forward_close(conn_serial: int, vendor: int, orig_serial: int) -> bytes:
    body = bytearray()
    body.append(0x0A)
    body.append(0x05)
    body += le16(conn_serial)
    body += le16(vendor)
    body += le32(orig_serial)
    body.append(0)  # path size
    body.append(0)
    path = bytes([0x20, CIP_CLASS_CONN_MANAGER, 0x24, 1])
    return bytes([CIP_SVC_FORWARD_CLOSE, 2]) + path + bytes(body)


def class1_io_frame(conn_id: int, seq: int, payload: bytes) -> bytes:
    buf = bytearray()
    buf += le16(2)
    buf += le16(EIP_ITEM_SEQ_ADDR) + le16(8)
    buf += le32(conn_id) + le32(seq)
    buf += le16(EIP_ITEM_CONNECTED_DATA) + le16(2 + len(payload))
    buf += le16(seq & 0xFFFF)
    buf += payload
    return bytes(buf)


def parse_class1_io(frame: bytes) -> tuple[int, bytes]:
    if len(frame) < 6:
        raise IOError("short Class1 frame")
    items = struct.unpack_from("<H", frame, 0)[0]
    off = 2
    conn_id = 0
    payload = b""
    for _ in range(items):
        if off + 4 > len(frame):
            break
        itype, ilen = struct.unpack_from("<HH", frame, off)
        off += 4
        chunk = frame[off : off + ilen]
        off += ilen
        if itype == EIP_ITEM_SEQ_ADDR and len(chunk) >= 8:
            conn_id = struct.unpack_from("<I", chunk, 0)[0]
        elif itype == EIP_ITEM_CONNECTED_DATA:
            payload = chunk[2:] if len(chunk) >= 2 else chunk
    return conn_id, payload


def parse_assembly_input(data: bytes) -> tuple[str, float]:
    if len(data) < 36:
        raise IOError(f"short assembly {len(data)}")
    barcode = data[0:32].split(b"\x00", 1)[0].decode("ascii", "replace").rstrip()
    temp_c = struct.unpack_from("<f", data, 32)[0]
    return barcode, temp_c


def run_eip_explicit(args: argparse.Namespace, sock: socket.socket, session: int) -> int:
    stats = Stats()

    def cycle(n: int) -> str | None:
        ident = eip_sendrr(sock, session, cip_get_attr(CIP_CLASS_IDENTITY, 1, 1))
        if len(ident) < 2:
            return "short Identity attr1"
        vendor = struct.unpack_from("<H", ident, 0)[0]
        if vendor != 0xABCD:
            return f"Identity vendor 0x{vendor:04x} != 0xABCD"
        data = eip_sendrr(
            sock, session, cip_get_attr(CIP_CLASS_ASSEMBLY, args.eip_input_asm, 3)
        )
        barcode, temp_c = parse_assembly_input(data)
        err = check_sensor_barcode_temp(barcode, temp_c, stats.t0, args.wait_s)
        if err:
            return err
        out = struct.pack("<H", n & 0xFFFF) + bytes(14)
        eip_sendrr(
            sock,
            session,
            cip_set_attr(CIP_CLASS_ASSEMBLY, args.eip_output_asm, 3, out[:16]),
        )
        if not args.quiet:
            print(
                f"cycle={n} barcode={barcode!r} temperature={temp_c:.1f} "
                f"vendor=0x{vendor:04x}  [tcp_loopback explicit]",
                flush=True,
            )
        return None

    run_until(args, cycle, stats)
    print_result(
        "ethernetip",
        "tcp_loopback_explicit",
        stats,
        float(args.period_ms),
        extra="(not Class1 UDP)",
    )
    return 0 if stats.fail == 0 and stats.ok > 0 else 1


def run_eip_class1(args: argparse.Namespace, sock: socket.socket, session: int) -> int:
    ident = eip_sendrr(sock, session, cip_get_attr(CIP_CLASS_IDENTITY, 1, 1))
    vendor = struct.unpack_from("<H", ident, 0)[0] if len(ident) >= 2 else 0
    if vendor != 0xABCD:
        raise IOError(f"Identity vendor 0x{vendor:04x} != 0xABCD")

    conn_serial = int(time.time()) & 0xFFFF
    orig_serial = 0x53574D31  # 'SWM1'
    orig_vendor = 1
    rpi_us = max(int(args.period_ms * 1000), 8000)
    cip = cip_forward_open(
        args.eip_output_size,
        args.eip_input_size,
        rpi_us,
        conn_serial,
        orig_vendor,
        orig_serial,
    )
    fo = eip_sendrr(sock, session, cip)
    if len(fo) < 8:
        raise IOError(f"short Forward Open reply {fo!r}")
    o2t = struct.unpack_from("<I", fo, 0)[0]
    t2o = struct.unpack_from("<I", fo, 4)[0]
    if o2t == 0 or t2o == 0:
        raise IOError(f"Forward Open conn ids o2t={o2t} t2o={t2o}")

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.bind((args.host, 0))
    udp.settimeout(0.25)
    dut = (args.host, args.eip_udp_port)
    seq = 0
    stats = Stats()

    def cycle(n: int) -> str | None:
        nonlocal seq
        seq += 1
        payload = struct.pack("<H", n & 0xFFFF) + bytes(args.eip_output_size - 2)
        frame = class1_io_frame(o2t, seq, payload[: args.eip_output_size])
        udp.sendto(frame, dut)
        deadline = time.monotonic() + 0.4
        data = b""
        while time.monotonic() < deadline:
            try:
                pkt, _addr = udp.recvfrom(2048)
            except socket.timeout:
                udp.sendto(frame, dut)
                continue
            cid, data = parse_class1_io(pkt)
            if cid == t2o and len(data) >= 36:
                break
            data = b""
        if len(data) < 36:
            return "no Class1 T->O (adapter produce)"
        barcode, temp_c = parse_assembly_input(data)
        err = check_sensor_barcode_temp(barcode, temp_c, stats.t0, args.wait_s)
        if err:
            return err
        if not args.quiet:
            print(
                f"cycle={n} barcode={barcode!r} temperature={temp_c:.1f} "
                f"o2t=0x{o2t:08x} t2o=0x{t2o:08x}  [tcp+udp Class1 loopback]",
                flush=True,
            )
        return None

    try:
        run_until(args, cycle, stats)
    finally:
        try:
            eip_sendrr(
                sock,
                session,
                cip_forward_close(conn_serial, orig_vendor, orig_serial),
            )
        except (OSError, IOError):
            pass
        udp.close()
    print_result(
        "ethernetip",
        "tcp_udp_class1_loopback",
        stats,
        float(args.period_ms),
        extra=f"o2t=0x{o2t:08x} t2o=0x{t2o:08x}",
    )
    return 0 if stats.fail == 0 and stats.ok > 0 else 1


def run_eip(args: argparse.Namespace) -> int:
    wait_port(args.host, args.eip_port, timeout=args.wait_s)
    sock = connect_tcp(args.host, args.eip_port)
    try:
        session = eip_register_session(sock)
        if not args.quiet:
            print(
                f"RegisterSession session=0x{session:08x} "
                f"{args.host}:{args.eip_port} mode={args.eip_mode}",
                flush=True,
            )
        if args.eip_mode == "explicit":
            return run_eip_explicit(args, sock, session)
        try:
            return run_eip_class1(args, sock, session)
        except (OSError, IOError) as e:
            print(
                f"Class1 scanner path failed ({e}); "
                "falling back to cyclic explicit Get/Set Attribute "
                "(still live TCP loopback, not in-process CTT)",
                flush=True,
            )
            return run_eip_explicit(args, sock, session)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Live TCP loopback against fake_sensor_app / our stacks.\n"
            "PROFINET is not a live software-master path (see docs/sw_master_io.md).\n"
            "Not CODESYS, not certification."
        ),
    )
    p.add_argument(
        "--protocol",
        choices=("modbus", "slmp", "ethernetip"),
        default="modbus",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=15560, help="Modbus TCP port")
    p.add_argument("--unit", type=int, default=1)
    p.add_argument("--slmp-port", type=int, default=15561)
    p.add_argument("--eip-port", type=int, default=15562, help="EIP TCP Encaps")
    p.add_argument("--eip-udp-port", type=int, default=15563, help="EIP Class1 UDP")
    p.add_argument(
        "--eip-mode",
        choices=("class1", "explicit"),
        default="class1",
        help="class1 = Forward Open + UDP IO; explicit = cyclic UCMM only",
    )
    p.add_argument("--eip-input-asm", type=int, default=150)
    p.add_argument("--eip-output-asm", type=int, default=101)
    p.add_argument("--eip-input-size", type=int, default=64)
    p.add_argument("--eip-output-size", type=int, default=16)
    p.add_argument("--cycles", type=int, default=32, help="0 = use --seconds")
    p.add_argument("--seconds", type=float, default=0, help="overrides cycles if >0")
    p.add_argument("--period-ms", type=int, default=50)
    p.add_argument("--wait-s", type=float, default=8.0)
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.quiet:
        print(BANNER, flush=True)
        print(
            "live TCP loopback vs in-repo DUT; not CODESYS; not certification",
            flush=True,
        )
    if args.protocol == "modbus":
        return run_modbus(args)
    if args.protocol == "slmp":
        return run_slmp(args)
    return run_eip(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
