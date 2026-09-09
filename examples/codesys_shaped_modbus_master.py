#!/usr/bin/env python3
"""CODESYS-shaped Modbus TCP master stand-in.

This is NOT CODESYS Control / Development System. It is a cyclic Modbus TCP
client that polls the same holding/coil map a SoftPLC Modbus TCP Master would
use against our DUT (fake_sensor / example.codesys.modbus.json).

Use it in CI and on hosts where the Windows IDE cannot download a boot
application yet. Do not cite this as a CODESYS run, certification, or RT proof.

Usage (DUT already listening):
  python3 examples/codesys_shaped_modbus_master.py --host 127.0.0.1 --port 15560 --cycles 32

See docs/codesys_master_io.md.
First-class non-CODESYS soak (Modbus + SLMP + EIP): examples/sw_master.py
and docs/sw_master_io.md.
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

BANNER = (
    "CODESYS-shaped stand-in until SoftPLC has an app "
    "(not CODESYS, not certification, no PREEMPT_RT)"
)


def be16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def txn(sock: socket.socket, unit: int, pdu: bytes, timeout: float = 2.0) -> bytes:
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


def recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def connect(host: str, port: int, timeout: float = 3.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def elapsed_since(t0: float) -> float:
    return time.monotonic() - t0


def wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    last: OSError | None = None
    while time.time() < end:
        try:
            s = connect(host, port)
            s.close()
            return
        except OSError as e:
            last = e
            time.sleep(0.05)
    raise TimeoutError(f"{host}:{port} not open ({last})")


def fc03(sock: socket.socket, unit: int, start: int, qty: int) -> bytes:
    pdu = bytes([0x03]) + be16(start) + be16(qty)
    body = txn(sock, unit, pdu)
    if not body or body[0] != 0x03:
        raise IOError(f"FC03 exception/unexpected: {body!r}")
    n = body[1]
    return body[2 : 2 + n]


def fc05(sock: socket.socket, unit: int, coil: int, on: bool) -> None:
    val = 0xFF00 if on else 0x0000
    pdu = bytes([0x05]) + be16(coil) + be16(val)
    body = txn(sock, unit, pdu)
    if not body or body[0] != 0x05:
        raise IOError(f"FC05 exception/unexpected: {body!r}")


def unpack_barcode(regs: bytes) -> str:
    # chars_per_register=2, no string_swap: high byte then low byte per register.
    chars = []
    for i in range(0, len(regs), 2):
        chars.append(chr(regs[i]))
        if i + 1 < len(regs):
            chars.append(chr(regs[i + 1]))
    s = "".join(chars)
    return s.split("\x00", 1)[0].rstrip()


def eip_register_session(host: str, port: int, timeout: float = 2.0) -> int:
    """TCP Encapsulation RegisterSession. Listen probe only — not a Scanner."""
    cmd = 0x0065
    payload = struct.pack("<HH", 1, 0)  # protocol version, options
    hdr = struct.pack("<HHIII8sI", cmd, len(payload), 0, 0, 0, b"\x00" * 8, 0)
    s = connect(host, port, timeout=timeout)
    try:
        s.sendall(hdr + payload)
        resp = recvall(s, 24)
        if len(resp) < 24:
            raise IOError(f"short Encaps {resp!r}")
        rcmd, length, session, status = struct.unpack_from("<HHII", resp, 0)
        rest = recvall(s, length) if length else b""
        if rcmd != cmd or status != 0 or session == 0:
            raise IOError(f"RegisterSession failed cmd={rcmd:#x} st={status} sess={session} extra={rest!r}")
        return session
    finally:
        s.close()


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "SoftPLC/IDE master side is manual until a boot application can be "
            "downloaded. This script is the CI stand-in only."
        ),
    )
    p.add_argument("--host", default="127.0.0.1", help="DUT IPv4 (SoftPLC would use this)")
    p.add_argument("--port", type=int, default=15560, help="Modbus TCP listen port")
    p.add_argument("--unit", type=int, default=1, help="Modbus unit id")
    p.add_argument("--cycles", type=int, default=32, help="poll iterations (0 = use --seconds)")
    p.add_argument("--seconds", type=float, default=0, help="run for N seconds (overrides cycles if >0)")
    p.add_argument("--period-ms", type=int, default=50, help="poll period (SoftPLC-like, not 8ms RT)")
    p.add_argument("--write-coil", action="store_true", help="also FC05 coil 0 (trigger) each cycle")
    p.add_argument(
        "--protocol",
        choices=("modbus", "ethernetip"),
        default="modbus",
        help="modbus = FC03 soak; ethernetip = TCP RegisterSession listen probe",
    )
    p.add_argument("--eip-port", type=int, default=44818, help="EIP TCP Encaps port")
    p.add_argument("--wait-s", type=float, default=8.0, help="seconds to wait for DUT listen")
    p.add_argument("--quiet", action="store_true")
    return p.parse_args(argv)


def run_modbus(args: argparse.Namespace) -> int:
    wait_port(args.host, args.port, timeout=args.wait_s)
    sock = connect(args.host, args.port)
    ok = 0
    fail = 0
    t0 = time.monotonic()
    n = 0
    try:
        while True:
            n += 1
            try:
                data = fc03(sock, args.unit, 0, 17)
                if len(data) < 34:
                    raise IOError(f"short holding payload {len(data)}")
                barcode = unpack_barcode(data[0:32])
                temp_raw = struct.unpack(">H", data[32:34])[0]
                temp_c = temp_raw * 0.1
                # fake_sensor publishes after fb_start; empty map is warmup.
                if not barcode.startswith("LOT-A-"):
                    if elapsed_since(t0) < args.wait_s and not barcode:
                        if not args.quiet:
                            print(f"cycle={n} warmup (empty holding)", flush=True)
                    else:
                        raise IOError(f"unexpected barcode {barcode!r}")
                elif temp_c < 20.0 or temp_c > 40.0:
                    raise IOError(f"temperature out of fake-sensor range: {temp_c}")
                else:
                    if args.write_coil:
                        fc05(sock, args.unit, 0, True)
                    ok += 1
                    if not args.quiet:
                        print(
                            f"cycle={n} barcode={barcode!r} temperature={temp_c:.1f} "
                            f"(raw={temp_raw})  [stand-in]",
                            flush=True,
                        )
            except (OSError, IOError) as e:
                fail += 1
                print(f"FAIL cycle={n}: {e}", flush=True)
                try:
                    sock.close()
                except OSError:
                    pass
                sock = connect(args.host, args.port)

            elapsed = time.monotonic() - t0
            if args.seconds > 0:
                if elapsed >= args.seconds:
                    break
            elif args.cycles > 0 and n >= args.cycles:
                break
            time.sleep(max(args.period_ms, 1) / 1000.0)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    print(
        f"stand-in result ok={ok} fail={fail} cycles={n} "
        f"elapsed_s={time.monotonic() - t0:.2f}",
        flush=True,
    )
    return 0 if fail == 0 and ok > 0 else 1


def run_eip_probe(args: argparse.Namespace) -> int:
    wait_port(args.host, args.eip_port, timeout=args.wait_s)
    session = eip_register_session(args.host, args.eip_port)
    print(
        f"eip listen probe RegisterSession session=0x{session:08x} "
        f"{args.host}:{args.eip_port}  [not a Scanner, not CODESYS]",
        flush=True,
    )
    return 0


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if not args.quiet:
        print(BANNER, flush=True)
        print(
            "SoftPLC/IDE master side is manual until IDE can download a boot app.",
            flush=True,
        )
    if args.protocol == "ethernetip":
        return run_eip_probe(args)
    return run_modbus(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
