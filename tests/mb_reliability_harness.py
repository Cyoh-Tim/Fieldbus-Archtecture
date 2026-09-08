#!/usr/bin/env python3
"""
Full Modbus reliability harness against stacks/modbus + multiproto_daemon.

Phases:
  1) unit binaries
  2) seeded server functional matrix (all FC / areas / patterns)
  3) multiproto_daemon server holding/coil R/W
  4) concurrent multi-master
  5) reconnect storm
  6) long soak poll (default 900s)
"""

from __future__ import annotations

import argparse
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
ARTIFACT_CANDIDATES = [
    Path("/opt/cursor/artifacts/modbus-full-reliability-report.txt"),
    ROOT / "build" / "modbus-full-reliability-report.txt",
    Path("/tmp/modbus-full-reliability-report.txt"),
]


@dataclass
class Stats:
    ok: int = 0
    fail: int = 0
    errors: list[str] = field(default_factory=list)

    def check(self, cond: bool, msg: str) -> None:
        if cond:
            self.ok += 1
        else:
            self.fail += 1
            self.errors.append(msg)
            print(f"FAIL: {msg}", flush=True)


def be16(v: int) -> bytes:
    return struct.pack(">H", v & 0xFFFF)


def txn(sock: socket.socket, unit: int, pdu: bytes, timeout: float = 2.0) -> bytes:
    sock.settimeout(timeout)
    tid = 1
    mbap = struct.pack(">HHHB", tid, 0, 1 + len(pdu), unit) + pdu
    sock.sendall(mbap)
    hdr = sock.recv(7)
    if len(hdr) < 7:
        raise IOError(f"short hdr {hdr!r}")
    length = struct.unpack(">H", hdr[4:6])[0]
    body = b""
    while len(body) < length - 1:
        chunk = sock.recv(length - 1 - len(body))
        if not chunk:
            raise IOError("eof")
        body += chunk
    return body


def connect(port: int) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def wait_port(port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = connect(port)
            s.close()
            return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} not open")


def start_proc(cmd: list[str], log_path: Path) -> subprocess.Popen:
    log = open(log_path, "w")
    return subprocess.Popen(
        cmd,
        cwd=str(ROOT),
        stdout=log,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_proc(p: subprocess.Popen | None) -> None:
    if not p:
        return
    p.send_signal(signal.SIGTERM)
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=2)


def phase_unit(stats: Stats) -> None:
    print("\n=== PHASE 1: unit binaries ===", flush=True)
    for name in ("test_mb_stack", "test_mb_adapter"):
        r = subprocess.run([str(BUILD / name)], capture_output=True, text=True)
        stats.check(r.returncode == 0, f"{name} rc={r.returncode} {r.stderr}")
        print(r.stdout.strip(), flush=True)


def phase_functional(stats: Stats, port: int) -> None:
    print("\n=== PHASE 2: seeded functional matrix ===", flush=True)
    s = connect(port)
    # FC03 holding[0]=0xA000
    body = txn(s, 1, bytes([0x03]) + be16(0) + be16(1))
    stats.check(body[0] == 0x03 and body[2:4] == b"\xa0\x00", f"FC03 hold0 {body!r}")
    # FC04 input[5]=0xB005
    body = txn(s, 1, bytes([0x04]) + be16(5) + be16(1))
    stats.check(body[0] == 0x04 and body[2:4] == b"\xb0\x05", f"FC04 in5 {body!r}")
    # FC01 coil[2] = 2&1 = 0
    body = txn(s, 1, bytes([0x01]) + be16(2) + be16(1))
    stats.check(body[0] == 0x01 and (body[2] & 1) == 0, f"FC01 coil2 {body!r}")
    # FC02 discrete[2] = (2>>1)&1 = 1
    body = txn(s, 1, bytes([0x02]) + be16(2) + be16(1))
    stats.check(body[0] == 0x02 and (body[2] & 1) == 1, f"FC02 di2 {body!r}")
    # FC06 write holding 10
    body = txn(s, 1, bytes([0x06]) + be16(10) + be16(0x1234))
    stats.check(body[0] == 0x06, f"FC06 {body!r}")
    body = txn(s, 1, bytes([0x03]) + be16(10) + be16(1))
    stats.check(body[2:4] == b"\x12\x34", f"FC06 verify {body!r}")
    # FC05 coil 7 on
    body = txn(s, 1, bytes([0x05]) + be16(7) + be16(0xFF00))
    stats.check(body[0] == 0x05, f"FC05 {body!r}")
    body = txn(s, 1, bytes([0x01]) + be16(7) + be16(1))
    stats.check((body[2] & 1) == 1, f"FC05 verify {body!r}")
    # FC16 multi regs
    payload = be16(0x1111) + be16(0x2222) + be16(0x3333)
    body = txn(s, 1, bytes([0x10]) + be16(20) + be16(3) + bytes([6]) + payload)
    stats.check(body[0] == 0x10, f"FC16 {body!r}")
    body = txn(s, 1, bytes([0x03]) + be16(20) + be16(3))
    stats.check(body[2:8] == payload, f"FC16 verify {body!r}")
    # FC15 multi coils
    body = txn(s, 1, bytes([0x0F]) + be16(50) + be16(8) + bytes([1, 0xA5]))
    stats.check(body[0] == 0x0F, f"FC15 {body!r}")
    body = txn(s, 1, bytes([0x01]) + be16(50) + be16(8))
    stats.check(body[2] == 0xA5, f"FC15 verify {body!r}")
    # FC22 mask write on holding 0 (was 0xA000)
    # and=0xFF00 or=0x00EE -> (0xA000&0xFF00)|(0x00EE&~0xFF00)=0xA000|0x00EE=0xA0EE
    body = txn(s, 1, bytes([0x16]) + be16(0) + be16(0xFF00) + be16(0x00EE))
    stats.check(body[0] == 0x16, f"FC22 {body!r}")
    body = txn(s, 1, bytes([0x03]) + be16(0) + be16(1))
    stats.check(body[2:4] == b"\xa0\xee", f"FC22 verify {body!r}")
    # FC23 read/write
    wpay = be16(0xABCD)
    body = txn(
        s,
        1,
        bytes([0x17]) + be16(20) + be16(2) + be16(30) + be16(1) + bytes([2]) + wpay,
    )
    stats.check(body[0] == 0x17 and body[1] == 4, f"FC23 {body!r}")
    body = txn(s, 1, bytes([0x03]) + be16(30) + be16(1))
    stats.check(body[2:4] == b"\xab\xcd", f"FC23 write verify {body!r}")
    # bulk read 125 regs
    body = txn(s, 1, bytes([0x03]) + be16(100) + be16(125))
    stats.check(body[0] == 0x03 and body[1] == 250, f"bulk125 {body[0]} {body[1]}")
    # exception illegal address
    body = txn(s, 1, bytes([0x03]) + be16(9990) + be16(20))
    stats.check(body[0] == 0x83 and body[1] == 0x02, f"ex addr {body!r}")
    # wrong unit ignored -> timeout expected
    try:
        txn(s, 9, bytes([0x03]) + be16(0) + be16(1), timeout=0.3)
        stats.check(False, "wrong unit should timeout")
    except Exception:
        stats.check(True, "wrong unit timeout")
    # string ABCD at 400
    body = txn(s, 1, bytes([0x03]) + be16(400) + be16(2))
    stats.check(body[2:6] == b"ABCD", f"string {body[2:6]!r}")
    # float 1.5 at 300
    body = txn(s, 1, bytes([0x03]) + be16(300) + be16(2))
    stats.check(body[2:6] == b"\x3f\xc0\x00\x00", f"float {body[2:6]!r}")
    s.close()


def phase_daemon(stats: Stats, port: int) -> None:
    print("\n=== PHASE 3: multiproto_daemon holding/coil ===", flush=True)
    s = connect(port)
    # write holding 16 (temperature map) and coil 0 (trigger start=1 -> offset 0)
    body = txn(s, 1, bytes([0x06]) + be16(16) + be16(255))
    stats.check(body[0] == 0x06, "daemon FC06")
    body = txn(s, 1, bytes([0x03]) + be16(16) + be16(1))
    stats.check(body[2:4] == b"\x00\xff", f"daemon hold16 {body!r}")
    body = txn(s, 1, bytes([0x05]) + be16(0) + be16(0xFF00))
    stats.check(body[0] == 0x05, "daemon FC05")
    body = txn(s, 1, bytes([0x01]) + be16(0) + be16(1))
    stats.check((body[2] & 1) == 1, f"daemon coil0 {body!r}")
    # bit3 of holding 99
    body = txn(s, 1, bytes([0x06]) + be16(99) + be16(0x0008))
    stats.check(body[0] == 0x06, "daemon bit seed")
    body = txn(s, 1, bytes([0x03]) + be16(99) + be16(1))
    stats.check(body[2:4] == b"\x00\x08", f"daemon bit {body!r}")
    s.close()


def worker_master(port: int, n: int, wid: int, out: list) -> None:
    err = 0
    try:
        s = connect(port)
        for i in range(n):
            # Non-overlapping address bands per worker (50 regs each).
            addr = wid * 60 + (i % 50)
            val = (wid << 8) | (i & 0xFF)
            txn(s, 1, bytes([0x06]) + be16(addr) + be16(val))
            body = txn(s, 1, bytes([0x03]) + be16(addr) + be16(1))
            got = struct.unpack(">H", body[2:4])[0]
            if got != val:
                err += 1
        s.close()
    except Exception as e:
        err += 1
        out.append(f"worker{wid}: {e}")
    out.append(f"worker{wid}:err={err}")


def phase_multi(stats: Stats, port: int) -> None:
    print("\n=== PHASE 4: concurrent multi-master ===", flush=True)
    out: list[str] = []
    threads = [
        threading.Thread(target=worker_master, args=(port, 200, i, out))
        for i in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("\n".join(out), flush=True)
    bad = [x for x in out if "err=" in x and not x.endswith("err=0")]
    stats.check(len(bad) == 0, f"multi-master errors {bad}")


def phase_reconnect(stats: Stats, port: int) -> None:
    print("\n=== PHASE 5: reconnect storm ===", flush=True)
    fails = 0
    for i in range(100):
        try:
            s = connect(port)
            body = txn(s, 1, bytes([0x03]) + be16(0) + be16(1))
            if body[0] != 0x03:
                fails += 1
            s.close()
        except Exception:
            fails += 1
    stats.check(fails == 0, f"reconnect fails={fails}/100")


def phase_soak(stats: Stats, port: int, seconds: int) -> None:
    print(f"\n=== PHASE 6: soak poll {seconds}s ===", flush=True)
    s = connect(port)
    end = time.time() + seconds
    cycles = 0
    fails = 0
    last_report = time.time()
    # rotate through FC01/02/03/04 and occasional writes
    while time.time() < end:
        try:
            addr = cycles % 200
            body = txn(s, 1, bytes([0x03]) + be16(addr) + be16(10), timeout=1.0)
            if body[0] != 0x03 or body[1] != 20:
                fails += 1
            body = txn(s, 1, bytes([0x04]) + be16(addr) + be16(10), timeout=1.0)
            if body[0] != 0x04:
                fails += 1
            body = txn(s, 1, bytes([0x01]) + be16(addr) + be16(16), timeout=1.0)
            if body[0] != 0x01:
                fails += 1
            body = txn(s, 1, bytes([0x02]) + be16(addr) + be16(16), timeout=1.0)
            if body[0] != 0x02:
                fails += 1
            if cycles % 20 == 0:
                txn(s, 1, bytes([0x06]) + be16(500 + (cycles % 50)) + be16(cycles & 0xFFFF))
            cycles += 1
        except Exception as e:
            fails += 1
            # reconnect
            try:
                s.close()
            except Exception:
                pass
            time.sleep(0.05)
            try:
                s = connect(port)
            except Exception as e2:
                fails += 1
                print(f"soak reconnect fail: {e2}", flush=True)
                time.sleep(0.2)
        now = time.time()
        if now - last_report >= 30:
            print(
                f"  soak progress t={int(now - (end - seconds))}s cycles={cycles} fails={fails}",
                flush=True,
            )
            last_report = now
    try:
        s.close()
    except Exception:
        pass
    rate = cycles / max(seconds, 1)
    print(f"soak done cycles={cycles} fails={fails} rate={rate:.1f} cycle/s", flush=True)
    stats.check(fails == 0, f"soak fails={fails} cycles={cycles}")
    stats.check(cycles > seconds * 5, f"soak too slow cycles={cycles}")


def try_pymodbus_poll(stats: Stats, port: int) -> None:
    print("\n=== PHASE 2b: pymodbus poll client ===", flush=True)
    try:
        from pymodbus.client import ModbusTcpClient
    except Exception as e:
        stats.check(False, f"pymodbus import {e}")
        return
    c = ModbusTcpClient("127.0.0.1", port=port, timeout=2)
    stats.check(c.connect(), "pymodbus connect")
    # pymodbus 3.x uses keyword device_id or slave depending on version
    kwargs = {}
    try:
        rr = c.read_holding_registers(0, count=10, device_id=1)
    except TypeError:
        rr = c.read_holding_registers(0, count=10, slave=1)
        kwargs["slave"] = 1
    else:
        kwargs["device_id"] = 1
    stats.check(not rr.isError(), f"pymodbus FC03 {rr}")
    rr = c.read_input_registers(0, count=10, **kwargs)
    stats.check(not rr.isError(), f"pymodbus FC04 {rr}")
    rr = c.read_coils(0, count=16, **kwargs)
    stats.check(not rr.isError(), f"pymodbus FC01 {rr}")
    rr = c.read_discrete_inputs(0, count=16, **kwargs)
    stats.check(not rr.isError(), f"pymodbus FC02 {rr}")
    wr = c.write_register(11, 0x55AA, **kwargs)
    stats.check(not wr.isError(), f"pymodbus FC06 {wr}")
    rr = c.read_holding_registers(11, count=1, **kwargs)
    stats.check(not rr.isError() and rr.registers[0] == 0x55AA, f"pymodbus verify {rr}")
    # poll loop 200 times
    fails = 0
    for i in range(200):
        rr = c.read_holding_registers(i % 50, count=5, **kwargs)
        if rr.isError():
            fails += 1
    stats.check(fails == 0, f"pymodbus poll fails={fails}")
    c.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--soak-seconds", type=int, default=900, help="soak duration")
    ap.add_argument("--skip-soak", action="store_true")
    args = ap.parse_args()

    ARTIFACT_CANDIDATES[0].parent.mkdir(parents=True, exist_ok=True)
    stats = Stats()
    logdir = Path("/tmp/mb_reliability")
    logdir.mkdir(exist_ok=True)

    # Ensure binaries
    if not (BUILD / "test_mb_stack").exists():
        print("build missing; run cmake/make first", file=sys.stderr)
        return 2

    phase_unit(stats)

    seeded_port = 1602
    daemon_port = 1502
    seeded = start_proc(
        [str(BUILD / "mb_seeded_server"), "--port", str(seeded_port)],
        logdir / "seeded.log",
    )
    try:
        wait_port(seeded_port)
        phase_functional(stats, seeded_port)
        try_pymodbus_poll(stats, seeded_port)
        phase_multi(stats, seeded_port)
        phase_reconnect(stats, seeded_port)
        if not args.skip_soak:
            phase_soak(stats, seeded_port, args.soak_seconds)
    finally:
        stop_proc(seeded)

    daemon = start_proc(
        [str(BUILD / "multiproto_daemon"), str(ROOT / "config/test.modbus.reliability.json")],
        logdir / "daemon.log",
    )
    try:
        wait_port(daemon_port)
        phase_daemon(stats, daemon_port)
        # short daemon soak 60s
        print("\n=== PHASE 3b: daemon short soak 60s ===", flush=True)
        s = connect(daemon_port)
        end = time.time() + 60
        cyc = fail = 0
        while time.time() < end:
            try:
                body = txn(s, 1, bytes([0x03]) + be16(0) + be16(5))
                if body[0] != 0x03:
                    fail += 1
                cyc += 1
            except Exception:
                fail += 1
                try:
                    s.close()
                except Exception:
                    pass
                s = connect(daemon_port)
        s.close()
        print(f"daemon soak cycles={cyc} fails={fail}", flush=True)
        stats.check(fail == 0 and cyc > 100, f"daemon soak fail={fail} cyc={cyc}")
    finally:
        stop_proc(daemon)

    report = []
    report.append(f"Modbus full reliability report @ {time.strftime('%Y-%m-%d %H:%M:%S')}")
    report.append(f"OK={stats.ok} FAIL={stats.fail}")
    report.append(f"soak_seconds={0 if args.skip_soak else args.soak_seconds}")
    if stats.errors:
        report.append("Failures:")
        report.extend(f"  - {e}" for e in stats.errors)
    else:
        report.append("All checks passed.")
    text = "\n".join(report) + "\n"
    written = None
    for path in ARTIFACT_CANDIDATES:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            written = path
            break
        except OSError as e:
            print(f"warn: cannot write {path}: {e}", flush=True)
    print(f"report: {written}", flush=True)
    print("\n" + text, flush=True)
    return 1 if stats.fail else 0


if __name__ == "__main__":
    sys.exit(main())
