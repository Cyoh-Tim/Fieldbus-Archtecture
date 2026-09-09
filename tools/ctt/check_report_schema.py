#!/usr/bin/env python3
"""Run one CTT scenario with --report and check ctt-report/v1 keys.

Used by ctest (`ctt_report_schema_v1`, `ctt_report_schema_eip_v1`). Stdlib only.
Internal bundle-grade report != PI / ODVA certification evidence.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REQUIRED = (
    "schema",
    "disclaimer",
    "suite_id",
    "tc_id",
    "name",
    "protocol",
    "scenario",
    "transport",
    "verdict",
    "failures",
    "duration_ms",
    "metrics",
)

METRIC_KEYS = (
    "rtc1_frames",
    "late_cycles",
    "missed_cycles",
    "unexpected_frames",
    "ar_drops",
    "period_min_ns",
    "period_max_ns",
    "jitter_max_ns",
    "cycle_ns",
    "jitter_hist_ms",
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ctt", required=True)
    ap.add_argument("--scenario", required=True)
    ap.add_argument(
        "--protocol",
        default="profinet",
        help="expected report protocol (profinet, ethernetip, ...)",
    )
    args = ap.parse_args()
    sc = Path(args.scenario)
    if not sc.is_file():
        print(f"missing scenario {sc}", file=sys.stderr)
        return 2

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "report.json"
        cmd = [args.ctt, "--scenario", str(sc), "--report", str(out)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stdout)
            sys.stderr.write(r.stderr)
            print("ctt failed", file=sys.stderr)
            return r.returncode or 1
        data = json.loads(out.read_text(encoding="utf-8"))

    missing = [k for k in REQUIRED if k not in data]
    if missing:
        print(f"missing keys: {missing}", file=sys.stderr)
        return 1
    if data["schema"] != "ctt-report/v1":
        print(f"bad schema {data['schema']!r}", file=sys.stderr)
        return 1
    if data["verdict"] != "pass":
        print(f"expected pass, got {data['verdict']!r}", file=sys.stderr)
        return 1
    if data["protocol"] != args.protocol:
        print(f"expected {args.protocol}, got {data['protocol']!r}", file=sys.stderr)
        return 1
    if not data.get("tc_id"):
        print("tc_id empty", file=sys.stderr)
        return 1
    metrics = data["metrics"]
    miss_m = [k for k in METRIC_KEYS if k not in metrics]
    if miss_m:
        print(f"missing metrics: {miss_m}", file=sys.stderr)
        return 1
    if not isinstance(metrics["jitter_hist_ms"], list) or len(
        metrics["jitter_hist_ms"]
    ) != 6:
        print("jitter_hist_ms must be 6 buckets", file=sys.stderr)
        return 1
    if metrics["rtc1_frames"] < 1:
        print("rtc1_frames should be > 0 for cyclic scenario", file=sys.stderr)
        return 1
    print(
        f"ok schema={data['schema']} tc_id={data['tc_id']} "
        f"verdict={data['verdict']} rtc1={metrics['rtc1_frames']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
