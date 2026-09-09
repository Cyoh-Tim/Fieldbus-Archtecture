#!/usr/bin/env bash
# Thin wrapper around dcp_probe (AF_PACKET Identify.Req). Pair with pn_device_run.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${DCP_PROBE:-"$ROOT/build/dcp_probe"}
IFACE=${1:-${CTT_IFACE:-ctt-ctl}}
if [ ! -x "$BIN" ]; then
    echo "missing $BIN (cmake -DBUILD_PN_LAB_TOOLS=ON)" >&2
    exit 1
fi
exec "$BIN" "$IFACE"
