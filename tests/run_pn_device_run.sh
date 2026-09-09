#!/usr/bin/env bash
# Thin wrapper around pn_device_run (unsigned lab Device on a real iface).
# CMake target: BUILD_PN_LAB_TOOLS. Needs CAP_NET_RAW. Not ctest.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${PN_DEVICE_RUN:-"$ROOT/build/pn_device_run"}
IFACE=${1:-${CTT_DUT_IFACE:-ctt-dut}}
if [ ! -x "$BIN" ]; then
    echo "missing $BIN (cmake -DBUILD_PN_LAB_TOOLS=ON)" >&2
    exit 1
fi
exec "$BIN" "$IFACE"
