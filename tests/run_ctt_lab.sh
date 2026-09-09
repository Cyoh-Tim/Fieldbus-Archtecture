#!/usr/bin/env bash
# CTT lab profile: veth pair + AF_PACKET. Same YAML as mock CI.
# Requires CAP_NET_ADMIN (veth) + CAP_NET_RAW (AF_PACKET). Not a default ctest.
#
# Usage (from repo root):
#   tests/run_ctt_lab.sh
#   CTT_LAB_REQUIRE=1 tests/run_ctt_lab.sh   # fail if capabilities missing
#
# Optional wrappers (if built with BUILD_PN_LAB_TOOLS):
#   ./build/pn_device_run ctt-dut
#   ./build/dcp_probe ctt-ctl
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTT=${CTT_BIN:-"$ROOT/build/ctt"}
CTL_IF=${CTT_IFACE:-ctt-ctl}
DUT_IF=${CTT_DUT_IFACE:-ctt-dut}
REQUIRE=${CTT_LAB_REQUIRE:-0}
export PATH="/usr/sbin:/sbin:$PATH"

skip() {
    echo "SKIP lab: $*" >&2
    if [ "$REQUIRE" = "1" ]; then
        exit 1
    fi
    exit 0
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || skip "missing $1"
}

if [ ! -x "$CTT" ]; then
    skip "ctt binary not found at $CTT (build with -DBUILD_CTT=ON -DENABLE_CTT_AF_PACKET=ON)"
fi

need_cmd ip

if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -E CTT_BIN="$CTT" CTT_IFACE="$CTL_IF" CTT_DUT_IFACE="$DUT_IF" \
            CTT_LAB_REQUIRE="$REQUIRE" "$0" "$@"
    fi
    skip "need root or passwordless sudo (CAP_NET_ADMIN + CAP_NET_RAW)"
fi

cleanup() {
    ip link del "$CTL_IF" 2>/dev/null || true
}
trap cleanup EXIT

if ! ip link add "$CTL_IF" type veth peer name "$DUT_IF" 2>/tmp/ctt-veth.err; then
    skip "cannot create veth ($CTL_IF/$DUT_IF): $(cat /tmp/ctt-veth.err 2>/dev/null)"
fi

# Match mock MACs so Identify.Res src/dst stay predictable on the wire.
ip link set "$CTL_IF" address 00:11:22:33:44:55
ip link set "$DUT_IF" address 02:fb:00:00:00:01
ip link set "$CTL_IF" up
ip link set "$DUT_IF" up
ip link set "$CTL_IF" multicast on
ip link set "$DUT_IF" multicast on

run_sc() {
    local yaml=$1
    echo "=== lab $yaml ==="
    "$CTT" --transport=af_packet --iface="$CTL_IF" --dut-iface="$DUT_IF" \
        --scenario "$ROOT/$yaml"
}

# Wire-meaningful subset. RPC Connect stays in-process (pn_stack_handle_rpc);
# RTC1/DCP frames go over the veth. SNMP/record stay mock-style hooks.
run_sc tests/scenarios/profinet/dcp_identify_name_of_station.yaml || {
    echo "FAIL: DCP Identify on veth" >&2
    exit 1
}

run_sc tests/scenarios/profinet/rtc1_io_cycle_smoke.yaml || {
    echo "FAIL: Connect (in-process) + RTC1 on veth" >&2
    exit 1
}

echo "OK lab subset on $CTL_IF <-> $DUT_IF (Identify + RTC1)"
exit 0
