#!/usr/bin/env bash
# CTT lab profile: veth pair + AF_PACKET (+ UDP CM 34964 / SNMP 161).
# Same YAML as mock CI. Requires CAP_NET_ADMIN (veth) + CAP_NET_RAW (AF_PACKET).
# Not a default ctest.
#
# Usage (from repo root):
#   tests/run_ctt_lab.sh
#   CTT_LAB_REQUIRE=1 tests/run_ctt_lab.sh   # fail if capabilities missing
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTT=${CTT_BIN:-"$ROOT/build/ctt"}
CTL_IF=${CTT_IFACE:-ctt-ctl}
DUT_IF=${CTT_DUT_IFACE:-ctt-dut}
REQUIRE=${CTT_LAB_REQUIRE:-0}
CTL_IP=${CTT_LAB_CTL_IP:-192.168.200.1}
DUT_IP=${CTT_LAB_DUT_IP:-192.168.200.2}
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
            CTT_LAB_REQUIRE="$REQUIRE" CTT_LAB_CTL_IP="$CTL_IP" \
            CTT_LAB_DUT_IP="$DUT_IP" "$0" "$@"
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
ip addr add "$CTL_IP/24" dev "$CTL_IF" 2>/dev/null || true
ip addr add "$DUT_IP/24" dev "$DUT_IF" 2>/dev/null || true
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

fail_sc() {
    echo "FAIL: $*" >&2
    exit 1
}

# Ethernet (wire-meaningful). DCP/LLDP/Alarm/RTC1 frames on veth.
run_sc tests/scenarios/profinet/dcp_identify_name_of_station.yaml || fail_sc "DCP Identify on veth"
run_sc tests/scenarios/profinet/dcp_get.yaml || fail_sc "DCP Get on veth"
run_sc tests/scenarios/profinet/dcp_signal.yaml || fail_sc "DCP Signal on veth"
run_sc tests/scenarios/profinet/dcp_hello.yaml || fail_sc "DCP Hello TX on veth"
run_sc tests/scenarios/profinet/dcp_set_ip.yaml || fail_sc "DCP Set IP + Hello on veth"
run_sc tests/scenarios/profinet/lldp.yaml || fail_sc "LLDP on veth"

# UDP CM 34964 / SNMP 161 (DUT binds when not using mock eth_ops).
# YAML device.ip must match DUT_IP. Mock path still uses handle_rpc/handle_snmp.
run_sc tests/scenarios/profinet/snmp_get_sysname.yaml || fail_sc "SNMP GET sysName UDP :161"
run_sc tests/scenarios/profinet/rtc1_io_cycle_smoke.yaml || fail_sc "UDP Connect + RTC1 on veth"
run_sc tests/scenarios/profinet/alarm_tx.yaml || fail_sc "Alarm High after Connect"
run_sc tests/scenarios/profinet/alarm_low.yaml || fail_sc "Alarm Low after Connect"
run_sc tests/scenarios/profinet/record_read_im0.yaml || fail_sc "Record I&M0 UDP"
run_sc tests/scenarios/profinet/record_read_im1_4.yaml || fail_sc "Record I&M1-4 UDP"
run_sc tests/scenarios/profinet/rpc_write_prmend_appready.yaml || fail_sc "Write / PrmEnd / ApplicationReady"
run_sc tests/scenarios/profinet/rpc_release.yaml || fail_sc "CM Release UDP"

# Soak stays mock-only (not run here).
echo "OK lab subset on $CTL_IF <-> $DUT_IF ($CTL_IP / $DUT_IP)"
exit 0
