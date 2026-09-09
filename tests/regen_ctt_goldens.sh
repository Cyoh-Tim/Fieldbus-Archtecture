#!/usr/bin/env bash
# Regenerate mock goldens checked in under tests/golden/profinet/.
# Run from repo root after building ./build/ctt. No NIC required.
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CTT=${CTT_BIN:-"$ROOT/build/ctt"}
OUT="$ROOT/tests/golden/profinet"
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

copy_step() {
    local src=$1
    local dst=$2
    cp -f "$TMP/$src" "$OUT/$dst"
}

"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_identify_name_of_station.yaml" \
    --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_set_sec_class1.yaml" \
    --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_get.yaml" --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_hello.yaml" --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_signal.yaml" --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_set_ip.yaml" --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/alarm_low.yaml" --capture "$TMP"

copy_step dcp_identify_name_of_station-1-dcp_identify.pcap dcp_identify_res.pcap
# Second dcp_set step is signed accept (step index 2).
copy_step dcp_set_sec_class1-2-dcp_set.pcap dcp_set_sec_class1_accept.pcap
copy_step dcp_get-1-dcp_get.pcap dcp_get_res.pcap
copy_step dcp_hello-1-dcp_hello.pcap dcp_hello.pcap
copy_step dcp_signal-1-dcp_signal.pcap dcp_signal_accept.pcap
copy_step dcp_set_ip-1-dcp_set_ip.pcap dcp_hello_after_set_ip.pcap
copy_step alarm_low-2-alarm.pcap alarm_low.pcap

echo "wrote:"
ls -l "$OUT"/*.pcap
echo "re-run: ctest --test-dir build -L golden --output-on-failure"
