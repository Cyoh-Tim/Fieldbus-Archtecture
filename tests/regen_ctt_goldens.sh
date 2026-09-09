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

"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_identify_name_of_station.yaml" \
    --capture "$TMP"
"$CTT" --scenario "$ROOT/tests/scenarios/profinet/dcp_set_sec_class1.yaml" \
    --capture "$TMP"

cp -f "$TMP"/dcp_identify_name_of_station-1-dcp_identify.pcap \
    "$OUT/dcp_identify_res.pcap"
# Second dcp_set step is signed accept (step index 2).
cp -f "$TMP"/dcp_set_sec_class1-2-dcp_set.pcap \
    "$OUT/dcp_set_sec_class1_accept.pcap"

echo "wrote:"
ls -l "$OUT"/dcp_identify_res.pcap "$OUT"/dcp_set_sec_class1_accept.pcap
echo "re-run: ctest --test-dir build -L golden --output-on-failure"
