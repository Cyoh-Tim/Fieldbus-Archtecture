#!/usr/bin/env bash
# CODESYS (Windows) manual interoperability checklist — not CI.
#
# This script never launches CODESYS Control Win. GitHub Actions has no
# Windows Development System. Use it on a Linux DUT host next to a Windows
# engineering PC (USB Ethernet / bridge / same L2).
#
# Usage:
#   tests/codesys_manual_lab.sh              # print checklist
#   tests/codesys_manual_lab.sh ctt-dut      # also start pn_device_run
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
IFACE=${1:-}

cat <<'EOF'
CODESYS manual path (CC-B / RT Class 1 only — no IRT project)

Linux DUT
  1. Build: cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON \
       -DBUILD_PN_LAB_TOOLS=ON && cmake --build build
  2. Bring up the NIC that faces the CODESYS PC. Example veth (same machine):
       tests/run_ctt_lab.sh          # automated CTT subset, not CODESYS
  3. Device process (unsigned lab):
       ./build/pn_device_run <iface>
       # or daemon: ./build/multiproto_daemon config/example.profinet.json
  4. NameOfStation: sensor-line1
     Cycle: 8 ms, RT Class 1. Do not enable IRT / RT Class 3 / CC-C.

Windows / CODESYS (manual — not in GitHub Actions)
  5. Install CODESYS Development System + Control Win on a Windows PC.
  6. Import stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml
  7. New standard project, add the Device, set NameOfStation sensor-line1.
  8. Controller scan / DCP Identify. Assign IP if needed (DCP Set IP).
  9. Expected CM sequence (same as CTT rpc_write_prmend_appready.yaml):
       Connect → (optional Write) → ParameterEnd → Device ApplicationReady
       → cyclic RTC1
  10. Confirm cyclic IO (8 ms). Do not tick IRT / isochronous.
  11. Optional: SNMP GET sysName from a Linux host on the same L2
       (UDP 161; community public). CM is UDP 34964.

Pass / fail (lab notes, not PI evidence)
  [ ] Identify sees sensor-line1
  [ ] IP assignment / Hello (if engineering tool sends DCP Set IP)
  [ ] AR established, cyclic IO running
  [ ] ParameterEnd / ApplicationReady did not fault
  [ ] No IRT / PTCP / CC-C features used

CTT vs CODESYS
  CTT YAML is the regression harness (mock CI + optional veth).
  CODESYS is a manual interoperability gate. Green CTT ≠ PI certificate.

Related:
  docs/ctt_lab.md
  tests/run_ctt_lab.sh
  tests/run_pn_device_run.sh
  tests/run_dcp_probe.sh
EOF

if [ -n "$IFACE" ]; then
    BIN=${PN_DEVICE_BIN:-"$ROOT/build/pn_device_run"}
    if [ ! -x "$BIN" ]; then
        echo "pn_device_run not found at $BIN (build with -DBUILD_PN_LAB_TOOLS=ON)" >&2
        exit 1
    fi
    echo
    echo "starting $BIN $IFACE (Ctrl-C to stop)"
    exec "$BIN" "$IFACE"
fi
exit 0
