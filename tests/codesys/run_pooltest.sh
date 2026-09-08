#!/usr/bin/env bash
# Full protocol pool test: live sensor demo + CODESYS-role masters.
# CODESYS Control SL (if installed) is probed; IEC download still needs the
# Windows Development System. Wire-level masters here use the same roles
# (Modbus TCP Master, EtherNet/IP Scanner/UCMM, PN Controller, SLMP 3E).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${ROOT}/build"
LOGDIR="${ROOT}/build/pooltest-logs"
mkdir -p "${LOGDIR}"

need() {
  if [[ ! -x "$1" ]]; then
    echo "missing $1 — cmake --build build first" >&2
    exit 1
  fi
}

need "${BIN}/sensor_demo"
need "${BIN}/pool_master"
need "${BIN}/multiproto_daemon"

PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do
    kill "${p}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  sudo ip link del pn-dev 2>/dev/null || true
}
trap cleanup EXIT

pass=0
fail=0
skip=0

ok() { echo "PASS $1"; pass=$((pass + 1)); }
ng() { echo "FAIL $1"; fail=$((fail + 1)); }
sk() { echo "SKIP $1 — $2"; skip=$((skip + 1)); }

# ---------- Modbus TCP (CODESYS Master ← this Device/slave) ----------
echo "=== Modbus TCP ==="
rm -f /tmp/fieldbus-sensor-mb.json
SENSOR_STATE=/tmp/fieldbus-sensor-mb.json \
  "${BIN}/sensor_demo" "${ROOT}/config/demo.sensor.modbus.json" \
  >"${LOGDIR}/sensor-modbus.log" 2>&1 &
PIDS+=($!)
sleep 0.4
if SENSOR_STATE=/tmp/fieldbus-sensor-mb.json \
  "${BIN}/pool_master" --proto modbus --host 127.0.0.1 --port 1502 --seconds 4 \
  --state /tmp/fieldbus-sensor-mb.json \
  >"${LOGDIR}/master-modbus.log" 2>&1; then
  ok "modbus live data"
else
  ng "modbus live data"
  tail -n 30 "${LOGDIR}/master-modbus.log" || true
fi
kill "${PIDS[-1]}" 2>/dev/null || true
wait "${PIDS[-1]}" 2>/dev/null || true
unset 'PIDS[-1]'

# ---------- EtherNet/IP (CODESYS Scanner ← this Adapter) ----------
echo "=== EtherNet/IP ==="
rm -f /tmp/fieldbus-sensor-eip.json
SENSOR_STATE=/tmp/fieldbus-sensor-eip.json \
  "${BIN}/sensor_demo" "${ROOT}/config/demo.sensor.ethernetip.json" \
  >"${LOGDIR}/sensor-eip.log" 2>&1 &
PIDS+=($!)
sleep 0.5
if SENSOR_STATE=/tmp/fieldbus-sensor-eip.json \
  "${BIN}/pool_master" --proto ethernetip --host 127.0.0.1 --port 44818 --seconds 4 \
  --state /tmp/fieldbus-sensor-eip.json \
  >"${LOGDIR}/master-eip.log" 2>&1; then
  ok "ethernetip live data"
else
  ng "ethernetip live data"
  tail -n 40 "${LOGDIR}/master-eip.log" || true
  tail -n 20 "${LOGDIR}/sensor-eip.log" || true
fi
kill "${PIDS[-1]}" 2>/dev/null || true
wait "${PIDS[-1]}" 2>/dev/null || true
unset 'PIDS[-1]'

# ---------- SLMP 3E (sensor client → PLC stand-in; CODESYS has no SLMP) ----------
echo "=== SLMP 3E ==="
rm -f /tmp/fieldbus-sensor-slmp.json
"${BIN}/multiproto_daemon" "${ROOT}/config/demo.slmp.plc.json" \
  >"${LOGDIR}/slmp-plc.log" 2>&1 &
PIDS+=($!)
sleep 0.3
SENSOR_STATE=/tmp/fieldbus-sensor-slmp.json \
  "${BIN}/sensor_demo" "${ROOT}/config/demo.sensor.slmp.json" \
  >"${LOGDIR}/sensor-slmp.log" 2>&1 &
PIDS+=($!)
sleep 0.5
if SENSOR_STATE=/tmp/fieldbus-sensor-slmp.json \
  "${BIN}/pool_master" --proto slmp --host 127.0.0.1 --port 15000 --seconds 4 \
  --state /tmp/fieldbus-sensor-slmp.json \
  >"${LOGDIR}/master-slmp.log" 2>&1; then
  ok "slmp live data (PLC stand-in; not a CODESYS protocol)"
else
  ng "slmp live data"
  tail -n 40 "${LOGDIR}/master-slmp.log" || true
  tail -n 20 "${LOGDIR}/sensor-slmp.log" || true
  tail -n 20 "${LOGDIR}/slmp-plc.log" || true
fi
kill "${PIDS[-1]}" 2>/dev/null || true
wait "${PIDS[-1]}" 2>/dev/null || true
unset 'PIDS[-1]'
kill "${PIDS[-1]}" 2>/dev/null || true
wait "${PIDS[-1]}" 2>/dev/null || true
unset 'PIDS[-1]'

# ---------- PROFINET (CODESYS Controller CM profile + live barcode) ----------
echo "=== PROFINET RT Class 1 ==="
if [[ ! -x "${BIN}/pn_codesys_beta" ]]; then
  sk "profinet" "pn_codesys_beta not built"
elif ! sudo -n true 2>/dev/null; then
  sk "profinet" "need passwordless sudo for veth/AF_PACKET"
else
  sudo ip link del pn-dev 2>/dev/null || true
  sudo ip link add pn-dev type veth peer name pn-ctl
  sudo ip addr add 192.168.10.2/24 dev pn-dev
  sudo ip addr add 192.168.10.1/24 dev pn-ctl
  sudo ip link set pn-dev up
  sudo ip link set pn-ctl up
  rm -f /tmp/fieldbus-sensor-pn.json
  SENSOR_STATE=/tmp/fieldbus-sensor-pn.json \
    sudo env SENSOR_STATE=/tmp/fieldbus-sensor-pn.json \
    "${BIN}/sensor_demo" "${ROOT}/config/demo.sensor.profinet.json" \
    >"${LOGDIR}/sensor-pn.log" 2>&1 &
  PIDS+=($!)
  sleep 0.6
  if sudo "${BIN}/pn_codesys_beta" pn-ctl sensor-line1 \
    >"${LOGDIR}/master-pn.log" 2>&1; then
    ok "profinet CODESYS-profile CM + RTC1 + BETA-PN-IN"
  else
    ng "profinet CODESYS-profile"
    tail -n 50 "${LOGDIR}/master-pn.log" || true
    tail -n 20 "${LOGDIR}/sensor-pn.log" || true
  fi
  kill "${PIDS[-1]}" 2>/dev/null || true
  sudo kill "${PIDS[-1]}" 2>/dev/null || true
  wait "${PIDS[-1]}" 2>/dev/null || true
  unset 'PIDS[-1]'
  sudo ip link del pn-dev 2>/dev/null || true
fi

# ---------- CC-Link / EtherCAT: not in this pool ----------
sk "cclink" "adapter stub, spec not frozen"
sk "ethercat" "SubDevice needs ESC ASIC"

# ---------- Real CODESYS Control SL binary (optional) ----------
echo "=== CODESYS Control SL binary ==="
if command -v codesyscontrol >/dev/null 2>&1 || [[ -x /opt/codesys/bin/codesyscontrol.bin ]]; then
  CDS_BIN="$(command -v codesyscontrol 2>/dev/null || true)"
  [[ -z "${CDS_BIN}" ]] && CDS_BIN=/opt/codesys/bin/codesyscontrol.bin
  echo "found ${CDS_BIN}"
  if ss -ltn 2>/dev/null | grep -q ':11740'; then
    ok "codesyscontrol listening 11740 (empty runtime is not a fieldbus master)"
  else
    sk "codesyscontrol live" "binary present but not listening; start with 2-hour demo"
  fi
else
  sk "codesyscontrol binary" "not installed (see tests/codesys/try_install_codesys.sh)"
fi

echo
echo "pooltest PASS=${pass} FAIL=${fail} SKIP=${skip}"
echo "logs: ${LOGDIR}"
[[ "${fail}" -eq 0 ]]
