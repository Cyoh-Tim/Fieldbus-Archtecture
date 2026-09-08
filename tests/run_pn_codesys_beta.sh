#!/usr/bin/env bash
# CODESYS Control SL 2-hour demo profile against this Device (veth).
# Not the CODESYS binary — Store package + Windows IDE are not in this VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/build"
DEV_IF="${PN_DEV_IF:-pn-dev}"
CTL_IF="${PN_CTL_IF:-pn-ctl}"
DEV_IP="${PN_DEV_IP:-192.168.10.2}"
CTL_IP="${PN_CTL_IP:-192.168.10.1}"

if [[ ! -x "${BIN}/pn_device_run" || ! -x "${BIN}/pn_codesys_beta" ]]; then
  echo "build pn_device_run / pn_codesys_beta first" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${DEV_PID:-}" ]]; then
    sudo kill "${DEV_PID}" 2>/dev/null || true
    wait "${DEV_PID}" 2>/dev/null || true
  fi
  sudo ip link del "${DEV_IF}" 2>/dev/null || true
}
trap cleanup EXIT

sudo ip link del "${DEV_IF}" 2>/dev/null || true
sudo ip link add "${DEV_IF}" type veth peer name "${CTL_IF}"
sudo ip addr add "${DEV_IP}/24" dev "${DEV_IF}"
sudo ip addr add "${CTL_IP}/24" dev "${CTL_IF}"
sudo ip link set "${DEV_IF}" up
sudo ip link set "${CTL_IF}" up

sudo env PN_BETA_IO=1 "${BIN}/pn_device_run" "${DEV_IF}" "${DEV_IP}" 20 &
DEV_PID=$!
sleep 0.5

sudo "${BIN}/pn_codesys_beta" "${CTL_IF}" sensor-line1
