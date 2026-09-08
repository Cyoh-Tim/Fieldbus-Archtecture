#!/usr/bin/env bash
# Try to install CODESYS Control for Linux SL (2-hour demo) + Edge Gateway.
# Requires CODESYS_STORE_EMAIL / CODESYS_STORE_PASSWORD.
# Does not commit binaries. Not released for VMs; may still start a demo.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE="${CODESYS_CACHE:-$HOME/.cache/codesys-store}"
mkdir -p "${CACHE}"

if [[ -z "${CODESYS_STORE_EMAIL:-}" || -z "${CODESYS_STORE_PASSWORD:-}" ]]; then
  echo "set CODESYS_STORE_EMAIL and CODESYS_STORE_PASSWORD" >&2
  exit 2
fi

python3 "${ROOT}/tests/codesys/download_codesys_store.py"

# WIBU CodeMeter-lite (runtime dependency), official user download.
CM_DEB="${CACHE}/codemeter-lite.deb"
if [[ ! -f "${CM_DEB}" ]]; then
  echo "fetch CodeMeter-lite"
  curl -fsSL -o "${CM_DEB}" \
    "https://www.wibu.com/support/user/user-software/file/download/17974.html?tx_wibudownloads_downloadlist[directDownload]=directDownload&tx_wibudownloads_downloadlist[useAwsS3]=0" \
    || echo "WARN CodeMeter download failed (continuing)"
fi

if [[ -f "${CM_DEB}" ]]; then
  sudo dpkg -i "${CM_DEB}" || sudo apt-get install -y -f || true
fi

mapfile -t DEBS < <(find "${CACHE}/deb" -name '*.deb' 2>/dev/null | sort || true)
if [[ ${#DEBS[@]} -eq 0 ]]; then
  echo "no CODESYS debs extracted — store download did not yield packages" >&2
  exit 3
fi

echo "installing ${#DEBS[@]} debs"
sudo dpkg -i "${DEBS[@]}" || sudo apt-get install -y -f

# Start without systemd if needed
if command -v service >/dev/null; then
  sudo service codemeter start 2>/dev/null || sudo /etc/init.d/codemeter start || true
fi

if [[ -x /opt/codesys/bin/codesyscontrol.bin ]]; then
  echo "starting codesyscontrol (2-hour demo)"
  sudo mkdir -p /etc/codesyscontrol
  if [[ ! -f /etc/codesyscontrol/CODESYSControl_User.cfg ]]; then
    sudo tee /etc/codesyscontrol/CODESYSControl_User.cfg >/dev/null <<'CFG'
[SysEthernet]
Linux.PACKET_QDISC_BYPASS=1
Linux.ProtocolFilter=3
CFG
  fi
  sudo pkill -f codesyscontrol.bin 2>/dev/null || true
  sudo env LD_LIBRARY_PATH=/opt/codesys/lib \
    /opt/codesys/bin/codesyscontrol.bin /etc/codesyscontrol/CODESYSControl.cfg \
    >"${CACHE}/codesyscontrol.log" 2>&1 &
  sleep 2
  ss -ltn | grep -E '11740|1217|4840' || true
  echo "codesyscontrol started (demo). empty runtime is not a PN/Modbus/EIP master until an IEC app is downloaded."
else
  echo "codesyscontrol.bin not found after dpkg" >&2
  ls -la /opt/codesys/bin 2>/dev/null || true
  exit 4
fi
