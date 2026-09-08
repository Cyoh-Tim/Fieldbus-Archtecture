#!/usr/bin/env bash
# Install CODESYS Control for Linux SL (2-hour demo) + Edge Gateway.
# Requires CODESYS_STORE_EMAIL / CODESYS_STORE_PASSWORD.
# Does not commit binaries. Not released for VMs; demo still starts.
# PID 1 may not be systemd — start CodeMeter / Control / Gateway directly.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CACHE="${CODESYS_CACHE:-$HOME/.cache/codesys-store}"
mkdir -p "${CACHE}"

if [[ -z "${CODESYS_STORE_EMAIL:-}" || -z "${CODESYS_STORE_PASSWORD:-}" ]]; then
  echo "set CODESYS_STORE_EMAIL and CODESYS_STORE_PASSWORD" >&2
  exit 2
fi

python3 "${ROOT}/tests/codesys/download_codesys_store.py"

# WIBU CodeMeter-lite (runtime dependency). Brackets in the query must be encoded.
CM_DEB="${CACHE}/codemeter-lite.deb"
if [[ ! -f "${CM_DEB}" ]]; then
  echo "fetch CodeMeter-lite"
  curl -fsSL -o "${CM_DEB}" \
    "https://www.wibu.com/support/user/user-software/file/download/17974.html?tx_wibudownloads_downloadlist%5BdirectDownload%5D=directDownload&tx_wibudownloads_downloadlist%5BuseAwsS3%5D=0" \
    || echo "WARN CodeMeter download failed (continuing)"
fi

if [[ -f "${CM_DEB}" ]]; then
  sudo dpkg -i "${CM_DEB}" || sudo apt-get install -y -f || true
fi

mapfile -t DEBS < <(find "${CACHE}/deb" -name '*amd64*.deb' 2>/dev/null | sort || true)
if [[ ${#DEBS[@]} -eq 0 ]]; then
  echo "no CODESYS amd64 debs extracted — store download did not yield packages" >&2
  exit 3
fi

echo "installing ${#DEBS[@]} amd64 debs"
sudo dpkg -i "${DEBS[@]}" || sudo apt-get install -y -f

listening() {
  ss -ltn 2>/dev/null | grep -q ":${1} "
}

start_codemeter() {
  if listening 22350; then
    echo "CodeMeter already listening 22350"
    return
  fi
  if [[ -x /etc/init.d/codemeter ]]; then
    sudo /etc/init.d/codemeter start || true
  fi
  if ! listening 22350 && [[ -x /usr/sbin/CodeMeterLin ]]; then
    sudo /usr/sbin/CodeMeterLin >/dev/null 2>&1 &
    disown || true
  fi
  sleep 1
  if listening 22350; then
    echo "CodeMeter listening 22350"
  else
    echo "WARN CodeMeter did not bind 22350" >&2
  fi
}

ensure_user_cfg() {
  sudo mkdir -p /etc/codesyscontrol
  if ! sudo test -f /etc/codesyscontrol/CODESYSControl_User.cfg; then
    sudo tee /etc/codesyscontrol/CODESYSControl_User.cfg >/dev/null <<'CFG'
[SysEthernet]
Linux.PACKET_QDISC_BYPASS=1
Linux.ProtocolFilter=3
CFG
  elif ! sudo grep -q 'Linux.ProtocolFilter' /etc/codesyscontrol/CODESYSControl_User.cfg; then
    sudo tee -a /etc/codesyscontrol/CODESYSControl_User.cfg >/dev/null <<'CFG'

[SysEthernet]
Linux.PACKET_QDISC_BYPASS=1
Linux.ProtocolFilter=3
CFG
  fi
}

start_direct() {
  local name="$1" bin="$2" cfg="$3" lib="$4" port="$5" workdir="$6"
  if listening "${port}"; then
    echo "${name} already listening ${port}"
    return
  fi
  if [[ ! -x "${bin}" ]]; then
    echo "${name}: ${bin} not found" >&2
    return 1
  fi
  sudo mkdir -p "${workdir}"
  echo "starting ${name} (2-hour demo, no systemd)"
  # cwd must not be the git worktree — Control writes codesyscontrol.log / .pki there.
  sudo bash -c "cd '${workdir}' && exec env LD_LIBRARY_PATH='${lib}' '${bin}' '${cfg}'" \
    >/dev/null 2>&1 &
  disown || true
  sleep 2
  if listening "${port}"; then
    echo "${name} listening ${port}"
  else
    echo "WARN ${name} did not bind ${port}" >&2
  fi
}

start_codemeter
ensure_user_cfg

if [[ -x /opt/codesys/bin/codesyscontrol.bin ]]; then
  start_direct codesyscontrol \
    /opt/codesys/bin/codesyscontrol.bin \
    /etc/codesyscontrol/CODESYSControl.cfg \
    /opt/codesys/lib \
    11740 \
    /var/opt/codesys
else
  echo "codesyscontrol.bin not found after dpkg" >&2
  ls -la /opt/codesys/bin 2>/dev/null || true
  exit 4
fi

if [[ -x /opt/codesysedge/bin/codesysedge.bin ]]; then
  start_direct codesysedge \
    /opt/codesysedge/bin/codesysedge.bin \
    /etc/codesysedge/Gateway.cfg \
    /opt/codesysedge/lib \
    1217 \
    /var/opt/codesysedge
fi

ss -ltn | grep -E '11740|1217|4840|22350' || true
echo "empty Control SL is not a PN/Modbus/EIP master until an IEC app is downloaded from Windows CODESYS Development System."
