#!/usr/bin/env bash
# Full lab pretest for the PROFINET Device stack.
# Official PI Test Bundle (ART/SPIRTA/ETS) is member-only and Windows/ETS based.
# Member zip stays locked until PI maps the company account; this script is the
# in-tree substitute:
#   1) unit tests (mock Ethernet)
#   2) GSDML well-formed + required DAP/PDev fields
#   3) on-wire RT Device groups over veth (DCP/LLDP/SNMP/CM/RTC1)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${ROOT}/build"
GSD="${ROOT}/stacks/profinet/gsdml/GSDML-V2.35-Fieldbus-PN-Device.xml"
DEV_IF="${PN_DEV_IF:-pn-dev}"
CTL_IF="${PN_CTL_IF:-pn-ctl}"
DEV_IP="${PN_DEV_IP:-192.168.10.2}"
CTL_IP="${PN_CTL_IP:-192.168.10.1}"
FAIL=0

echo "======== 1/3 unit (test_pn_stack) ========"
if [[ ! -x "${BIN}/test_pn_stack" ]]; then
  echo "build test_pn_stack first" >&2
  exit 1
fi
"${BIN}/test_pn_stack" || FAIL=1

echo "======== 2/3 GSDML ========"
if xmllint --noout "${GSD}"; then
  echo "PASS  LAB-GSD-XML  well-formed"
else
  echo "FAIL  LAB-GSD-XML  well-formed"
  FAIL=1
fi
python3 - "${GSD}" <<'PY' || FAIL=1
import sys
from xml.etree import ElementTree as ET
path = sys.argv[1]
ns = {"g": "http://www.profibus.com/GSDML/2003/11/DeviceProfile"}
root = ET.parse(path).getroot()
ident = root.find(".//g:DeviceIdentity", ns)
ok = True
def chk(cond, cid, msg):
    global ok
    print(("PASS" if cond else "FAIL") + f"  {cid}  {msg}")
    if not cond:
        ok = False
chk(ident is not None and ident.get("VendorID") == "0xABCD"
    and ident.get("DeviceID") == "0x0001",
    "LAB-GSD-IDENT", "VendorID/DeviceID")
text = ET.tostring(root, encoding="unicode")
chk("MinDeviceInterval=\"256\"" in text, "LAB-GSD-MDI", "MinDeviceInterval=256 (8 ms)")
chk("SubslotNumber=\"32768\"" in text and "SubslotNumber=\"32769\"" in text,
    "LAB-GSD-PDEV", "Interface 0x8000 / Port 0x8001")
chk("RT_CLASS_1" in text, "LAB-GSD-RT1", "SupportedRT_Classes includes RT_CLASS_1")
chk("IsochroneModeSupported=\"false\"" in text, "LAB-GSD-NO-IRT",
    "IsochroneModeSupported=false")
chk("SupportedProtocols=\"SNMP;LLDP\"" in text, "LAB-GSD-PROTO",
    "SupportedProtocols SNMP;LLDP")
chk("SupportedMibs=\"MIB2\"" in text, "LAB-GSD-MIB2", "SupportedMibs=MIB2")
chk("NumberOfAR=\"1\"" in text, "LAB-GSD-AR", "NumberOfAR=1")
chk("DNS_CompatibleName=" in text, "LAB-GSD-DNS", "DNS_CompatibleName present")
sys.exit(0 if ok else 1)
PY

echo "======== 3/3 on-wire PI lab pretest (veth) ========"
if [[ ! -x "${BIN}/pn_device_run" || ! -x "${BIN}/pn_pi_pretest" ]]; then
  echo "build pn_device_run / pn_pi_pretest first" >&2
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

sudo "${BIN}/pn_device_run" "${DEV_IF}" "${DEV_IP}" 45 &
DEV_PID=$!
sleep 0.5

if ! sudo "${BIN}/pn_pi_pretest" "${CTL_IF}" sensor-line1; then
  FAIL=1
fi

echo "======== summary ========"
if [[ "${FAIL}" -ne 0 ]]; then
  echo "FULLTEST FAILED (not a PI certificate; lab pretest only)"
  exit 1
fi
echo "FULLTEST PASSED (lab pretest; ART/PITL not available in this environment)"
