#!/usr/bin/env python3
"""Dissect the T12-11 LLDPDU with scapy.contrib.lldp.

The C test checks the same bytes. This script is the scapy view of that
frame: Port ID ``port-001``, PNO OUI 00-0E-CF, Port Status, IEEE 802.3
MAC/PHY, and the Management Address TLV.

Usage: test_pn_t12_11_scapy.py /path/to/test_pn_t12_11
"""
import subprocess
import sys

from scapy.contrib.lldp import (
    LLDPDU,
    LLDPDUChassisID,
    LLDPDUEndOfLLDPDU,
    LLDPDUGenericOrganisationSpecific,
    LLDPDUManagementAddress,
    LLDPDUPortID,
    LLDPDUSystemName,
    LLDPDUTimeToLive,
)
from scapy.layers.l2 import Ether


def as_bytes(value):
    if isinstance(value, str):
        return value.encode()
    return bytes(value)


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: test_pn_t12_11_scapy.py <test_pn_t12_11>")
    proc = subprocess.run(
        [sys.argv[1], "--dump"], check=True, capture_output=True
    )
    pkt = Ether(proc.stdout)
    assert pkt.type == 0x88CC, hex(pkt.type)
    assert pkt.dst.lower() == "01:80:c2:00:00:0e", pkt.dst
    assert pkt.src.lower() == "02:fb:00:00:00:01", pkt.src

    layers = list(pkt[LLDPDU].iterpayloads())
    chassis = [t for t in layers if isinstance(t, LLDPDUChassisID)]
    port = [t for t in layers if isinstance(t, LLDPDUPortID)]
    ttl = [t for t in layers if isinstance(t, LLDPDUTimeToLive)]
    name = [t for t in layers if isinstance(t, LLDPDUSystemName)]
    mgmt = [t for t in layers if isinstance(t, LLDPDUManagementAddress)]
    org = [t for t in layers if isinstance(t, LLDPDUGenericOrganisationSpecific)]
    end = [t for t in layers if isinstance(t, LLDPDUEndOfLLDPDU)]

    assert len(chassis) == 1 and chassis[0].subtype == 7
    assert as_bytes(chassis[0].id) == b"sensor-line1"
    assert len(port) == 1 and port[0].subtype == 7
    assert as_bytes(port[0].id) == b"port-001"
    assert len(ttl) == 1 and ttl[0].ttl == 20
    assert len(name) == 1 and as_bytes(name[0].system_name) == b"sensor-line1"
    assert len(mgmt) == 1
    assert mgmt[0].management_address_subtype == 1
    assert as_bytes(mgmt[0].management_address) == bytes(
        [0xC0, 0xA8, 0xC8, 0x02]
    )
    assert mgmt[0].interface_numbering_subtype == 2
    assert mgmt[0].interface_number == 1
    assert as_bytes(mgmt[0].object_id) == b""

    ouis = {t.org_code for t in org}
    assert 0x000ECF in ouis, ouis
    assert 0x000CCF not in ouis, ouis
    assert 0x00120F in ouis, ouis

    def org_data(code, subtype):
        hit = [t for t in org if t.org_code == code and t.subtype == subtype]
        assert len(hit) == 1, (code, subtype, [(t.org_code, t.subtype) for t in org])
        return as_bytes(hit[0].data)

    assert org_data(0x000ECF, 2) == b"\x00\x00\x00\x00"  # Port Status OFF/OFF
    assert org_data(0x000ECF, 5) == bytes([0x02, 0xFB, 0x00, 0x00, 0x00, 0x01])
    assert org_data(0x00120F, 1) == bytes([0x03, 0x04, 0x00, 0x00, 0x10])
    assert len(end) == 1

    print("scapy LLDPDU:")
    print(f"  Chassis ID subtype {chassis[0].subtype} {as_bytes(chassis[0].id)!r}")
    print(f"  Port ID subtype {port[0].subtype} {as_bytes(port[0].id)!r}")
    print(f"  TTL {ttl[0].ttl}")
    print(f"  System Name {as_bytes(name[0].system_name)!r}")
    print(
        "  Management Address IPv4 "
        f"{as_bytes(mgmt[0].management_address).hex()} "
        f"ifsubtype {mgmt[0].interface_numbering_subtype} "
        f"ifnumber {mgmt[0].interface_number}"
    )
    for t in org:
        print(
            f"  Org {t.org_code:#08x} subtype {t.subtype} "
            f"data {as_bytes(t.data).hex()}"
        )
    print("test_pn_t12_11_scapy: OK")


if __name__ == "__main__":
    main()
