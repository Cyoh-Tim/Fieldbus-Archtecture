# Checked-in PROFINET goldens (mock)

PCAP frames captured from `./build/ctt --transport=mock`. No NIC.

| file | scenario step |
|------|----------------|
| `dcp_identify_res.pcap` | Identify.Res (`0xFEFF`) |
| `dcp_set_sec_class1_accept.pcap` | signed DCP Set.Res accept |

Regenerate: `tests/regen_ctt_goldens.sh` (see `docs/ctt_lab.md`).
