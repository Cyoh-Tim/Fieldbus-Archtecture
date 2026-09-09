# Checked-in PROFINET goldens (mock)

PCAP frames captured from `./build/ctt --transport=mock`. No NIC.

| file | scenario step |
|------|----------------|
| `dcp_identify_res.pcap` | Identify.Res (`0xFEFF`) |
| `dcp_set_sec_class1_accept.pcap` | signed DCP Set.Res accept |
| `dcp_get_res.pcap` | Get.Res (`0xFEFD`) |
| `dcp_hello.pcap` | Hello.Req TX (`0xFEFC`) |
| `dcp_signal_accept.pcap` | Signal Set.Res accept |
| `dcp_hello_after_set_ip.pcap` | Hello after DCP Set IP |
| `alarm_low.pcap` | Alarm Low (`0xFE01`) |

Regenerate: `tests/regen_ctt_goldens.sh` (see `docs/ctt_lab.md`).
