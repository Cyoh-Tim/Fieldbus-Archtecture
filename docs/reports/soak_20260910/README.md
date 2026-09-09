# soak_20260910 artifacts

Internal mock soak JSON (`ctt-report/v1`) after absolute-time soak waits.
**Not certification.** Same-class host as `soak_20260909` (shared VM, no PREEMPT_RT).

Human report: [`docs/soak_report_20260910_jitter.md`](../soak_report_20260910_jitter.md).

| file | protocol |
|------|----------|
| `modbus.json` | Modbus TCP FC03, 300 s |
| `slmp.json` | SLMP Binary 3E batch read, 300 s |
| `ethernetip.json` | EtherNet/IP Class 1, 300 s |
| `profinet.json` | PROFINET CC-B RT1, 300 s |
