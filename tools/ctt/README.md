# Controller Test Tool (CTT)

In-repo fieldbus scenario harness: **one runner**, protocol plugins.
DUT is `stacks/profinet/` (**CC-B + RT Class 1** only),
`stacks/ethernetip/` (Adapter Class 1, mock), **Modbus TCP**
(`stacks/modbus/`), and **SLMP Binary 3E** (`stacks/slmp/`). CC-C / IRT
are out of scope permanently. Purchased EIP stub is not a CTT DUT.

```
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
./build/ctt --scenario tests/scenarios/modbus/fc03_read_holding.yaml
./build/ctt --scenario tests/scenarios/slmp/encode_batch_read.yaml
./build/ctt --scenario tests/scenarios/modbus/fc03_cyclic_metrics.yaml \
    --report /tmp/mb-t-cyc-002.json
ctest --test-dir build --output-on-failure -LE soak_ci
ctest --test-dir build --output-on-failure -L ethernetip
ctest --test-dir build --output-on-failure -L modbus
ctest --test-dir build --output-on-failure -L slmp
ctest --test-dir build --output-on-failure -L profinet
```

CI uses mock Ethernet (`iface: mock`). No AF_PACKET / sudo.

Lab (optional, not default `ctest`):

```
./build/ctt --transport=af_packet --iface=ctt-ctl --dut-iface=ctt-dut \
    --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
tests/run_ctt_lab.sh
```

See `docs/ctt_lab.md`. CMake `-DENABLE_CTT_AF_PACKET=ON` (default) compiles the
path; default `ctest` never opens a raw socket.

Golden replay (mock, in default `ctest`): YAML `golden:` →
`tests/golden/profinet/*.pcap`. Regenerate:

```
tests/regen_ctt_goldens.sh
```


## YAML subset

Scenarios are parsed by a **vendored subset parser** (`yaml_mini.c`), not
libyaml / FetchContent. No network is required at configure or test time.

Supported:

- block mappings and sequences (spaces only; typical 2-space indent)
- scalars: unquoted, `"double"` / `'single'` quoted
- integers (`42`, `0xFEFF`), booleans `true` / `false`
- `#` comments
- `tags: [a, b]` kept as a single scalar (runner ignores tags)

Not supported: anchors, tags (`!!`), multiline `|` / `>`, merge keys, tabs.

`protocol:` selects the plugin. Unknown keys under `device` / `steps` are owned
by the plugin. The common runner does not parse DCP/CIP frames.

## Layout

| Path | Role |
|------|------|
| `tools/ctt/` | runner, report, mock eth ring, **AF_PACKET lab transport**, PCAP golden |
| `tools/ctt/proto/profinet/` | Controller stub + PN steps |
| `tools/ctt/proto/ethernetip/` | Scanner stub + EIP steps (`stacks/ethernetip/` DUT) |
| `tools/ctt/proto/modbus/` | Modbus TCP client stub (`mb_stack_handle_adu`) |
| `tools/ctt/proto/slmp/` | SLMP Binary 3E stub (`slmp_stack_handle_request`) |
| `tests/scenarios/<protocol>/` | YAML; `protocol:` is `profinet` / `ethernetip` / `modbus_tcp` / `slmp` |
| `docs/ctt_pn_bundle.md` | PN internal bundle-grade roadmap + TC IDs (**≠ PI cert**) |
| `docs/ctt_eip_bundle.md` | EIP internal bundle-grade roadmap + TC IDs (**≠ ODVA CT**) |
| `docs/ctt_mb_bundle.md` | Modbus internal bundle-grade roadmap + TC IDs (**≠ Modbus.org**) |
| `docs/ctt_slmp_bundle.md` | SLMP internal bundle-grade roadmap + TC IDs (**≠ Mitsubishi cert**) |
| `docs/ctt_pi_matrix.md` | CC-A/B internal mapping (not certification) |
| `docs/ctt_odva_matrix.md` | EIP internal CT-style mapping (not official CT) |
| `docs/ctt_modbus_matrix.md` | Modbus FC coverage (not Modbus.org cert) |
| `docs/ctt_slmp_matrix.md` | SLMP 3E coverage (not Mitsubishi cert) |
| `tests/golden/profinet/` | mock PCAPs for `golden:` replay |
| `docs/ctt_lab.md` | veth / CODESYS / `pn_device_run` |
| `docs/ctt_board.html` | scenario status board (pass / skip / gap / out of scope; not cert) |

PROFINET actions (CC-B / RTC1):

| action | notes |
|--------|--------|
| `dcp_identify` / `dcp_get` / `dcp_set` | Identify.Res, Get.Res, Sec1 HMAC Set |
| `dcp_set_ip` | DCP Set IP + DUT Hello (`0xFEFC`) |
| `dcp_signal` | Control/Signal Set (LED stub) |
| `dcp_hello` | DUT Hello TX helper |
| `rpc_connect` | mock: `handle_rpc`. lab + `device.ip`: UDP 34964 |
| `rpc_write` / `rpc_control` / `rpc_application_ready` | Write, ParameterEnd, Device AppReady indication |
| `rpc_release` | AR down |
| `rpc_inject` | raw `pdu_hex` or `opcode` — malformed / unknown CM (fail closed) |
| `io_cycle` | RTC1 cyclic + period / late / missed / jitter vs `cycle_us` |

Modbus TCP (`protocol: modbus_tcp`): `seed`, `request` (FC 01–06, 0F, 10, 16, 17),
`map_check`, `adu_inject` (`pdu_hex` — truncated / bad MBAP fail closed),
`soak` (late/missed/jitter vs `cycle_us`). Inject via `mb_stack_handle_adu`
(no :502).

SLMP (`protocol: slmp`, Binary 3E only): `device_lookup`, `encode_batch_read` /
`encode_batch_write`, `batch_read` / `batch_write`, `seed_words` / `seed_bits`,
`map_check_*`, `inject` (`pdu_hex` or subheader/cmd), `soak` (late/missed/jitter
vs `cycle_us`), `create_stack` (ASCII/4E reject).
4E/ASCII are out of scope.

EtherNet/IP actions (mock `eip_cfg_t.mock`; no NIC):

| action | notes |
|--------|--------|
| `register_session` / `list_identity` | Encapsulation |
| `get_attr` | UCMM Get_Attribute_Single (`class_id`, `instance`, `attribute`) |
| `write_input` / `read_input` / `read_output` | Assembly image |
| `forward_open` | `integrity: true` adds CPF `0x00C1` HMAC; `integrity: bad` flips MAC |
| `forward_close` | CM Forward Close (serial/vendor/orig from last FO) |
| `encap_inject` | raw `pdu_hex` or `cmd` — truncated / unknown Encaps (fail closed) |
| `class1_io` / `io_cycle` | O→T inject; produce via transport ops. `io_cycle` records late/missed/jitter vs `rpi_us`/`cycle_us`. `require_class1: false` for NEG |
| `acd_conflict` / `lldp` / `watchdog` / `poll` | ACD, LLDP TX, Class 1 timeout |

## Soak / metrics

`io_cycle` and `soak` record:

- unexpected frame count (non-RTC1, non-LLDP during soak)
- AR drop count
- cycle count (`rtc1_frames`), late / missed vs `device.cycle_us` (1.5x / 2.5x)
- `jitter_max_ns` = max `|dt - cycle_ns|`
- coarse ms histogram (`<4,<8,<12,<16,<20,>=20`)

Logged as `LOG_INFO` `ctt` metrics at the end of the run. Machine-readable
summary: `./build/ctt --scenario <yaml> --report out.json` (`ctt-report/v1`).
Internal gate, not PI / ODVA / Modbus.org / Mitsubishi certification. See
`docs/ctt_pn_bundle.md`, `docs/ctt_eip_bundle.md`, `docs/ctt_mb_bundle.md`,
`docs/ctt_slmp_bundle.md`.

YAML top-level `id:` / `bundle_id:` / `suite:` are copied into the report
(`tc_id`, `suite_id`).

| scenario | default PR `ctest` | how to run |
|----------|--------------------|------------|
| `rtc1_cyclic_metrics.yaml` | yes (48 RTC1 cycles + late/missed/jitter) | `ctest -R rtc1_cyclic_metrics` |
| `class1_cyclic_metrics.yaml` | yes (48 Class1 cycles + late/missed/jitter) | `ctest -R class1_cyclic_metrics` |
| `fc03_cyclic_metrics.yaml` | yes (48 FC03 cycles + late/missed/jitter) | `ctest -R fc03_cyclic_metrics` |
| `batch_cyclic_metrics.yaml` | yes (48 SLMP batch cycles + late/missed/jitter) | `ctest -R batch_cyclic_metrics` |
| `soak_short.yaml` | yes (32 iterations, sub-second; PN/MB/SLMP) | `ctest -R soak_short` |
| Identify / Sec1 Set `golden:` | yes (mock PCAP replay, no NIC) | `ctest -L golden` |
| `soak_ci.yaml` | no (`-LE soak_ci`) | `ctest -L soak_ci` or workflow_dispatch `soak=true` (~30s) |
| `nightly/soak_nightly.yaml` | no (not globbed) | `./build/ctt --scenario tests/scenarios/profinet/nightly/soak_nightly.yaml` (1h; edit `duration_s: 7200` for 2h) |
| lab veth | no (needs CAP_NET_RAW) | `tests/run_ctt_lab.sh` or workflow_dispatch `lab=true` |
