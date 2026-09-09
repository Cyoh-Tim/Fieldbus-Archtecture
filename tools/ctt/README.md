# Controller Test Tool (CTT)

In-repo fieldbus scenario harness: **one runner**, protocol plugins.
DUT is `stacks/profinet/` (**CC-B + RT Class 1** only). CC-C / IRT are
out of scope permanently. EtherNet/IP plugin remains a reserved slot.

```
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
ctest --test-dir build --output-on-failure -LE soak_ci
```

CI uses mock Ethernet (`iface: mock`). No AF_PACKET / sudo.

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
| `tools/ctt/` | runner, report, mock eth ring, metrics |
| `tools/ctt/proto/profinet/` | Controller stub + PN steps |
| `tools/ctt/proto/ethernetip/` | reserved until `stacks/ethernetip/` lands |
| `tests/scenarios/<protocol>/` | YAML; directory matches `protocol:` |

PROFINET actions (CC-B / RTC1):

| action | Phase | notes |
|--------|-------|--------|
| `dcp_identify` / `dcp_set` | 1 | Identify.Res, Sec1 HMAC Set |
| `rpc_connect` | 1–2 | `integrity: false` reject; `integrity: true` block `0x0E01` AR up |
| `io_cycle` | 1 | RTC1 cyclic smoke + period stats |
| `rpc_release` | 2 | AR down |
| `alarm` | 2 | Device TX Alarm High (`0xFC01`); AR must be up |
| `record_read` | 2 | I&M0 index `0xAFF0` |
| `lldp` | 2 | ethertype `0x88CC`, NameOfStation |
| `snmp_get` | 2 | sysName via `pn_stack_handle_snmp` (no UDP :161) |
| `soak` | 2 | `duration_s` and/or `iterations`; unexpected frames / AR drops |

## Soak / metrics

`io_cycle` and `soak` record:

- unexpected frame count (non-RTC1, non-LLDP during soak)
- AR drop count
- cycle period min/max/avg and a coarse ms histogram (`<4,<8,<12,<16,<20,>=20`)

Logged as `LOG_INFO` `ctt` metrics at the end of the run.

| scenario | default PR `ctest` | how to run |
|----------|--------------------|------------|
| `soak_short.yaml` | yes (32 RTC1 iterations, sub-second) | `ctest -R soak_short` |
| `soak_ci.yaml` | no (`-LE soak_ci`) | `ctest -L soak_ci` or workflow_dispatch `soak=true` (~30s) |
| `nightly/soak_nightly.yaml` | no (not globbed) | `./build/ctt --scenario tests/scenarios/profinet/nightly/soak_nightly.yaml` (1h; edit `duration_s: 7200` for 2h) |
