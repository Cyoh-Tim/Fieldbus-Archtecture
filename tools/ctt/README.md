# Controller Test Tool (CTT)

In-repo fieldbus scenario harness: **one runner**, protocol plugins.
Phase 1 DUT is `stacks/profinet/` (**CC-B + RT Class 1** only). CC-C / IRT are
out of scope permanently.

```
./build/ctt --scenario tests/scenarios/profinet/dcp_identify_name_of_station.yaml
ctest --test-dir build --output-on-failure
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
| `tools/ctt/` | runner, report, mock eth ring |
| `tools/ctt/proto/profinet/` | Controller stub + PN steps |
| `tools/ctt/proto/ethernetip/` | reserved until `stacks/ethernetip/` lands |
| `tests/scenarios/<protocol>/` | YAML; directory matches `protocol:` |

Phase 1 actions: `dcp_identify`, `dcp_set`, `rpc_connect`, `io_cycle`.
