# EtherNet/IP CTT plugin

Scanner/Originator stub for the self-hosted Adapter DUT in
`stacks/ethernetip/`. Selected by `protocol: ethernetip` on the same
`./build/ctt` binary.

**DUT is not** `adapters/ethernetip/` (daemon adapter). CTT talks to the
self-hosted stack directly.

```
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON
cmake --build build
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
./build/ctt --scenario tests/scenarios/ethernetip/list_services.yaml
./build/ctt --scenario tests/scenarios/ethernetip/large_forward_open.yaml
ctest --test-dir build --output-on-failure -L ethernetip
```

Mock only (`eip_cfg_t.mock=1`, `eip_stack_handle_encap` / `handle_io`).
No NIC / AF_PACKET for CIP TCP in this plugin.

Actions include `list_services` (Encaps `0x0004`) and `forward_open`
with `large: true` (CIP `0x5B`). ListInterfaces is not implemented on the DUT.

Internal ODVA CT-style mapping: `docs/ctt_odva_matrix.md` (not official CT).
Internal bundle-grade catalog: `docs/ctt_eip_bundle.md` (`EIP-A-*`, not certification).
