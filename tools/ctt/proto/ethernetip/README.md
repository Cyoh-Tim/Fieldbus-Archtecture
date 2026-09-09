# EtherNet/IP CTT plugin

Scanner/Originator stub for the self-hosted Adapter DUT in
`stacks/ethernetip/`. Selected by `protocol: ethernetip` on the same
`./build/ctt` binary.

**DUT is not** `adapters/ethernetip/` purchased-stack stub.

```
cmake -S . -B build -DBUILD_DAEMON=OFF -DBUILD_CTT=ON
cmake --build build
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
ctest --test-dir build --output-on-failure -L ethernetip
```

Mock only (`eip_cfg_t.mock=1`, `eip_stack_handle_encap` / `handle_io`).
No NIC / AF_PACKET for CIP TCP in this plugin.

Internal ODVA CT-style mapping: `docs/ctt_odva_matrix.md` (not official CT).
