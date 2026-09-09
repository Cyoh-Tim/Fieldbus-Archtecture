# EtherNet/IP CTT scenarios

`protocol: ethernetip`. DUT is `stacks/ethernetip/` (self stack).
Purchased-stack adapter stub is not a DUT.

Internal bundle-grade catalog: `docs/ctt_eip_bundle.md` (`EIP-A-*`).
**Internal gate ≠ ODVA CT / certification.**

```
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
./build/ctt --scenario tests/scenarios/ethernetip/class1_cyclic_metrics.yaml \
    --report /tmp/eip-a-cyc-002.json
ctest --test-dir build --output-on-failure -L ethernetip
```

Migrated from `tests/test_eip_stack.c` (HMAC stays in `tests/test_eip_crypto.c`).
