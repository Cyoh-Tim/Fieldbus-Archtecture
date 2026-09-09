# EtherNet/IP CTT scenarios

`protocol: ethernetip`. DUT is `stacks/ethernetip/` (self stack).
Purchased-stack adapter stub is not a DUT.

```
./build/ctt --scenario tests/scenarios/ethernetip/register_session.yaml
ctest --test-dir build --output-on-failure -L ethernetip
```

Migrated from `tests/test_eip_stack.c` (HMAC stays in `tests/test_eip_crypto.c`).
