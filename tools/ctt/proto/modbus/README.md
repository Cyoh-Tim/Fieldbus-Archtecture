# Modbus TCP CTT plugin

DUT is the self-hosted stack in `stacks/modbus/` (draft PR #2), **not**
libmodbus. Plugin is a Modbus TCP client stub: it assembles MBAP+PDU and
injects via `mb_stack_handle_adu` (no listen socket, no NIC).

Selected by `protocol: modbus_tcp` on the same `./build/ctt` binary.
Scenarios live in `tests/scenarios/modbus/` (directory name; protocol field
matches daemon config).

RTU is out of scope. Official Modbus.org conformance is not a goal.
