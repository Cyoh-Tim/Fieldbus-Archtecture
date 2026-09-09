# SLMP CTT plugin (Binary 3E)

DUT is the self-hosted stack in `stacks/slmp/` (same tree as the daemon
adapter). Plugin is a Binary 3E client stub: encode batch read/write
(`0x0401` / `0x1401`) and inject via `slmp_stack_handle_request` (no TCP,
no PLC).

Selected by `protocol: slmp`. ASCII and 4E frames are **not implemented**
(`slmp_stack_create` rejects them; inject of a non-`0x0050` subheader
fails). Random R/W commands are not in the product scope.

Not Mitsubishi formal certification.
