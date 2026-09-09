# EtherNet/IP CTT plugin (reserved)

Phase 1–2 do **not** implement this plugin.

DUT will be the self-hosted Adapter stack in `stacks/ethernetip/` after that
tree merges (draft PR #4). `adapters/ethernetip/` (purchased-stack stub) is
not a CTT DUT.

When implemented: Scanner/Originator stub + `tests/scenarios/ethernetip/*.yaml`,
selected by `protocol: ethernetip` on the same `./build/ctt` binary.
