# `adapters/` (Runtime Specs, Not Python Code)

This top-level directory is the runtime contract location for adapter YAML specs
(for example `adapters/target.yaml`).

It is **not** where Python adapter implementations live.

## Source Of Truth For Adapter Code

Python adapter implementations live under:
- `src/harness/adapters/`

Docs:
- `docs/ADAPTERS.md`

## Related Directories

- `templates/adapters/`: starter YAML templates you can copy/adapt.
- `adapters/platform/`: platform-specific scaffolding (not a Python runtime package).
