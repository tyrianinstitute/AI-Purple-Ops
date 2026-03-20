# Changelog

All notable changes to AI Purple Ops will be documented in this file.

## 0.5.0-rc.1 (2026-03-19) - Fix the Foundation

The foundation was broken. Install didn't work, the package name was wrong,
and there were no regression tests to catch it. Fixed all three.

### Fixed
- Package dependencies were under `[project.urls]` instead of `[project]` — pip silently ignored them
- Killed the `all-official` meta-extra that asked for two incompatible `fschat` pins
- Updated package description from "vendor-neutral harness" to something that actually describes the tool

### Changed
- Renamed package from `harness` to `aipop` — the brand and the code finally agree
- All 377 files updated: imports, monkeypatches, docs, tests, entry points
- Version bumped from 0.1.0 to 0.5.0-rc.1 (SemVer inside v1 until ecosystem graduation)

### Added
- Install smoke tests — catches pyproject.toml regressions before they hit users
- Golden master regression tests — 23 tests snapshotting CLI behavior before the S1 engine extraction

---

## 0.1.0 (2026-03-13) - Fresh Start

Reset to 0.1.0 after codebase cleanup. The previous version numbers (1.0.0–1.2.5)
were inflated and did not reflect production readiness. This is the honest baseline.

### What exists and works

- CLI entrypoint (`aipop`) with Typer-based command structure
- 8 adapters: OpenAI, Anthropic, HuggingFace, Ollama, LlamaCpp, Bedrock, MCP, Mock
- Protocol-based core architecture (Adapter, Runner, Reporter, Gate, Detector)
- YAML-based test suites (10+ suites, 140+ test cases)
- Recipe engine for workflow orchestration
- Policy detectors (HarmfulContent, ToolPolicy)
- Quality gates with threshold enforcement
- Evidence pack generation (JSON, JUnit, ZIP)
- GCG, AutoDAN, PAIR attack methods (legacy + plugin modes)
- PyRIT orchestrator integration with multi-turn verification
- MCP adapter with HTTP, stdio, WebSocket transports
- DuckDB-backed caching and session storage
- 753 tests passing, 34 skipped

### Cleanup performed in this release

- Deleted dead code: empty stubs, placeholder dirs, unreachable legacy modules
- Consolidated package sprawl: merged `reporting/` into `reporters/`, `engines/` into `mutators/`, `output/` into `ctf/`
- Moved torch to optional `[adversarial]` extra (saves ~2 GB for users who don't need it)
- Fixed broken CI workflow
- Removed redundant pre-commit hooks
- Deleted 8 stale doc files referencing unbuilt features
- Fixed docs to only reference things that actually exist
- Added `.env.example` (was referenced but missing)
- Auto-fixed lint and formatting across entire codebase

### Known issues

- `cli/` moved into `src/aipop/cli/` with all imports updated
- Heavy dependency footprint (PyRIT, DuckDB, scipy, pygad) for a CLI tool
- Some CLI commands reference features that are partially wired up
- No automated integration tests against real model APIs
