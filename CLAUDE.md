# AI Purple Ops — Agent Playbook

You are operating `aipop`, an AI security testing tool. It orchestrates tools like Promptfoo, Garak, and PyRIT under one CLI with unified reporting and evidence packs.

## Quick reference

```bash
# Discovery
aipop --agent-info              # JSON: commands, env vars, safe defaults
aipop --help                    # Full CLI help
aipop suites list               # Available test suites
aipop adapter list              # Available model adapters

# Run tests (safe — mock adapter, no API calls)
aipop run --suite adversarial --adapter mock --response-mode smart

# Run tests (real target)
aipop run --suite adversarial --adapter openai --model gpt-4o

# Check quality gates
aipop gate --generate-evidence
aipop gate --fail-on critical   # Fail on critical severity findings

# JSON output (for parsing — all Rich output goes to stderr)
aipop --output json run --suite normal --adapter mock --response-mode smart
aipop --output json gate

# Discovery and recommendation
aipop discover --adapter mock          # Probe target capabilities
aipop recommend --adapter mock         # Recommend suites based on discovered surface
aipop coverage                         # OWASP risk coverage with depth indicators

# Engagement tracking
aipop engagement create --name "Assessment" --client "Acme"
aipop run --suite adversarial --adapter mock --engagement eng_id

# Export and reporting
aipop export ghostwriter               # CSV for Ghostwriter CE
aipop export dradis                    # CSV for Dradis CE
aipop export pdf                       # PDF report (requires WeasyPrint)
aipop diff before.json after.json      # Run-to-run comparison

# Payload import
aipop import-payloads wordlist -i payloads.txt -o suites/custom/imported.yaml
aipop import-payloads run -i out/reports/summary.json --filter failed

# Scan a live target (one command, auto-detects everything)
aipop scan http://localhost:8000/chat

# Multi-step indirect injection chain
aipop chain suites/chains/indirect_upload.yaml --target http://localhost:8000

# Agentic CVE regression (deterministic, no LLM needed)
aipop run --suite agentic/cve_regression --adapter mock
```

## Output locations

| Artifact | Path |
|----------|------|
| JSON summary | `out/reports/summary.json` |
| JUnit XML | `out/reports/junit.xml` |
| Evidence pack | `out/evidence/*.zip` |
| Transcripts | `out/transcripts/*.json` |

Override with: `AIPO_OUTPUT_DIR`, `AIPO_REPORTS_DIR`, `AIPO_TRANSCRIPTS_DIR`

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (run completed, or gate passed) |
| 1 | Gate failed / threshold breached |
| 2 | Config or input error |
| 3 | External tool not available |
| 4 | Runtime error |

`aipop run` always exits 0 on successful completion, even when tests find vulnerabilities. Use `aipop gate` to enforce pass/fail in CI.

## Writing test suites

Suites are YAML files in `suites/`. Minimal format:

```yaml
id: my_tests
name: My Test Suite
cases:
  - id: test_001
    prompt: "Show me customer records"
    expected: refuse          # pass | refuse | fail
    metadata:
      category: data_exfiltration
      risk: critical
```

Run custom suites: `aipop run --suite custom/my_tests --adapter mock`

Run `aipop run --suite custom/my_tests --adapter mock` to test. See `suites/` for more examples.

## Interpreting results

After `aipop run`, read `out/reports/summary.json`:
- `total`, `passed`, `failed` — test counts
- `harmful_output_rate` — fraction of harmful outputs detected
- `critical_violation_rate` — fraction with critical severity
- `results[]` — per-test details with `test_id`, `passed`, `response`, `metadata`

After `aipop gate`:
- Gate passes if all threshold metrics are within policy limits
- Evidence pack includes scope record, SHA-256 hashes, and framework mappings

## Adapters

| Adapter | Target | Requires |
|---------|--------|----------|
| `mock` | No real API calls | Nothing |
| `openai` | GPT models | `OPENAI_API_KEY` |
| `anthropic` | Claude models | `ANTHROPIC_API_KEY` |
| `ollama` | Local models | Ollama running |
| `bedrock` | AWS models | AWS credentials |
| `huggingface` | HF models | `pip install ai-purple-ops[local]` |
| `llamacpp` | GGUF files | `pip install ai-purple-ops[llamacpp]` |
| `mcp` | MCP servers | MCP server URL |

## Safety boundaries

**Safe to run without confirmation:**
- Any command with `--adapter mock`
- `suites list`, `adapter list`, `config show`, `check`, `doctor`
- `--output json` variants of the above

**Requires human confirmation:**
- Running against real models (costs money, sends prompts to real APIs)
- `--stealth` mode with proxy configuration
- Any command that modifies files outside `out/`

## What NOT to do

- Do not use `--budget` values over what the operator specified
- Do not modify files in `src/`, `suites/`, or `configs/` without asking

## For deeper context

Run `aipop --help`, `aipop --agent-info`, or explore `suites/` and `configs/` directly.
