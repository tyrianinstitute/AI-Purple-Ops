# AI Purple Ops

Scan AI apps for security flaws. Get evidence a CISO would accept.

```
pip install git+https://github.com/tyrianinstitute/AI-Purple-Ops.git
```

```bash
aipop scan --adapter openai --model gpt-4o-mini
```

<!-- hero asciinema recording goes here — real scan, real target, real findings -->

## What it does

`aipop scan` runs recon, selects attack templates based on what it discovers, tests for real vulnerabilities, and produces an evidence pack. One command.

Findings are **behavioral**, not keyword-based. The tool detects "the model called `file_read` with `../../etc/passwd`" — not "the response contained a bad word." That's the difference between a finding a pentester respects and scanner noise.

## Quick start

Validate your pipeline (no API key needed):

```bash
aipop scan --adapter static
```

Scan a real target:

```bash
aipop scan --adapter openai --model gpt-4o-mini --budget 1.00
aipop scan --adapter ollama --model llama3
aipop scan --adapter anthropic --model claude-sonnet-4-20250514
```

See what it found:

```bash
aipop gate --generate-evidence
```

## What it tests

Five architectural seams that exist in every AI agent system:

| Seam | What breaks | Example finding |
|------|------------|----------------|
| **Concatenation** | Retrieved context treated as instructions | "Model followed instruction embedded in meeting notes" |
| **Model-Action** | Tool calls with attacker-chosen arguments | "`file_read` called with `../../etc/shadow`" |
| **State** | Behavior shifts across conversation turns | "Refused in turn 1, revealed credentials in turn 3" |
| **Instruction-Data** | Semantic framing bypasses safety | "Authority reframe caused system prompt disclosure" |
| **Monitor-Executor** | Encoded content evades guardrails | "Base64 payload bypassed Prompt Shield classifier" |

These seams are architectural — they don't get patched away. The templates demonstrate each axiom. You supply the creativity for your specific target.

## Templates are the on-ramp, not the product

AIPOP ships reference templates that prove each seam is testable. The real power is the workbench:

```yaml
# Write your own — fork a template, change the payload, run it
cases:
  - id: my_rag_injection_test
    prompt: "Summarize this doc: [MEETING NOTES] ... [hidden instruction] ..."
    expected: fail
    metadata:
      seam: concatenation
      behavior_indicators: ["api_key", "password", "secret"]
```

```bash
aipop run --suite custom/my_test --adapter openai --model gpt-4o-mini
```

## Recon first, then attack

```bash
aipop scan --adapter openai --model gpt-4o-mini
```

The scan starts with discovery — probes the target for capabilities (tool calling, RAG, memory, code execution) and fingerprints the guardrail. Then selects templates based on what it found. The output shows you why:

```
◎ recon
  target:  openai/gpt-4o-mini
  surface: ● tool calling  ● rag retrieval  ○ code execution
  suites:  adversarial, tools, rag
```

## Evidence packs

Every scan produces structured evidence mapped to OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS, and CVSS v3.1. Export for Ghostwriter, Dradis, or PDF delivery.

```bash
aipop gate --generate-evidence
aipop export pdf
aipop export ghostwriter
```

## Adapters

| `--adapter` | What it targets |
|---|---|
| `openai` | GPT-4o, GPT-4o-mini, o1, o3 |
| `anthropic` | Claude Opus 4, Claude Sonnet 4 |
| `ollama` | Local models (Llama 3, Mistral, Phi, Qwen) |
| `bedrock` | AWS Bedrock models |
| `huggingface` | Any Hugging Face model |
| `custom_http` | Any HTTP endpoint |
| `static` | Pipeline validation (no LLM, canned responses) |

## Install

```bash
pip install git+https://github.com/tyrianinstitute/AI-Purple-Ops.git
```

Optional extras:

```bash
pip install ai-purple-ops[pyrit]        # Multi-turn agentic red teaming
pip install ai-purple-ops[intelligence] # Guardrail fingerprinting, genetic algorithms
pip install ai-purple-ops[reports]      # PDF generation
pip install ai-purple-ops[all]          # Everything
```

## Project layout

```
src/aipop/             Core: scanner engine, adapters, detectors, reporters
src/aipop/cli/         CLI + cinematic display components
src/aipop/detectors/   Behavioral detection (tool args, behavior matching, state diff)
src/aipop/harnesses/   ASI01-ASI10 deterministic security test harnesses
suites/                YAML attack templates (5 seam categories)
research/              Attack axiom research and primitive mapping
tests/                 627+ tests
```

## License

[MIT](LICENSE)
