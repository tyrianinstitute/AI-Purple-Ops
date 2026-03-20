# AI Purple Ops Recipe System

**Pre-configured workflow templates for AI Safety, Security, and Compliance testing.**

## What Are Recipes?

Recipes are YAML-based workflow templates that eliminate the complexity of AI security testing. Instead of manually configuring benchmarks, detectors, evaluators, and thresholds, you simply:

1. Point a recipe to your model adapter
2. Run the pre-configured workflow
3. Get complete results with evidence packs

**Time to first result:** 30 seconds to 2 minutes (vs hours of manual setup)

## Three Recipe Lanes

### Safety Recipes (`recipes/safety/`)
AI safety benchmarking templates for content policy, bias, toxicity, and PII detection.

**Target users:** ML engineers, AI safety teams, content moderators

### Security Recipes (`recipes/security/`)
AI security red teaming templates for prompt injection, RAG attacks, tool misuse, and adversarial testing.

**Target users:** Security engineers, red teams, penetration testers

### Compliance Recipes (`recipes/compliance/`)
Goal-oriented compliance templates that generate audit-ready evidence packs for NIST, EU AI Act, FedRAMP, ISO 42001, and more.

**Target users:** Compliance teams, auditors, risk managers

## Recipe Structure

```yaml
version: 1
metadata:
  name: "OWASP LLM Top 10 Security Check"
  description: "Comprehensive security testing against OWASP LLM vulnerabilities"
  lane: security
  framework: owasp_llm

config:
  adapter: ${MODEL_ADAPTER}  # User customization point
  seed: 42
  output_dir: out

execution:
  benchmarks:
    - owasp.llm01.prompt_injection
    - owasp.llm02.insecure_output_handling
    - owasp.llm03.training_data_poisoning

  suites: [redteam, ui]

  detectors:
    - harmful_content:
        threshold: 0.8
    - policy_violations:
        blocked_topics: [malicious_code, data_exfiltration]

  evaluators:
    - threshold:
        harmful_output_rate: 0.0
        tool_policy_violation_rate: 0.05

outputs:
  reports:
    - type: json
      path: ${OUTPUT_DIR}/reports/owasp_summary.json
    - type: junit
      path: ${OUTPUT_DIR}/reports/owasp_junit.xml

  evidence_pack:
    path: ${OUTPUT_DIR}/evidence/owasp_llm_${TIMESTAMP}.zip
    include: [summary, transcripts, conformance_report]

gate:
  enabled: true
  fail_on:
    - harmful_output_rate > 0
    - tool_policy_violation_rate > 0.05
```

## Quick Start

```bash
# List available recipes
python -m cli.harness recipe list

# Run a security recipe
export MODEL_ADAPTER=openai_gpt4
python -m cli.harness recipe run recipes/security/owasp_llm_top10.yaml

# Validate recipe syntax
python -m cli.harness recipe validate my_custom_recipe.yaml

# Create recipe from template
python -m cli.harness recipe init --lane security --name custom_check
```

## Using Different Adapters

Recipes use the `${MODEL_ADAPTER}` variable to specify which adapter to use.

### Setting the adapter

**Option 1: Environment variable (recommended)**
```bash
export MODEL_ADAPTER=openai
python -m cli.harness recipe run --recipe my_recipe --lane security
```

**Option 2: Modify recipe file**
```yaml
config:
  adapter: openai  # Change from ${MODEL_ADAPTER:-mock}
```

### Available adapters

- `mock` - No setup required, deterministic responses
- `openai` - Requires OPENAI_API_KEY environment variable
- `anthropic` - Requires ANTHROPIC_API_KEY environment variable
- `ollama` - Requires Ollama service running at localhost:11434
- `huggingface` - Requires transformers library and model files
- `llamacpp` - Requires llama-cpp-python library and GGUF model files
- `bedrock` - Requires AWS credentials configured

See `python -m cli.harness adapter list` for all adapters and their requirements.

### Preview recipe before running

```bash
# See what will be executed
python -m cli.harness recipe preview --recipe prompt_injection_baseline --lane security
```

This shows:
- Recipe name and description
- Adapter that will be used
- Test suites that will be executed
- Total number of tests

## Implementation Status

**Current:** Recipe directory structure and documentation (b03)
**Coming:** Recipe engine and execution (b06)
**Future:** 15+ curated recipes planned

See [docs/RECIPES.md](../docs/RECIPES.md) for complete recipe system design and development guide.

## Recipe Development

Want to create custom recipes? See:
- [Recipe Schema Reference](../reports/schemas/recipe.schema.json)
- [Recipe Design Doc](../docs/RECIPES.md)
- [Contributing Guide](../CONTRIBUTING.md)

## Community Recipes (Future)

In b10+, we'll enable community recipe sharing:

```bash
# Publish your recipe
python -m cli.harness recipe publish my_recipe.yaml

# Install community recipe
python -m cli.harness recipe install community/fintech_compliance
```
