# Policy Configuration

This directory contains policy configuration files that define rules for content safety, tool usage, and other policy enforcement mechanisms.

## Files

### `content_policy.yaml`

Defines rules for detecting harmful content in model outputs. Each rule includes:
- `id`: Unique identifier for the rule
- `category`: Type of harmful content (violence, hate_speech, sexual_content, pii, etc.)
- `severity`: Severity level (low, medium, high, critical)
- `description`: Human-readable description
- `patterns`: List of regex patterns to match
- `keywords`: List of keywords to detect

**SLO Thresholds:**
- `harmful_output_rate`: Maximum percentage of outputs that can be harmful (default: 0.05 = 5%)
- `critical_violation_rate`: Maximum percentage that can be critical violations (default: 0.01 = 1%)

### `tool_allowlist.yaml`

Defines which tools/functions are allowed to be called by models. **Full implementation not yet available** - tool/function calling support is planned.

## Custom Policies

You can create custom policy files and load them using the `--policy` CLI flag:

```bash
python -m cli.harness run --suite normal --policy /path/to/custom_policy.yaml
```

## Policy Schema

### Content Policy Schema

```yaml
version: "1.0.0"
description: "Policy description"

rules:
  - id: rule_id
    category: "violence|hate_speech|sexual_content|pii"
    severity: "low|medium|high|critical"
    description: "Rule description"
    patterns:
      - "regex pattern 1"
      - "regex pattern 2"
    keywords:
      - "keyword1"
      - "keyword2"

thresholds:
  harmful_output_rate: 0.05
  critical_violation_rate: 0.01
```

### Tool Policy Schema

```yaml
version: "1.0.0"
description: "Tool policy description"

allowed_tools: []  # Not yet implemented

schema:
  type: "object"
  properties: {}
  required: []
```

## Examples

See `content_policy.yaml` for examples of policy rules covering:
- Violence detection
- Hate speech detection
- Sexual content detection
- PII (Personally Identifiable Information) detection
