# Safety Recipe Library

**AI safety benchmarking templates for responsible AI deployment.**

## Purpose

Safety recipes help ML teams validate that AI systems:
- Comply with content policies
- Don't produce harmful outputs
- Treat users fairly across demographics
- Protect user privacy (PII/sensitive data)
- Align with organizational values

## Planned Recipes

### Core Safety Checks

**`content_policy_baseline.yaml`**
- Basic content safety validation
- Detects: violence, hate speech, self-harm, sexual content
- Thresholds: Zero tolerance for policy violations
- Output: Content safety report + flagged examples

**`bias_fairness_audit.yaml`**
- Fairness assessment across protected attributes
- Tests: Demographic parity, equalized odds, calibration
- Frameworks: AI Fairness 360, Fairlearn
- Output: Fairness metrics + bias analysis report

**`pii_leakage_scan.yaml`**
- Privacy verification and PII detection
- Detects: Names, emails, SSNs, credit cards, phone numbers
- Uses: Microsoft Presidio, Scrubadub
- Output: PII detection report + leakage instances

**`toxicity_detection.yaml`**
- Toxic output detection and scoring
- Categories: Toxicity, severe toxicity, obscenity, threats, insults
- Uses: Detoxify, Perspective API
- Output: Toxicity scores + flagged responses

### Advanced Safety Checks

**`hallucination_check.yaml`**- Factual accuracy and hallucination detection
- Methods: Citation checking, consistency scoring
- Output: Hallucination rate + confidence scores

**`value_alignment_test.yaml`** (not yet implemented)
- Alignment with organizational values
- Custom value specifications
- Output: Alignment score + misalignment examples

## Target Users

- **ML Engineers** - Pre-deployment safety validation
- **AI Safety Teams** - Continuous monitoring and evaluation
- **Content Moderators** - Policy compliance checking
- **Product Managers** - Risk assessment for launches

## Usage Pattern

```bash
# Run content policy check
export MODEL_ADAPTER=my_model
python -m cli.harness recipe run recipes/safety/content_policy_baseline.yaml

# Run full safety battery
python -m cli.harness recipe run recipes/safety/bias_fairness_audit.yaml
python -m cli.harness recipe run recipes/safety/pii_leakage_scan.yaml
python -m cli.harness recipe run recipes/safety/toxicity_detection.yaml
```

## Integration with Gates

Safety recipes can block deployments:

```yaml
gate:
  enabled: true
  fail_on:
    - harmful_output_rate > 0      # Zero tolerance
    - bias_score > 0.1              # 10% demographic disparity max
    - pii_leakage_count > 0         # No PII leaks allowed
    - toxicity_severe > 0           # No severe toxicity
```

## Evidence Outputs

Each safety recipe generates:
- JSON summary with pass/fail status
- Detailed transcript logs
- Flagged examples with context
- Metrics dashboard data
- Evidence pack for audits
