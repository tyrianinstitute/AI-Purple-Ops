# Compliance Recipe Library

**Goal-oriented compliance templates for regulatory frameworks.**

## Purpose

Compliance recipes help compliance teams generate audit-ready evidence packs that demonstrate:
- Regulatory framework conformance (NIST, EU, FedRAMP, ISO)
- Control coverage and implementation
- Risk assessment and mitigation
- Continuous monitoring compliance
- Certification readiness

## Planned Recipes

### Major Framework Coverage

**`nist_ai_rmf_measure.yaml`**- NIST AI Risk Management Framework - MEASURE phase
- Functions: MAP, MEASURE, MANAGE capabilities
- Controls: Bias, fairness, robustness, transparency
- Output: NIST conformance report + control coverage matrix

**`eu_ai_act_article15.yaml`** (not yet implemented)
- EU AI Act Article 15 compliance (high-risk AI)
- Requirements: Accuracy, robustness, cybersecurity
- Documentation: Technical documentation (Annex IV)
- Output: EU AI Act conformance report + risk assessment

**`fedramp_continuous_monitoring.yaml`** (not yet implemented)
- FedRAMP continuous monitoring requirements
- Controls: AC (Access Control), AU (Audit), SI (System Integrity)
- Evidence: OSCAL-compatible artifacts
- Output: FedRAMP assessment report + control evidence

**`iso42001_audit_pack.yaml`** (not yet implemented)
- ISO/IEC 42001 AI management system audit
- Clauses: Context, leadership, planning, support, operation
- Evidence: Documented processes and records
- Output: ISO 42001 audit pack + gap analysis

**`soc2_ai_controls.yaml`** (not yet implemented)
- SOC 2 Type II controls for AI systems
- Trust principles: Security, availability, confidentiality
- AI-specific: Model governance, data handling, monitoring
- Output: SOC 2 control evidence + attestation support

### Additional Frameworks

**`gdpr_ai_compliance.yaml`** (not yet implemented)
- GDPR compliance for AI systems
- Requirements: Lawfulness, fairness, transparency, data minimization
- Rights: Explanation, rectification, erasure
- Output: GDPR compliance report + DPO evidence

**`ccpa_data_protection.yaml`** (not yet implemented)
- CCPA compliance for AI data processing
- Requirements: Notice, deletion, opt-out, non-discrimination
- Output: CCPA compliance report + consumer rights evidence

## Target Users

- **Compliance Teams** - Framework conformance validation
- **Auditors** - Evidence collection and verification
- **Risk Managers** - Risk assessment and documentation
- **Legal Counsel** - Regulatory compliance attestation
- **CISOs** - Security control evidence

## Usage Pattern

```bash
# Generate NIST evidence pack
export MODEL_ADAPTER=production_model
python -m cli.harness recipe run recipes/compliance/nist_ai_rmf_measure.yaml

# EU AI Act assessment
python -m cli.harness recipe run recipes/compliance/eu_ai_act_article15.yaml

# FedRAMP continuous monitoring
python -m cli.harness recipe run recipes/compliance/fedramp_continuous_monitoring.yaml
```

## Evidence Pack Contents

Each compliance recipe generates a complete evidence pack:

```
evidence/nist_ai_rmf_measure_20251021/
├── summary.json                    # Executive summary
├── conformance_report.pdf          # Framework conformance
├── control_coverage_matrix.csv     # Control mappings
├── test_results/                   # Detailed test outputs
│   ├── bias_fairness_results.json
│   ├── robustness_results.json
│   └── transparency_results.json
├── transcripts/                    # Full conversation logs
├── evidence_manifest.json          # Artifact inventory
└── attestation_template.docx       # Pre-filled attestation
```

## Compliance Mappings

Recipes include machine-readable control mappings:

```yaml
mappings:
  nist_ai_rmf:
    - control: MEASURE-2.3
      description: "AI system performance metrics documented"
      evidence: [test_results/robustness_results.json]
      status: compliant

  eu_ai_act:
    - article: Article_15_accuracy
      requirement: "Appropriate levels of accuracy documented"
      evidence: [conformance_report.pdf]
      status: compliant
```

## Gate Integration

Compliance recipes can block deployments on control failures:

```yaml
gate:
  enabled: true
  fail_on:
    - control_coverage < 0.95      # 95% control coverage required
    - critical_gaps > 0            # No critical gaps allowed
    - conformance_score < 0.90     # 90% conformance threshold
```

## Audit Readiness

Compliance recipes are designed for audit presentation:
- **Executive summaries** for leadership
- **Technical reports** for auditors
- **Evidence artifacts** for verification
- **Gap analysis** for remediation planning
- **Attestation templates** for sign-off

## Continuous Compliance

Run recipes regularly to maintain compliance:

```bash
# Daily compliance check (automated)
cron: 0 2 * * * python -m cli.harness recipe run recipes/compliance/nist_ai_rmf_measure.yaml

# Quarterly audit prep
python -m cli.harness recipe run recipes/compliance/iso42001_audit_pack.yaml

# Pre-certification validation
python -m cli.harness recipe run recipes/compliance/fedramp_continuous_monitoring.yaml
```
