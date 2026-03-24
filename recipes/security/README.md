# Security Recipe Library

**AI security red teaming templates for adversarial testing.**

## Purpose

Security recipes help security teams validate that AI systems resist:
- Prompt injection and jailbreak attempts
- Tool misuse and privilege escalation
- RAG poisoning and data exfiltration
- UI injection (XSS, SSRF) in agent interfaces
- Multi-step adversarial attack chains

## Planned Recipes

### OWASP LLM Coverage

**`owasp_llm_top10.yaml`**- Comprehensive OWASP LLM Top 10 testing
- Coverage: All 10 OWASP LLM vulnerabilities
- Tests: 100+ adversarial prompts
- Output: OWASP conformance report + findings

**`prompt_injection_battery.yaml`**- LLM01: Prompt injection comprehensive testing
- Techniques: Direct injection, indirect injection, context hijacking
- Tools: garak, PyRIT, promptfoo
- Output: Injection resistance score + bypass examples

### Advanced Attack Scenarios

**`rag_security_suite.yaml`**- RAG-specific attacks: poisoning, leakage, retrieval manipulation
- Tests: Document injection, context extraction, ACL bypass
- Output: RAG security report + attack vectors

**`tool_misuse_scenarios.yaml`**- Agent/tool security testing
- Tests: Tool allowlist bypass, privilege escalation, command injection
- Output: Tool security score + exploitation paths

**`ui_injection_full.yaml`**- UI injection in agent interfaces
- Tests: XSS, SSRF, template injection, markdown abuse
- Output: UI security report + PoC exploits

**`data_exfiltration_check.yaml`**- Data leakage and exfiltration detection
- Tests: Training data extraction, context leakage, side channels
- Output: Exfiltration risk score + leak examples

**`jailbreak_resistance.yaml`** (not yet implemented)
- Jailbreak and guardrail bypass testing
- Techniques: Roleplay, encoding, multilingual, adversarial suffixes
- Output: Jailbreak resistance score + successful bypasses

**`adversarial_robustness.yaml`** (not yet implemented)
- Adversarial ML attacks on model inputs
- Tools: ART, CleverHans, TextAttack
- Output: Robustness metrics + adversarial examples

## Target Users

- **Security Engineers** - Pre-deployment security validation
- **Red Teams** - Offensive security testing
- **Penetration Testers** - AI-specific attack scenarios
- **DevSecOps** - CI/CD security gates

## Usage Pattern

```bash
# Quick OWASP check
export MODEL_ADAPTER=production_model
python -m cli.harness recipe run recipes/security/owasp_llm_top10.yaml

# Deep dive on prompt injection
python -m cli.harness recipe run recipes/security/prompt_injection_battery.yaml

# RAG security assessment
python -m cli.harness recipe run recipes/security/rag_security_suite.yaml
```

## Integration with CI/CD

Security recipes block unsafe deployments:

```yaml
gate:
  enabled: true
  fail_on:
    - prompt_injection_success > 0    # No successful injections
    - tool_policy_violations > 0      # No tool misuse
    - rag_leakage_rate > 0            # No data leaks
    - ui_injection_success > 0        # No XSS/SSRF
  warn_on:
    - jailbreak_success_rate > 0.05   # <5% jailbreak rate acceptable
```

## Evidence Outputs

Each security recipe generates:
- JSON summary with vulnerability findings
- Detailed attack transcripts
- Proof-of-concept exploit code
- CVSS-style risk scoring
- Remediation recommendations
- Evidence pack for security audits

## Compliance Mapping

Security recipes map to frameworks:
- **MITRE ATLAS** - LLM threat matrix coverage
- **OWASP LLM Top 10** - Vulnerability classification
- **NIST AI RMF** - Security control mappings
- **FedRAMP** - SI (System and Information Integrity) controls
