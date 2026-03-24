# The Five Axioms of AI Agent Security

These are the first principles of AI agent security — the fundamental
truths that explain why this attack surface exists and why it won't be
patched away. Every technique, every template, every lab exercise traces
back to one of these five.

These survived the Jobs filter: each one is genuinely novel to AI agent
security. If it applies equally to web apps or network security, it
didn't make the list. These are the statements you'd defend at DEF CON.

---

| # | Axiom | Why It's Novel | What It Means for a Pentester |
|---|-------|---------------|------------------------------|
| **1** | **The context window is untyped. Instruction and data share one channel with no provenance.** | No other system merges trust levels into one untyped stream where the control language IS the data language. | Any data that enters the prompt can control the model. Every input surface is an injection surface. |
| **2** | **Tool calls inherit the agent's authority, not the requester's intent.** | The confused deputy problem via natural language — the model acts with its own credentials based on attacker-supplied text. | If the agent has a service account, every injection is a privilege escalation. The tool is the weapon, not the response. |
| **3** | **State persists as untyped text, re-entering the context as potential instructions.** | Memory, RAG, summaries are all untyped text that re-enters the prompt. Persistence and injection use the same medium. | One injection into memory or RAG can activate across sessions, users, and time. Test what persists and where it re-enters. |
| **4** | **Content monitoring can't catch behavioral attacks. The monitor and executor see different text.** | Guardrails tokenize and classify. The model interprets semantically. Same text, different interpretation. The IDS evasion problem at the semantic layer. | Identify the guardrail architecture first. Pre-model classifiers need encoding bypass. Model alignment needs semantic reframing. Post-model filters need gradual extraction. |
| **5** | **Recon determines the attack. Blind testing is noise.** | AI systems have layered architectures (wrapper → guardrail → model → tools → state) that determine which attacks work. Without recon, you're guessing which layer to target. | Fingerprint the stack. Map the trust architecture. THEN select your approach. The tool should show you WHY it recommends what it recommends. |

---

## How They Connect

```
Axiom 1 (untyped context) is the ROOT CAUSE.
  ↓
Axiom 2 (confused deputy) is what happens when tools exist.
Axiom 3 (state persistence) is what happens when memory exists.
Axiom 4 (monitor ≠ executor) is why defenses fail.
  ↓
Axiom 5 (recon before attack) is HOW you operate given 1-4.
```

Axiom 1 enables everything. If the context window had typed, provenance-
tracked inputs, axioms 2-4 wouldn't exist. But it doesn't, and they do,
and that's why AI agent security is a distinct discipline.

---

## What Didn't Make the Cut (And Why)

These are excellent TECHNIQUES and METHODOLOGIES that implement the five
axioms. They're in the playbook, not the axiom list.

| Candidate | Why It Was Cut |
|-----------|---------------|
| "Fingerprint the wrapper first, then the model" | Assessment methodology, not a system property. Standard recon practice. |
| "Fingerprinting is attribution, not banner-grabbing" | Operational advice. True for any fingerprinting, not AI-specific. |
| "Error strings are the strongest fingerprint" | 1990s banner grabbing. Great technique, not novel. |
| "Map principal/object/action/mediator" | Reference monitor concept (1972). We teach it, but it's not ours. |
| "Caching breaks complete mediation" | Consequence of Axioms 1 + 3 combined, not a separate axiom. |
| "Three guardrail architectures" | Taxonomy, not axiom. The axiom underneath it is Axiom 4. |
| "Web testing analogues are genuine" | True and useful, but it's a methodology bridge, not a truth about AI. |

These live in the technique libraries:
- `recon-fingerprinting-axioms.md` — fingerprinting playbook
- `recon-trust-architecture-axioms.md` — trust assessment playbook
- `attack-axioms-and-primitives.md` — attack primitive mapping

---

## For AIPOP

Each axiom maps to a tool capability:

| Axiom | AIPOP Feature |
|-------|--------------|
| 1. Untyped context | BehaviorDetector — detects model following embedded instructions |
| 2. Confused deputy | ToolArgumentDetector — catches malicious patterns in tool call args |
| 3. State persistence | StateDiffDetector — detects escalation and info leak across turns |
| 4. Monitor ≠ executor | Encoding mutators + guardrail fingerprinter |
| 5. Recon before attack | TargetDiscovery + GuardrailFingerprinter + auto-strategy |

## For Academy

Each axiom is a lesson:

| Axiom | Lab(s) | What Students Learn |
|-------|--------|-------------------|
| 1 | Lab 01 (Goal Hijacking) | Inject instructions via retrieved document context |
| 2 | Lab 02 (Tool Misuse), Lab 03 (Identity) | Induce tool calls with attacker-chosen arguments |
| 3 | Lab 06 (Memory Poisoning) | Persist injection across sessions via memory |
| 4 | Lab 09 (Trust Exploitation) | Bypass guardrails using semantic reframing |
| 5 | All labs, recon phase | Fingerprint before attack, every time |

## For Marketing

**One sentence:** "AI agents merge instructions and data into one channel,
act with their own authority, remember what you tell them, and their
guardrails can't see what they do. We test all five of those seams."

**For the README:** The five-axiom table above IS the README's "What it
tests" section.

---

## Evidence Base

Each axiom is backed by multiple independent sources:

**Axiom 1:** USENIX 2024 (Greshake), NDSS 2025 (spotlighting), AISec
2023 (indirect injection), ConfusedPilot (Black Hat 2024)

**Axiom 2:** CVE-2025-32711 (EchoLeak), Clinejection, CVE-2025-53967
(Figma MCP RCE), CVE-2025-59944 (Cursor), OWASP Excessive Agency

**Axiom 3:** AgentPoison (NeurIPS 2024), InjecMEM, Unit 42 memory
poisoning PoC, Clinejection cache poisoning (Cacheract)

**Axiom 4:** SemanticCamo (ACL 2025, 80%+ bypass), Bad Likert Judge
(71.6% ASR), emoji smuggling (100% evasion on Prompt Shield),
Ptacek & Newsham IDS evasion analogy

**Axiom 5:** NIST SP 800-115 (testing methodology), OWASP WSTG,
PTES, TRAP (model fingerprinting), ConfusedPilot (RAG recon)

---

*These axioms are the intellectual foundation of Tyrian Institute's
AI security curriculum and AIPOP's detection architecture. Every
template, every lab, every tool feature traces back to one of these
five truths.*
