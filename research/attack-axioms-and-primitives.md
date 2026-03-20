# TYR-817 Deliverable: Attack Axioms, Seams, and Primitive Mapping

Internal research document. Not shipped in the package — informs suite
design, detection primitives, and template format decisions.

---

## 1. The Five Seams

Every AI agent attack exploits a seam — a boundary where trust assumptions
break down. These seams are architectural, not implementation bugs. They
don't get patched away.

### Seam 1: Concatenation
Mixed-trust inputs fuse into one token stream with no provenance.
System instructions, user text, retrieved documents, tool outputs, and
memory are all concatenated into a single prompt. The model attends
across all of them equally.

**Axiom:** Any data that enters the context window is indistinguishable
from instructions.

**Evidence:** USENIX 2024 (Greshake et al.), ConfusedPilot (Black Hat
2024), CVE-2025-32711 (EchoLeak).

**AIPOP primitive needed:** Behavior matcher — detect when the model
follows an instruction embedded in context rather than responding to
the user query.

### Seam 2: Instruction-Data
The model can't distinguish "follow this" from "here's some text."
Natural language is both the data format and the control plane.

**Axiom:** Natural language IS the control plane. You can't fix this
without breaking utility.

**Evidence:** AISec 2023 (indirect injection), SemanticCamo ACL 2025
(80%+ bypass via semantic reframing), Bad Likert Judge (71.6% ASR via
evaluation reframing).

**AIPOP primitive needed:** Encoding/mutation support (exists) plus
semantic bypass templates (suite rewrite).

### Seam 3: Model-Action
Model output triggers real-world side effects — tool calls, URL
fetches, state writes. A "benign" response can still cause damage
through the tools it invokes.

**Axiom:** Side effects live outside the model. The security boundary
isn't the model output — it's the action runtime.

**Evidence:** Clinejection (npm install → credential theft),
CVE-2025-53967 (Framelink Figma MCP → RCE), CVE-2025-59944 (Cursor
config overwrite → RCE).

**AIPOP primitive needed:** Tool argument matcher — detect malicious
patterns in tool call arguments, not just tool names.

### Seam 4: Time/State
Memory, RAG stores, and multi-turn context persist attacker influence
across turns, sessions, or users. A single injection becomes durable
control.

**Axiom:** State amplifies one-shot injection into persistent,
triggerable control.

**Evidence:** AgentPoison NeurIPS 2024 (low poison rate, high success),
Unit 42 memory poisoning PoC (persists via summarization), Clinejection
cache poisoning (persists across nightly workflows).

**AIPOP primitive needed:** State diff across turns — capture what
changed between turn N and N+1 to detect escalation and poisoning.

### Seam 5: Monitor-Executor
Guardrails analyze surface tokens. The agent executes behavior. The gap
between what the monitor checks and what the executor does is the bypass
surface.

**Axiom:** Content-level filtering cannot guarantee correct behavior.

**Evidence:** Emoji smuggling (100% evasion on Prompt Shield), zero-width
chars (consistent bypass), SemanticCamo (semantic bypass at 80%+),
Ptacek & Newsham IDS evasion analogy.

**AIPOP primitive needed:** Encoding mutators (exist), guardrail
fingerprinter (exists). Gap: semantic transformation mutator.

---

## 2. Primitive-to-Seam Mapping

What AIPOP needs to test each seam:

| Seam | Primitive | Status | Implementation |
|------|-----------|--------|---------------|
| 1. Concatenation | Behavior matcher | NEW (TYR-826) | Detect model following embedded instructions |
| 2. Instruction-Data | Encoding mutators | EXISTS | base64, rot13, hex, unicode |
| 2. Instruction-Data | Semantic bypass templates | NEW (TYR-795) | Authority framing, role confusion |
| 3. Model-Action | Tool argument matcher | NEW (TYR-826) | Regex patterns on tool call args |
| 3. Model-Action | Tool policy detector | EXISTS | Allowlist check on tool names |
| 4. Time/State | State diff across turns | NEW (TYR-826) | Per-turn snapshots, delta computation |
| 4. Time/State | Multi-turn orchestrator | EXISTS | Conversation state management |
| 5. Monitor-Executor | Guardrail fingerprinter | EXISTS | 9 guardrail types detected |
| 5. Monitor-Executor | Encoding chains | EXISTS | Layered encoding bypass |

Three new primitives (TYR-826) fill the gaps. After they're built, every
seam is testable.

---

## 3. Reference Suite Mapping

Each rewritten suite (TYR-795) demonstrates ONE seam with ONE axiom.
Users fork and customize for their targets.

| Suite file | Seam | Axiom demonstrated | What changes |
|-----------|------|--------------------|-------------|
| rag_injection.yaml | Concatenation (#1) | Data in context = instructions | Replace "ignore previous" with document-level injection patterns. Test via behavior matcher. |
| tool_misuse.yaml | Model-Action (#3) | Side effects outside model | Replace "call rm -rf" with indirect queries that induce tool parameter abuse. Test via tool argument matcher. |
| multi_turn_crescendo.yaml | Time/State (#4) | State amplifies injection | Fix multi-turn to actually maintain state across messages. Test via state diff. |
| context_confusion.yaml | Instruction-Data (#2) | Language = control plane | Replace DAN/sudo with authority framing, academic pretext, semantic reframe. |
| encoding_chains.yaml | Monitor-Executor (#5) | Content filter ≠ behavior filter | Keep and expand encoding chains. Add emoji smuggling, zero-width injection. |

---

## 4. Confused Deputy Patterns for Templates

Four patterns, each a template category:

| Pattern | Template tests | Seam |
|---------|---------------|------|
| Tool deputy | Query induces agent to call tool with attacker-chosen args using agent's credentials | #3 |
| Retrieval deputy | Poisoned doc in RAG causes agent to output sensitive data | #1 |
| Delegation deputy | Task forwarded to higher-privilege worker contains embedded instructions | #1 + #3 |
| UI deputy | Visible-to-agent, invisible-to-human content on screen triggers action | #1 |

---

## 5. Detection Level Classification

Findings should report WHAT LEVEL the detection happened at:

| Level | What it means | Example | Pentester value |
|-------|-------------|---------|----------------|
| Content | Model said something flagged by keyword/regex | "Response contains 'rm -rf'" | Low — any scanner does this |
| Behavioral | Model DID something it shouldn't have | "Model called file_read with path traversal" | High — proves the confused deputy |
| State | Model's behavior CHANGED across turns in a way that indicates poisoning | "Turn 3 revealed info that Turn 1 refused" | High — proves state amplification |
| Architectural | Finding exploits an inherent seam, not an implementation bug | "Indirect injection via retrieved context — architectural, not patchable" | Highest — this is a design-level finding |

The behavioral primitives (TYR-826) enable the middle two levels. Without
them, AIPOP only operates at the content level — which is why Kenneth
called it "cringe vuln scanner" territory.

---

## 6. Evidence Pack Format (Bounty-Ready)

Five fields that make a finding submission-ready:

1. **Affecting surface:** prompt input | retrieved content | tool output | memory
2. **Capability boundary crossed:** data read | data write | tool execute | identity assumed
3. **Primitive operation:** inject | exfiltrate | escalate | persist
4. **Classification:** architectural (inherent) | implementation (patchable)
5. **Evidence chain:** full request → response → tool calls with arguments → detector verdict

This maps to STRIDE:
- Information Disclosure → exfiltration
- Elevation of Privilege → confused deputy escalation
- Tampering → state poisoning
- Repudiation → weak logging (no provenance at token level)

---

## 7. What We Don't Know (Honest Gaps)

- **Real-target validation:** None of this has been tested through AIPOP
  against a real model. Axioms are sound in theory. Primitives are
  designed from the seam analysis. But we haven't proved the tool can
  operationalize them until we scan a real target.

- **Semantic bypass effectiveness data is model-specific:** SemanticCamo
  reports 80%+ on GPT-4o and Claude 3.5 but results vary per model.
  Our templates can't promise a success rate — they demonstrate the
  technique and the user adapts.

- **Multi-modal is out of scope for S1:** File-based injection (PDFs,
  images, docs) requires the engine router (S3a). S1 covers text-based
  attacks only.

- **Bug bounty market pricing is invisible:** No public payout data
  exists for AI agent vulnerabilities. We can't tell students "this
  finding is worth $X." We can tell them the format that makes their
  submission professional.

---

## 8. Related Research

### Recon Fingerprinting Axioms (TYR-828)
Full research at: `tyrian-ai-labs/shared/research/recon-fingerprinting-axioms.md`

Five recon axioms from OpenAI Deep Research (March 2026):
1. Fingerprint the wrapper first, then the model
2. Fingerprinting is attribution, not banner-grabbing
3. Three guardrail architectures are distinguishable from behavior
4. Error strings are the strongest fingerprint
5. Latency is a side channel, not a banner

These govern the AI PTES recon cycle and feed into TYR-827 (recon
depth implementation for S2a).

### Attack Evidence Catalog
Full research at: `tyrian-ai-labs/shared/research/attack-evidence-catalog.md`

CVE chains, bounty market intelligence, STRIDE mapping, and the
5-field evidence pack format aligned with bounty submission.

### AI Recon Doctrine
Full research at: `tyrian-ai-labs/shared/research/ai-recon-doctrine.md`

The 6-phase AI PTES cycle: detect → map → fingerprint model →
fingerprint guardrails → detect framework → map trust architecture.
