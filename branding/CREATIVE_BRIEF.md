# AIPOP Branding — Creative Brief

## Brand Context

**Parent brand:** Tyrian Institute
**Color:** Tyrian purple (#66023C) — the ancient Phoenician dye. Regal, authoritative, rare.
**Tone:** Security workbench for professionals. Not corporate. Not gamer. Think: the tool a pentester recommends to another pentester.

**Comparable tool logos to study:**
- Nuclei (ProjectDiscovery) — atom symbol, clean, technical
- Metasploit — shield + crosshair, weapon energy
- Burp Suite — orange circle, minimal (boring but recognizable)
- Nmap — eye/crosshair, surveillance feel
- Wireshark — shark fin, distinctive silhouette

**What AIPOP is NOT:**
- Not a cute mascot (no octopus, no robot, no shield with a lock)
- Not corporate SaaS (no gradient blobs, no generic "AI" imagery)
- Not a game (no skulls, no Matrix green, no hoodies)

---

## Logo Brief (Ideogram / Midjourney)

### Concept: The Prism

AIPOP takes multiple attack frameworks (PyRIT, Promptfoo, Garak) and
unifies them into one focused output — like light entering a prism
and emerging as a focused beam. The prism IS the purple. The inputs
are diverse. The output is precise.

### Ideogram Prompt (for text-integrated logo):

```
Minimalist logo design for "AIPOP", an AI security testing tool.
A geometric prism or crystal shape in deep Tyrian purple (#66023C)
with subtle light refraction lines. Clean sans-serif typography.
The logo should feel technical, precise, and authoritative — like
a pentesting tool, not a SaaS product. Dark background. No gradients.
No AI clichés (no neural networks, no robots, no shields).
Professional security tool aesthetic.
```

### Midjourney Prompt (for abstract mark):

```
/imagine minimalist geometric logo mark, deep Tyrian purple crystal
prism shape, subtle refraction lines suggesting convergence of
multiple inputs into one output, technical security tool aesthetic,
clean vector style, dark background, no text, no AI clichés,
inspired by Nuclei and Metasploit logo energy --v 6 --style raw
```

### Alternative concept: The Convergence Node

A central node (AIPOP) with 5-8 input lines converging into it —
each representing a framework or capability. The node pulses purple.
The inputs are thin, the output is bold. Network topology energy.

```
/imagine minimalist logo mark, central hexagonal node in deep
Tyrian purple (#66023C), 6 thin lines converging into it from
different angles, each line a different subtle shade, the node
glows brighter than the inputs suggesting unification, dark
background, vector style, technical security tool aesthetic,
clean and geometric --v 6 --style raw
```

---

## Ecosystem Visual Brief (README / Landing Page Hero)

### What it needs to communicate:

"AIPOP unifies the best AI security tools into one framework.
You don't choose between PyRIT, Promptfoo, and Garak. You use
all of them through AIPOP."

### The Layout (2D Avast-style convergence map):

```
                    ┌─────────┐
                    │  PyRIT  │──┐
                    └─────────┘  │
┌───────────┐                    │    ┌─────────────────────┐
│ Promptfoo │────────────────────┼───▶│                     │
└───────────┘                    │    │       AIPOP         │───▶ Evidence Pack
┌─────────┐                     │    │   (The Workbench)    │───▶ CISO Report
│  Garak  │─────────────────────┼───▶│                     │───▶ CI/CD Gate
└─────────┘                     │    └─────────────────────┘
┌──────────────┐                │
│ Custom HTTP  │────────────────┘
└──────────────┘
┌──────────────┐                │
│  MCP Servers │────────────────┘
└──────────────┘
```

But as a polished visual with:
- Left side: Tool logos/icons in their brand colors (muted)
- Center: AIPOP prism/node (Tyrian purple, glowing, dominant)
- Right side: Outputs (evidence pack, PDF report, JUnit XML, CI gate)
- Connection lines showing data flow
- Dark background with subtle grid
- Each input tool has a one-line label: "30+ attack templates", "Multi-turn orchestration", "Guardrail detection"

### Midjourney Prompt (for the ecosystem visual):

```
/imagine technical architecture diagram, dark background with
subtle grid, center glowing Tyrian purple hexagonal node labeled
hub, 6 smaller nodes on the left connected by thin glowing lines
converging into center, 3 output nodes on the right emerging from
center, convergence visualization, clean vector infographic style,
security tool documentation aesthetic, no text, minimal,
professional --v 6 --ar 16:9 --style raw
```

### Better approach: Figma + AI

1. Use Midjourney/DALL-E for the BACKGROUND texture (dark grid, subtle purple glow)
2. Build the actual diagram in Figma with real text, real tool logos, real labels
3. Composite: AI background + Figma diagram = polished result
4. This avoids AI text rendering problems entirely

---

## Recommended Tools

### For the Logo:

| Tool | Best For | Cost | Notes |
|------|----------|------|-------|
| **Ideogram** | Text + symbol logos | Free tier available | Best text rendering in AI images. Use this for the wordmark. |
| **Midjourney** | Abstract logo marks | $10/mo | Strongest aesthetic quality. Use for the symbol/icon only, add text in Figma. |
| **Looka** | Quick brand kits | $20 one-time | AI logo generator. Fast but generic. Good for exploring directions. |

**Recommendation:** Generate 20 variations in Ideogram and Midjourney. Pick the best symbol from Midjourney, pair it with clean type in Figma. Total cost: $10-20.

### For the Ecosystem Visual:

| Tool | Best For | Notes |
|------|----------|-------|
| **Figma** | The actual diagram | Build the real thing here with proper layout and labels |
| **Midjourney** | Background texture | Generate the dark grid + purple glow backdrop |
| **Excalidraw** | Quick wireframe | Sketch the layout first, then polish in Figma |

**Recommendation:** Sketch in Excalidraw (5 min) → build in Figma (1 hr) → AI background if needed. The diagram IS the visual — AI can't generate accurate technical diagrams with correct labels.

---

## Color Palette

| Name | Hex | Usage |
|------|-----|-------|
| Tyrian Purple | #66023C | Primary brand, logo, headings |
| Deep Purple | #2D0016 | Dark backgrounds |
| Light Purple | #9B1B6A | Accents, hover states |
| White | #F5F5F5 | Text on dark backgrounds |
| Terminal Green | #00FF41 | Terminal output, "hacker" accent (use sparingly) |
| Finding Red | #FF4444 | Critical severity badges |
| Warning Amber | #FFB800 | High severity badges |

---

## What the README Hero Should Communicate in 5 Seconds

A visitor lands on the AIPOP GitHub page. In 5 seconds they should understand:

1. **What it is:** AI security scanner (like Nuclei but for AI/LLM systems)
2. **Why it's different:** Unifies PyRIT + Promptfoo + Garak + custom targets into one CLI
3. **How easy it is:** `aipop scan http://your-target.com/chat` (one command)
4. **That it's real:** Nuclei-style terminal screenshot showing findings with severity badges

The hero image should be: ecosystem convergence diagram (left) + terminal screenshot (right). Or: terminal screenshot with the one-liner command producing real findings.
