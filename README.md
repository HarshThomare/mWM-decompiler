# mWM-decompiler

## Abstract

A **weird register** is a microarchitectural state variable whose value can be manipulated, consumed, transformed, or observed through a program fragment while remaining weakly represented or invisible at the architectural abstraction. Microarchitectural weird machines (µWMs) compute over that state—often in a transient window—so the interesting function is not present as ordinary ISA dataflow.

This decompiler does not start by asking whether a fragment is an AND gate, a Flexo circuit, or a TAE program. It treats each candidate as a relation

\[
M_{\mathrm{out}} = F(M_{\mathrm{in}}, A, T)
\]

where \(M\) is observed or inferred microarchitectural state, \(A\) is architectural or transient dataflow, and \(T\) records window and timing conditions. A tiny harvest ontology of state, window, and architectural events is the canonical vocabulary. Higher-level readings—Flexo-style Boolean LUTs, TAE-style processor-like functions, TLB µWMs—are **derived** from that relation when evidence supports them, and otherwise remain `unknown`. Optional language-model assistance may propose a derived form or name a verified subgraph; it does not decide semantics. Native adapters and static checks confirm, refine, reject, or abstain.

## Relation model

Computation is inferred as a relation, not as a family label. Each fragment records:

| Symbol | Meaning |
|---|---|
| \(M\) | Microarchitectural state variables (weird registers), with physical key, encoding, persistence, and destructive-read when known |
| \(A\) | Architectural or transient operands feeding \(F\) |
| \(T\) | Window and timing constraints |
| events | Ordered harvest trace using the ontology below |
| derived form | At most one interpretation, or `unknown` |

Supported derived forms (`src/ir/relation.py`): `unknown`, `boolean_lut`, `bitvector`, `transition_system`, `indexed_memory`, `branch_dependent`, `sequential_machine`. Incomplete relations stay unresolved rather than being forced into Flexo / TAE / TLB. Mixed fusion of derived forms or \(M\) domains requires an explicit conversion edge; it is never inferred.

Native adapters validate claims about \(M\) (cache occupancy, BTB train/observe, TLB evict/walk). They are not a harvest classifier. WeMu is not used. ELFs are not executed unless you pass `--run-native`.

## Harvest ontology

Harvest should emit evidence-backed **event traces** on program fragments, not a resource+trigger guess that picks Flexo, TAE, or TLB up front. Instruction, address, operand/binding, state subject, and provenance are attributes on these primitives—not extra primitive names.

| Kind | Role |
|---|---|
| `STATE_READ` / `STATE_WRITE` / `STATE_CLEAR` / `STATE_TRAIN` / `STATE_OBSERVE` | Manipulate or observe \(M\) |
| `WINDOW_OPEN` / `WINDOW_SQUASH` / `WINDOW_EXTEND` | Transient-window bounds |
| `ARCH_COMPUTE` / `ARCH_BRANCH` / `ARCH_MEMORY` | Architectural dataflow inside the fragment |

Higher-level meanings are derived. Examples, not harvest labels:

- **Flexo LUT** — `STATE_READ` → timing-dependent computation → `STATE_WRITE` → `WINDOW_SQUASH` can support a `boolean_lut`.
- **TAE** — `STATE_READ` → `ARCH_COMPUTE` → `ARCH_BRANCH` → `STATE_WRITE` can support a processor-like (`bitvector` / branch-dependent) function.
- **TLB µWM** — `STATE_READ` (TLB) → `ARCH_COMPUTE` → `STATE_WRITE` (TLB) can support an indexed-memory or transition reading.

The IR for events, state, and relations is in `src/ir/events.py`, `state.py`, `relation.py`, and `net.py`. `src/extract.py --json` emits fragments, event traces, \(M\)/\(A\)/\(T\), validation, and derived form (or `unknown`).

## Architecture

Intended pipeline:

```
ELF  →  harvest (event traces / fragments)
     →  relation hypothesis   M_out = F(M_in, A, T)
     →  native / static validation
     →  derived form  (or remain unknown)
```

| Stage | Model | What it does *not* do |
|---|---|---|
| **Harvest** | CFG-aware scan of `.text` into ontology events and fragments. Unresolved sites are kept with provenance. CACM Table 1 is seed evidence, not a closed ISA. | Require `__DualGate__` / `__weird__`. Classify Flexo vs TAE vs TLB. Name the circuit. |
| **Hypothesis** | Bind \(M\), \(A\), and \(T\) from the event trace. Optional LLM `propose_relation` may guess a derived form from that evidence only. | Treat the LLM guess as derived. Merge registers by mnemonic equality alone. |
| **Validation** | Deterministic / static recovery (e.g. DualGate `table_id` when present) and resource-specific native adapters. Adapters may confirm, refine, reject, or abstain. | A universal write0/write1/read API. Invent a LUT or ISA body the evidence does not support. |
| **Derive / emit** | Recognize a supported form only when the relation evidence carries it. Otherwise stay `unknown`. Overlay naming/C may annotate a verified subgraph. | Use family as a pipeline branch. Use LLM for WR kind, same-WR merge, window I/O, LUT identity, or the derived form. |

`--no-llm` skips optional model calls; semantic IR and CEC are unchanged. `--run-native` pins a core and runs the ELF (Flexo accuracy banners or TAE output). Leave it off unless this CPU implements the gadget (TAE needs SERIALIZE / Sapphire Rapids–class Intel).

## LLM

Optional, hypothesis-only, JSON-only. Model: Composer 2.5. Copy `.env.example` to `.env` and set `CURSOR_API_KEY` (`.env` is gitignored). `--no-llm`, or a missing key, skips every model call.

`propose_relation` may suggest a derived form from harvested event/dataflow evidence. It must cite event ids, separate facts from inferences, and may abstain (`unknown`). Confirmation is deferred to deterministic, static, and native checks; an unvalidated hypothesis never becomes the derived interpretation.

Overlay naming, clustering, and C rendering still exist. They still must not decide WR kind, merge, window I/O, LUT identity, or the derived form.

## Comparison with 0xELF

[0xELF](https://yuval.yarom.org/pdfs/LusvardiAFYC26.pdf) (Lusvardi, Andreolini, Ferretti, Yarom, Chakraborty) is the first reverse-engineering framework for **Flexo-generated** µWMs. Given a weird-function entry, it uses angr symbolic execution with an emulated RSB and abstract cache, extracts each DualGate as DNF from a RAW-dependency forest, reconstructs wiring (including dual-rail polarity and repeaters), and emits BLIF. CEC against Yosys/Flexo gold succeeds on Flexo gates, adders, ALU, SHA-1, AES, Simon, and EPFL circuits (with I/O renaming). It does not execute µWMs on hardware. WeMu, in 0xELF’s terms, can only trace concrete inputs and cannot extract a logical description.

This decompiler is aimed at the leftover 0xELF names: identification without an expert address, and µWMs whose computation is not Flexo DualGate DNF. Flexo LUTs, TAE BTB programs, and TLB machines are derived readings of the same relation model, not parallel pipelines.

| | **0xELF** | **This decompiler** |
|---|---|---|
| Input | Weird-function address + parameter-count bound | Whole stripped ELF; no entry hint |
| Scope | Flexo RSB + dual-rail cache, *N*≤4 | Any fragment that yields \(M_{\mathrm{out}}=F(M_{\mathrm{in}},A,T)\); Flexo / TAE / TLB as derived examples |
| How a function is recovered | Structural: RAW forest → DNF (Eq. 1 in 0xELF) | Evidence-backed relation; DualGate `table_id` may support `boolean_lut`. Never invent a table |
| Oracle | None (symbolic / abstract cache) | Resource-specific **native** adapters as validators; `--run-native` optional |
| Output | Combinational BLIF; CEC vs Flexo/Yosys gold | Relation IR (events, \(M\)/\(A\)/\(T\), derived or `unknown`); CEC on confirmed LUT regions |
| Identification (C1) | Analyst locates `__weird__` | Harvest + confidence; trampoline-dense BTB and flush-only helpers may stay unresolved |
| Non-Flexo | Out of scope (§7 “Other µWM Designs”) | Same ontology; derive or remain `unknown`. Native adapters abstain without samples or SERIALIZE |
| LLM | None | Hypothesis-only `propose_relation` plus overlay naming/C; neither assigns the derived form |

0xELF remains the right tool for a *known* Flexo weird function: one symbolic pass scales to thousands of DualGates. This tree does not replace that DNF extraction. What it adds is expert-free localization and a relation IR that refuses to force a family or invent mixed composition.

## Submodules (the three public µWM implementations)

WeMu remains a separate emulator repository and is not part of this tree.

| Directory | Upstream | Role |
|---|---|---|
| `third_party/flexo` | [joeywang4/Flexo](https://github.com/joeywang4/Flexo) | Dual-rail cache / RSB compiler |
| `third_party/gitm` | [joeywang4/Transient-Weird-Machine](https://github.com/joeywang4/Transient-Weird-Machine) | Exception / TSX / predictor gates (public GITM-class source; original `skelly` is unpublished) |
| `third_party/tae` | [joeywang4/Weird-Programs](https://github.com/joeywang4/Weird-Programs) | TAE BTB weird programs |

```bash
git clone --recurse-submodules <this-repo>
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
./venv/bin/python src/extract.py path/to/binary.elf --no-llm
./venv/bin/python src/extract.py --self-test
```

`--all` walks `*.elf` under the three `third_party/` trees after you build them.

## Future work

These are open problems, not results of this tree.

- **Stealth and obfuscation.** µWMs are a natural obfuscation substrate: they execute transiently and leave architectural traces that look like ordinary ISA. Debuggers cannot read weird registers, and single-stepping disturbs or kills transient windows, so dynamic analysis is weak. Static analysis sees the ISA instructions that open those windows; whether that is enough to reconstruct \(F\), or whether race-condition circuits remain stealthier in practice, is unsolved. Detection via squash-rate counters or µWM emulation (beyond cache-based weird circuits) is likewise open.
- **Static vs dynamic analysis.** This decompiler is primarily static harvest plus optional native experiments. General dynamic de-obfuscation of µWMs, and a fair comparison of what static event traces can and cannot recover, remain future work.
- **Other microarchitectures.** Public TAE-style machines are tuned to a small set of Intel BTBs. Portability needs reverse-engineering of other BTBs (including non-Intel), not only retuning constants.
- **Multi-bit weird registers beyond the BTB.** Other microarchitectural structures may encode wider \(M\); converting that state to architectural values inside a transient window is unsolved.
- **Batch optimizations.** Amortizing BTB (or other \(M\)) updates across many inputs—lock-step execution of one weird function at a time—is a compilation/runtime concern, not something this decompiler claims.
- **Compilation to weird programs.** Compiling to µWMs is known; compiling to TAE-style weird programs still has to slice work so each fragment finishes inside a transient window whose length depends on the input. This tree recovers relations; it does not emit weird programs or prove window bounds.
