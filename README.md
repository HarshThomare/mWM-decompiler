# mWM-decompiler

## Abstract

Microarchitectural weird machines (µWMs) conceal computation in transient execution and microarchitectural state, defeating binary analysis. Existing systems either emulate known cache-based µWMs or recover Flexo circuits from analyst-identified functions. We present a generalized decompiler that locates µWM regions in unknown stripped ELFs and reconstructs programs spanning Flexo cache circuits, TAE branch-target-buffer computation, and TLB-based machines. Our approach combines CFG-aware static analysis with resource-specific native experiments, rather than assuming a universal register oracle. A typed evidence IR records register encodings, persistence, destructive reads, transient triggers, uncertainty, and cross-resource conversions. Specialized lifters recover Boolean LUTs or bounded architectural computations, while optional language-model assistance names verified subgraphs and renders C without participating in semantic correctness. We validate Boolean regions through combinational equivalence and program-like regions through differential native execution. Our contributions are expert-free whole-binary localization, evidence-backed cross-family recovery, a benchmark of stripped and negative binaries, and explicit measurement of accuracy, portability, and abstention.

## Architecture

Discovery does not start by guessing Flexo vs TAE. Flavor is a post-hoc label on a typed net (`lut` / `isa` / `converted`), not a branch in the pipeline. Native adapters are the oracle; WeMu is not used. ELFs are not executed unless you pass `--run-native`.

```
ELF  →  harvest (CFG + semantic evidence)
     →  hypothesize WRs / windows (provenance, confidence)
     →  native adapters (cache / BTB / TLB; samples or abstain)
     →  family lift (Flexo LUT, GITM exception gate, TAE ISA, TLB)
     →  typed compose (reject unsupported mixed fusion)
     →  BLIF + ABC/CEC  or  C  (Boolean vs program-like regions)
```

| Stage | Method | What it does *not* do |
|---|---|---|
| **Harvest** | Capstone walk of `.text`. CFG/call-graph clusters of triggers (`rsb`, `exception`, `tsx`, `indirect_jmp`), timers (`rdtscp`), probes (`clflush`, timed loads), and address formation. CACM Table 1 is seed evidence, not a closed ISA. Unresolved sites are kept with provenance. | Require `__DualGate__` / `__weird__`. Name the circuit. |
| **Hypothesize** | Bind WRs by physical key (line, BTB site, VPN) plus alias/copy-prop when a Flexo stride is already visible. Score needs a typed resource **and** a trigger. | Merge registers by mnemonic equality alone. Invent missing targets. |
| **Native adapters** | One protocol per resource: dual-rail occupancy (dcache/Flexo, GITM), train/observe (BTB/TAE), evict/walk (TLB). Calibration, invalid states (HH/LL, mixed targets), causality tests, uncertainty. | A universal write0/write1/read API. Fake LUTs when WeMu or this CPU cannot observe the resource. |
| **Family lift** | DualGate `table_id` when present; otherwise occupancy samples fill GATE tables. GITM: exception window + dcache. TAE: bounded ISA/CFG `EXPR` on persistent BTB places. TLB: hit/miss transitions. | Fuse cache LUTs with TAE bodies unless a `ConversionEdge` is explicit. |
| **Compose / emit** | `Net.compose()` → `lut`, `isa`, or `converted`. LUT regions → BLIF/ABC/CEC. ISA regions → straight-line C or native I/O equivalence. LLM names/clusters/renders only verified subgraphs. | Use LLM for WR kind, same-WR merge, window I/O, or LUT identity. Judge recovered C instead of the net. |

`--no-llm` keeps the same semantic IR and CEC. `--run-native` pins a core and runs the ELF (Flexo accuracy banners or TAE output). Leave it off unless the CPU implements the gadget (TAE needs SERIALIZE / Sapphire Rapids–class Intel).

## Comparison with 0xELF

[0xELF](https://yuval.yarom.org/pdfs/LusvardiAFYC26.pdf) (Lusvardi, Andreolini, Ferretti, Yarom, Chakraborty) is the first reverse-engineering framework for **Flexo-generated** µWMs. Given a weird-function entry, it uses angr symbolic execution with an emulated RSB and abstract cache, extracts each DualGate as DNF from a RAW-dependency forest, reconstructs wiring (including dual-rail polarity and repeaters), and emits BLIF. CEC against Yosys/Flexo gold succeeds on Flexo gates, adders, ALU, SHA-1, AES, Simon, and EPFL circuits (with I/O renaming). It does not execute µWMs on hardware. WeMu, in 0xELF’s terms, can only trace concrete inputs and cannot extract a logical description.

This decompiler is aimed at the leftover 0xELF names: identification without an expert address, and µWMs that are **not** Flexo DualGate DNF (GITM exception+dcache, TAE BTB/ISA, TLB).

| | **0xELF** | **This decompiler** |
|---|---|---|
| Input | Weird-function address + parameter-count bound | Whole stripped ELF; no entry hint |
| Scope | Flexo RSB + dual-rail cache, *N*≤4 | Flexo, GITM exception, TAE BTB/ISA, TLB; mixed only with an explicit conversion |
| How a gate is recovered | Structural: RAW forest → DNF (Eq. 1 in 0xELF) | DualGate `table_id` if present; else native occupancy / ISA slice. Never invent a table |
| Oracle | None (symbolic / abstract cache) | Resource-specific **native** adapters; `--run-native` optional |
| Output | Combinational BLIF; CEC vs Flexo/Yosys gold | Typed evidence IR; CEC on LUT regions; differential native / abstention on ISA |
| Identification (C1) | Analyst locates `__weird__` | Harvest + confidence; trampoline-dense BTB and flush-only helpers may stay unresolved |
| Non-Flexo | Out of scope (§7 “Other µWM Designs”) | Family lifters; TAE/TLB abstain (`unemulated`) without native samples or SERIALIZE |
| LLM | None | Overlay naming/C only, after `compose()` |

0xELF remains the right tool for a *known* Flexo weird function: one symbolic pass scales to thousands of DualGates. This tree does not replace that DNF extraction. What it adds is expert-free localization, a typed IR that refuses illegal mixed composition, and a native path for families whose encoding is not a RAW forest.

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
