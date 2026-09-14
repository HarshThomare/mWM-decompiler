# Flexo µWM net IR → BLIF → ABC

Hybrid lifter: static DualGate recovery (wired netlist) plus a native CPU oracle. Recovered nets are exported as combinational BLIF and run through Berkeley ABC (`print_stats`, `strash`/`dc2`, `cec`, `write_verilog`). Yosys/v2c were not available on this host (no root); ABC is the synthesis/CEC back-end.

Framework identity is derived (`flexo` iff every non-`ρ` transition has empty `expr` and all places are volatile). `classify()` remains that derived view. Typed fusion goes through `compose()`, which raises `MixedCompositionError` instead of inferring a mixed LUT+ISA or multi-resource net.

## Layout

| Path | Role |
|---|---|
| [`net.py`](net.py) | Typed evidence IR: `N = (P, T, F, col, kind, W, R)` plus resource, evidence, regions, conversions |
| [`typed_check.py`](typed_check.py) | Unit checks for typed IR and mixed-composition rejection |
| [`flexo_tables.py`](flexo_tables.py) | DualGate truth-table decode (incl. multi-output) |
| [`blif.py`](blif.py) | Net → single-rail BLIF |
| [`gold_blif.py`](gold_blif.py) | Spec BLIF for gates / adders / ALU |
| [`abc_run.py`](abc_run.py) | ABC canonicalize + CEC |
| [`../lift/flexo_static.py`](../lift/flexo_static.py) | Per-call DualGate instances + WR-slot wires |
| [`../oracle/native.py`](../oracle/native.py) | Pin a core, parse architectural accuracy after `ρ` |
| [`../extract.py`](../extract.py) | CLI: any ELF, locate → lift → compose → BLIF/C |

## How to run

ABC is built (no readline) at `.deps/abc-master/abc`. From repo root, using the venv:

```bash
./venv/bin/python src/extract.py --self-test
./venv/bin/python src/ir/typed_check.py
./venv/bin/python src/extract.py path/to/binary.elf --no-llm
./venv/bin/python src/extract.py --all --blif --outdir src/output/ir
./venv/bin/python src/extract.py --all --run-native --core 0 --outdir src/output/ir
./venv/bin/python src/eval/check.py
```

Rebuild ABC if needed:

```bash
make -C .deps/abc-master ABC_USE_NO_READLINE=1 -j"$(nproc)"
```

`--json` prints a recovered net. Combined `gate_*.elf` copies share one binary that measures AND first (cold WR/page faults).

## Typed evidence IR

Places may name a **resource** (`dcache`, `btb`, `tlb`, or `register_resource` for others), a **physical key** (cache line, BTB index, VPN), **encoding**, and **destructive-read** / persistence (the last also via `Kind`). `ResourceSpec` supplies per-resource WR/window defaults:

| resource | encoding | destructive read | persistent | default trigger | phys_key |
|---|---|---|---|---|---|
| `dcache` | dual_rail | yes | no | rsb | line |
| `btb` | btb_target | no | yes (width 16) | indirect_jmp | btb_index |
| `tlb` | hit_miss | yes | no | rsb | vpn |

`Evidence` on a place, transition, region, or net holds `trigger`, `observations`, and `confidence`. Boolean DualGate logic lives in `RegionKind.LUT` regions; TAE-style weird-function bodies live in `RegionKind.ISA` regions. Edges between resources are `ConversionEdge` objects only — a GATE/EXPR whose endpoints have different resources is rejected.

`Net.compose()` returns `lut`, `isa`, `converted`, or the legacy `classify()` string. It raises `MixedCompositionError` when:

- LUT and ISA regions (or multiple resources) share a net with no conversion edges
- a GATE/EXPR lists places of more than one resource
- a LUT region contains `expr` transitions or an ISA region contains `gate` transitions

`classify()` is unchanged and may still report `flexo`/`tae`/`mixed` as a derived view; it is not used to fuse typed regions.

## Recovered IR (AND)

`__DualGate__2_1_8` is AND (`id=8` = bit 3 of the 2-input table). Places are logical bits after dual-rail merge; `ρ` is the window rollback.

```json
{
  "name": "and",
  "class": "flexo",
  "places": [
    {"name": "w3", "kind": "volatile", "col": "bit"},
    {"name": "w2", "kind": "volatile", "col": "bit"},
    {"name": "w4", "kind": "volatile", "col": "bit"}
  ],
  "transitions": [
    {
      "name": "__DualGate__2_1_8@139a",
      "kind": "gate",
      "n_in": 2, "n_out": 1, "table_id": 8,
      "gate_table": {"00": 0, "10": 0, "01": 0, "11": 1},
      "expr": null,
      "inputs": ["w3", "w2"],
      "outputs": ["w4"]
    },
    {"name": "rho", "kind": "rollback", "expr": null}
  ]
}
```

## BLIF and ABC decompile (AND)

Recovered BLIF:

```
.model and
.inputs w2 w3
.outputs w4
.names w3 w2 w4
11 1
.end
```

ABC `write_verilog` after `strash`/`dc2`:

```
module and ( w2, w3, w4 );
  input  w2, w3;
  output w4;
  assign w4 = w2 & w3;
endmodule
```

`abc -c 'cec gold.blif impl.blif'` reports **Networks are equivalent** for all eight boolean gates (MUX after a 3-input permutation `i0,s,i1`).

ALU recovers **14 inputs / 6 outputs** (same as `ALU.v`) and 32 DualGate instances; ABC CEC against the spec BLIF is **not** equivalent under sorted wire-id port names (PI order is not the Verilog port order). Adders similarly mismatch gold because the spec BLIF exposes `cout` and the recovered net’s POs are the sum bits only.

## Full Flexo corpus (24 nets)

WeMu’s evaluation set is 24 µWMs = 7 GITM exception gadgets + 17 Flexo/RSB circuits. GITM has no DualGate symbols. This table is every `__weird__*` net in the Flexo ELFs (8 boolean + ALU + 3 adders + SHA-1 round + SHA-1 round broken + 4 SHA-1 2-block rounds + AES round + 4 AES-block helpers + Simon = **24**).

Host: `ytlab01`, Intel Xeon Gold 5222 @ 3.80 GHz (Cascade Lake), `taskset -c 0`. ABC stats are pre-`strash` LUT/BLIF nodes (`nd`). Native accuracy is architectural Flexo readout after rollback. Wired = DualGate calls whose WR arguments resolved to logical wires.

| # | Circuit | ELF | Gates (wired) | ABC i/o | ABC nd | CEC | Native |
|---|---|---|---|---|---|---|---|
| 1 | AND | `gates/gate_and.elf` | 1/1 | 2/1 | 1 | equiv | 15.1% * |
| 2 | OR | same | 1/1 | 2/1 | 1 | equiv | 14.5% * |
| 3 | NOT | same | 1/1 | 1/1 | 1 | equiv | 20.2% * |
| 4 | NAND | same | 1/1 | 2/1 | 1 | equiv | 97.2% |
| 5 | XOR | same | 1/1 | 2/1 | 1 | equiv | 95.6% |
| 6 | MUX | same | 1/1 | 3/1 | 1 | equiv | 98.9% |
| 7 | XOR3 | same | 1/1 | 3/1 | 1 | equiv | 99.4% |
| 8 | XOR4 | same | 1/1 | 4/1 | 1 | equiv | 97.6% |
| 9 | ALU | `alu/ALU-2.elf` | 32/32 | 14/6 | 46 | ports only | **100%** (`-r`, 80 trials) |
| 10 | ADD8 | `arithmetic/adder.elf` | 21/21 | 16/8 | 26 | — | 99.3% (400 trials) |
| 11 | ADD16 | same | 66/66 | 32/16 | 91 | — | 98.3% |
| 12 | ADD32 | same | 150/150 | 64/32 | 211 | — | 98.8% |
| 13 | SHA-1 round | `sha1/sha1_round.elf` | 544/544 | 192/32 | 867 | — | **100%** |
| 14 | SHA-1 round broken | `sha1/sha1_round_broken.elf` | 0/544 | 1172/867 | 867 | unwired | 80% |
| 15–18 | SHA-1 2-block r1–r4 | `sha1/sha1_2blocks-6.elf` | 544, 537, 553, 547 | 192/32 | 867–878 | — | **100%** (ELF) |
| 19 | AES round | `aes/aes_round-16.elf` | 2524/2524 | 256/128 | 4732 | — | **100%** |
| 20 | AES round (in block) | `aes/aes_block-10.elf` | 2524/2524 | 256/128 | 4732 | — | **100%** (ELF) |
| 21 | AES first round | same | 2636/2636 | 384/128 | 5020 | — | (same ELF) |
| 22 | AES last round | same | 2669/2669 | 264/128 | 4865 | — | (same ELF) |
| 23 | AES round-key | same | 669/669 | 136/128 | 1191 | — | (same ELF) |
| 24 | Simon32 | `simon/simon32-14.elf` | 4322/4322 | 96/32 | 8190 | — | 91.7% |

\* Combined gates ELF evaluates AND/OR/NOT first while WRs/pages are still cold in that process; later gates in the **same** 4000-trial run are 95–99%. Undetected error stayed ~0%; remaining misses are Flexo dual-rail **error detected**. ALU/SHA-1/AES admitted at 100% on this CPU.

`sha1_round_broken` is the negative check: DualGate symbols exist but WR-slot copy-prop does not resolve, so ABC sees a disconnected bag of LUTs (1172 inputs). The working SHA-1 round is 544/544 wired, 192/32.

Artifacts from `--blif` land under `src/output/ir/` (gitignored): `<circuit>.blif`, ABC `<circuit>.v`, and `summary.json`.
