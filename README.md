# µWM decompiler

Locate microarchitectural weird-machine regions in unknown stripped ELFs and recover a typed net (Flexo LUTs, GITM exception+dcache gates, TAE ISA/BTB regions, TLB walks). The oracle is **native adapters**, not WeMu. ELFs are not executed unless you pass `--run-native`.

WeMu remains a separate emulator repository and is not part of this tree.

## Submodules (the three public µWM implementations)

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

`--all` walks `*.elf` under the three `third_party/` trees after you build them. `--run-native` pins a core and runs the ELF (Flexo accuracy banners or TAE output). Leave it off unless you are on a CPU that actually implements the gadget (TAE needs SERIALIZE / SPR-class Intel).

Optional LLM naming/C is overlay only (`CURSOR_API_KEY`); `--no-llm` keeps the same IR and CEC.
