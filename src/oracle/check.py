"""Small checks for native adapters. Run: python src/oracle/check.py"""

import sys
from pathlib import Path

if __name__ == "__main__" and __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from ir.net import Evidence, Net, resource_spec
    from oracle.btb import BtbAdapter
    from oracle.cache import CacheAdapter
    from oracle.runner import AdapterConfig, NativeRunner, majority
    from oracle.tlb import TlbAdapter
else:
    from ir.net import Evidence, Net, resource_spec
    from oracle.btb import BtbAdapter
    from oracle.cache import CacheAdapter
    from oracle.runner import AdapterConfig, NativeRunner, majority
    from oracle.tlb import TlbAdapter


def check_no_universal_wr_api() -> None:
    for name in ("write0", "write1", "read"):
        for cls in (CacheAdapter, BtbAdapter, TlbAdapter):
            assert name not in cls.__dict__, (cls, name)
    assert CacheAdapter.wemu_supported is False
    assert BtbAdapter.wemu_supported is False
    assert TlbAdapter.wemu_supported is False
    assert hasattr(CacheAdapter, "decode_dual_rail")
    assert hasattr(CacheAdapter, "test_line_causality")
    assert not hasattr(BtbAdapter, "decode_dual_rail")
    assert hasattr(BtbAdapter, "train")
    assert hasattr(BtbAdapter, "observe_target")
    assert hasattr(BtbAdapter, "test_index_causality")
    assert not hasattr(TlbAdapter, "observe_target")
    assert hasattr(TlbAdapter, "decode_translation")
    assert hasattr(TlbAdapter, "test_vpn_causality")
    # BTB/TLB record unemulated without samples; cache uses no_samples instead
    assert CacheAdapter().unavailable("unemulated").uncertainty == "no_samples"


def check_affinity_and_repeats() -> None:
    cfg = AdapterConfig(core=3, repetitions=5)
    r = NativeRunner(cfg)
    cmd = r.taskset_cmd(["./a.elf", "-t", "10"])
    assert cmd[:4] == ["taskset", "-c", "3", "./a.elf"]
    xs = r.repeat(lambda: 1, n=5)
    assert xs == [1, 1, 1, 1, 1]
    val, agr, n = majority([0, 1, 1, 1, 1])
    assert val == 1 and n == 5 and agr == 0.8


def check_cache_calibration_and_dual_rail() -> None:
    ad = CacheAdapter(cfg=AdapterConfig(core=0, repetitions=8))
    hits = [40, 42, 41, 39, 43]
    misses = [280, 300, 290, 310, 295]
    cal = ad.calibrate_occupancy(hits, misses)
    assert cal.ok and cal.threshold is not None
    assert 43 < cal.threshold < 280
    hit = ad.decode_occupancy(41)
    miss = ad.decode_occupancy(300)
    assert hit.value == 1 and not hit.invalid
    assert miss.value == 0 and not miss.invalid
    band = ad.decode_occupancy(cal.threshold)
    assert band.invalid and band.uncertainty == "threshold"
    zero = ad.decode_dual_rail(41, 300)  # minus hit, plus miss → 0
    one = ad.decode_dual_rail(300, 41)
    both = ad.decode_dual_rail(40, 42)
    none = ad.decode_dual_rail(300, 310)
    assert zero.value == 0 and one.value == 1
    assert both.invalid and both.uncertainty == "both_rails"
    assert none.invalid and none.uncertainty == "both_rails"
    rec = ad.recover_dual_rail([(300, 41)] * 7 + [(40, 42)])
    assert rec.value == 1 and rec.confidence is not None and rec.confidence > 0.7


def check_cache_causality_and_record() -> None:
    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 8, [300] * 8)
    yes = ad.test_line_causality("0x4000", [300] * 8, [41] * 8)
    assert yes.causal is True and yes.value == 1
    no = ad.test_line_causality("0x4000", [300] * 8, [295] * 8)
    assert no.causal is False and no.uncertainty == "no_effect"
    net = Net("cache_wr")
    p = ad.record(net, "c0", phys_key="0x4000", result=yes)
    assert p.resource == "dcache" and p.encoding == "dual_rail"
    assert p.destructive_read is True
    assert p.evidence is not None and p.evidence.confidence == yes.confidence
    assert any(o.get("causal") for o in p.evidence.observations)
    assert net.native["adapters"]["dcache"][0]["protocol"] == "flush_reload"


def check_btb_unemulated_and_causality() -> None:
    ad = BtbAdapter()
    assert ad.wemu_supported is False
    missing = ad.observe_target([])
    assert missing.uncertainty == "unemulated" and missing.confidence is None
    assert missing.invalid and missing.value is None
    net = Net("tae")
    p = ad.record(net, "b0", phys_key="pc:0x10")
    assert p.resource == "btb" and p.encoding == "btb_target"
    assert p.destructive_read is False
    assert p.kind.value == "persistent"
    ev = p.evidence
    assert ev is not None and ev.confidence is None
    assert any(o.get("uncertainty") == "unemulated" for o in ev.observations)
    assert net.native["adapters"]["btb"][0]["uncertainty"] == "unemulated"

    ad.train("pc:0x10", 0x2000)
    assert ad.flush_state == "trained"
    ok = ad.test_index_causality("pc:0x10", [0x1000] * 8, [0x2000] * 8, expected_target=0x2000)
    assert ok.causal is True and ok.value == 0x2000
    ad.flush()
    assert ad.flush_state == "flushed"
    mixed = ad.observe_target([1, 2, 3, 4])
    assert mixed.invalid and mixed.uncertainty == "unstable"
    none = ad.test_index_causality("pc:0x10", [0x1000] * 8, [0x1000] * 8)
    assert none.causal is False and none.uncertainty == "no_effect"
    no_native = ad.test_index_causality("pc:0x10", [], [])
    assert no_native.uncertainty == "unemulated"


def check_tlb_unemulated_and_causality() -> None:
    ad = TlbAdapter()
    assert ad.wemu_supported is False
    assert ad.trigger == resource_spec("tlb").trigger
    empty = ad.recover_hit_miss([])
    assert empty.uncertainty == "unemulated" and empty.wemu_supported is False
    net = Net("tlb")
    p = ad.record(net, "t0", phys_key="0x1000", result=empty)
    assert p.resource == "tlb" and p.encoding == "hit_miss"
    assert p.destructive_read is True
    assert any(o.get("uncertainty") == "unemulated" for o in (p.evidence.observations if p.evidence else []))

    ad.calibrate_translation([30] * 6, [400] * 6)
    hit = ad.decode_translation(30)
    miss = ad.decode_translation(400)
    assert hit.value == 1 and miss.value == 0
    yes = ad.test_vpn_causality("0x1000", [400] * 6, [31] * 6)
    assert yes.causal is True and ad.flush_state == "filled"
    no = ad.test_vpn_causality("0x1000", [410] * 6, [390] * 6)
    assert no.causal is False
    no_native = ad.test_vpn_causality("0x2000", [], [])
    assert no_native.uncertainty == "unemulated"


def check_evidence_shape() -> None:
    ad = CacheAdapter()
    ad.calibrate_occupancy([40] * 4, [300] * 4)
    r = ad.decode_dual_rail(300, 40, phys_key="line0")
    ev = r.to_evidence()
    assert isinstance(ev, Evidence)
    assert ev.trigger == "rsb"
    assert ev.confidence == 1.0
    d = r.to_dict()
    assert d.get("invalid") is False
    assert "uncertainty" not in d
    assert d["value"] == 1


def main() -> None:
    check_no_universal_wr_api()
    check_affinity_and_repeats()
    check_cache_calibration_and_dual_rail()
    check_cache_causality_and_record()
    check_btb_unemulated_and_causality()
    check_tlb_unemulated_and_causality()
    check_evidence_shape()
    print("oracle-check: adapters, calibration, uncertainty, causality ok")


if __name__ == "__main__":
    main()
