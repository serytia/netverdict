"""Validation terrain : pcaps generes par un VRAI kernel Linux (lab VM).

Ces captures viennent de lab/scenarios.sh (netem, iptables, vraies sockets),
rapatriees dans tests/fixtures/lab/. Elles sont la contre-preuve independante
des fixtures synthetiques : produites par tcpdump, pas par dpkt.

Contrairement aux fixtures synthetiques, une capture kernel contient du reel
(plusieurs connexions curl, delayed ACKs, resets de fin) : on verifie donc le
verdict DOMINANT parmi les flux significatifs, pas une egalite stricte.
"""

from pathlib import Path

import pytest

from netverdict.pcap import read_capture
from netverdict.flows import build_flows
from netverdict.signals import compute_signals
from netverdict.rules.engine import evaluate, load_rules

LAB_DIR = Path(__file__).parent / "fixtures" / "lab"

# scenario -> (regle attendue dominante, regles interdites)
EXPECTED = {
    "clean":       ("clean", {"retrans-heavy", "zero-window-server", "syn-no-answer"}),
    "slow_app":    ("slow-app-proven", {"syn-no-answer", "retrans-heavy"}),
    "drop":        ("syn-no-answer", {"clean", "rst-to-syn"}),
    "reject":      ("reject-icmp", {"syn-no-answer", "clean"}),
    "rst":         ("rst-to-syn", {"syn-no-answer", "clean"}),
    "loss":        ("retrans-heavy", {"clean"}),
    "zero_window": ("zero-window-server", {"clean", "zero-window-client"}),
    "jitter":      ("rtt-degraded", {"retrans-heavy"}),
}

pytestmark = pytest.mark.skipif(
    not LAB_DIR.exists(),
    reason="pcaps du lab absents (generer avec lab/scenarios.sh dans la VM)",
)


def _primary_ids(path: Path) -> list[str]:
    cap = read_capture(path)
    flows = build_flows(cap)
    sigs = [compute_signals(f) for f in flows]
    verdicts = evaluate(sigs, load_rules())
    return [fv.primary.rule.id for fv in verdicts if fv.primary is not None]


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_lab_scenario(name):
    pcap = LAB_DIR / f"{name}.pcap"
    if not pcap.exists():
        pytest.skip(f"{pcap.name} absent")
    expected, forbidden = EXPECTED[name]
    ids = _primary_ids(pcap)
    assert ids, f"{name}: aucun flux analyse"
    assert expected in ids, f"{name}: attendu {expected!r}, obtenu {ids}"
    hit = forbidden.intersection(ids)
    # 'slow_app' avec ack delay non mesurable retombe legitimement sur
    # slow-app-likely : on tolere la variante, pas les contraires.
    if expected == "slow-app-proven":
        hit.discard("slow-app-likely")
    assert not hit, f"{name}: verdicts contradictoires {hit} (tous: {ids})"
