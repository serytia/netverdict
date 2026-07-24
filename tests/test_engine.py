"""Unitaires du moteur et des cas de bord du parsing TCP."""

import pytest

from make_fixtures import CLIENT, SERVER, _handshake, _tcp, write_pcap
from dpkt.tcp import TH_ACK, TH_PUSH

from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.rules.engine import Condition, RuleError, _EvidenceFormatter
from netverdict.signals import FlowSignals, compute_signals, seq_le


# ---------------------------------------------------------------- conditions

def test_condition_operators():
    sig = FlowSignals(retrans_total=7, synack_seen=True).as_dict()
    assert Condition.parse("retrans_total >= 5").eval(sig)
    assert Condition.parse("retrans_total < 10").eval(sig)
    assert Condition.parse("synack_seen == true").eval(sig)
    assert not Condition.parse("synack_seen == false").eval(sig)


def test_condition_none_semantics():
    # Un RTT non mesure n'est ni grand ni petit : les relations sont fausses,
    # seul le test d'existence (== none / != none) a un sens.
    sig = FlowSignals().as_dict()          # rtt_ms_p50 = None
    assert not Condition.parse("rtt_ms_p50 >= 50").eval(sig)
    assert not Condition.parse("rtt_ms_p50 < 50").eval(sig)
    assert Condition.parse("rtt_ms_p50 == none").eval(sig)


def test_condition_unknown_field_raises():
    with pytest.raises(RuleError):
        Condition.parse("champ_inexistant >= 1").eval(FlowSignals().as_dict())


def test_evidence_formatter_tolerates_none():
    out = _EvidenceFormatter().vformat(
        "rtt={rtt_ms_p50:.1f} n={pkts_total}", (),
        FlowSignals(pkts_total=4).as_dict())
    assert out == "rtt=n/a n=4"


# ---------------------------------------------------------------- seq 2^32

def test_seq_wraparound():
    assert seq_le(0xFFFFFF00, 0x00000100)   # apres le wrap, 0x100 est "apres"
    assert not seq_le(0x00000100, 0xFFFFFF00)


# ------------------------------------------------------------- cas de bord

def _analyze_pkts(tmp_path, pkts):
    p = tmp_path / "case.pcap"
    write_pcap(p, pkts)
    cap = read_capture(p)
    flows = build_flows(cap)
    assert len(flows) == 1
    return compute_signals(flows[0])


def test_dup_capture_not_counted_as_retrans(tmp_path):
    """Le meme paquet vu deux fois par le sniffer (<0.1 ms, meme ip_id)
    est un doublon de capture, pas une retransmission."""
    pkts = _handshake(0.0, 51100, 80)
    pkts.append(_tcp(0.01, CLIENT, SERVER, 51100, 80, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=b"x" * 100, ip_id=777))
    pkts.append(_tcp(0.01000005, CLIENT, SERVER, 51100, 80, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=b"x" * 100, ip_id=777))
    sig = _analyze_pkts(tmp_path, pkts)
    assert sig.retrans_total == 0
    assert sig.dup_capture_skipped == 1


def test_keepalive_not_counted_as_retrans(tmp_path):
    """Keepalives periodiques (1 octet a snd_nxt-1) : jamais des pertes."""
    pkts = _handshake(0.0, 51101, 80)
    pkts.append(_tcp(0.01, CLIENT, SERVER, 51101, 80, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=b"x" * 100))
    pkts.append(_tcp(0.02, SERVER, CLIENT, 80, 51101, TH_ACK,
                     seq=2001, ack=1101))
    for i in range(3):
        pkts.append(_tcp(10.0 + i * 10, CLIENT, SERVER, 51101, 80, TH_ACK,
                         seq=1100, ack=2001, payload=b"\x00"))
    sig = _analyze_pkts(tmp_path, pkts)
    assert sig.retrans_total == 0


def test_midstream_capture_direction_heuristic(tmp_path):
    """Capture demarree en pleine session : pas de SYN -> sens estime par
    le port bas, et le flag direction_confident doit etre baisse."""
    pkts = [
        _tcp(0.0, CLIENT, SERVER, 51102, 443, TH_PUSH | TH_ACK,
             seq=5000, ack=9000, payload=b"data"),
        _tcp(0.01, SERVER, CLIENT, 443, 51102, TH_ACK, seq=9000, ack=5004),
    ]
    sig = _analyze_pkts(tmp_path, pkts)
    assert sig.started_midstream
    assert not sig.direction_confident
    assert sig.server == SERVER            # port 443 = cote service
    assert sig.client == CLIENT


def test_empty_capture(tmp_path):
    import dpkt
    p = tmp_path / "empty.pcap"
    with open(p, "wb") as f:
        dpkt.pcap.Writer(f)
    cap = read_capture(p)
    assert cap.stats.total == 0
    assert build_flows(cap) == []
