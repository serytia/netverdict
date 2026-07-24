"""Verdict de bout en bout par scenario : pcap -> flux -> signaux -> regle.

Chaque test verifie (a) LA regle primaire attendue et (b) les 2-3 signaux
mesures qui la justifient — pour qu'une regression de mesure ne puisse pas
se cacher derriere un verdict encore correct par accident.
"""


def _rule_ids(fv):
    return [m.rule.id for m in fv.matches]


def test_syn_no_answer(analyze):
    sig, fv = analyze("syn_no_answer")
    assert fv.primary.rule.id == "syn-no-answer"
    assert fv.verdict == "RESEAU"
    assert sig.syn_count == 3
    assert not sig.synack_seen
    assert 2.9 < sig.syn_span_s < 3.1


def test_rst_to_syn(analyze):
    sig, fv = analyze("rst_to_syn")
    assert fv.primary.rule.id == "rst-to-syn"
    assert fv.verdict == "APP"
    assert sig.rst_to_syn
    assert 1.0 < sig.rst_to_syn_ms < 3.0
    assert sig.closed_by == "rst_server"
    assert not sig.rst_midstream          # RST au SYN != RST en pleine session


def test_reject_icmp(analyze):
    sig, fv = analyze("reject_icmp")
    assert fv.primary.rule.id == "reject-icmp"
    assert fv.verdict == "RESEAU"
    assert sig.icmp_admin_prohibited
    assert sig.icmp_admin_prohibited_from == "10.0.0.1"
    # Le unless doit empecher le doublon avec syn-no-answer
    assert "syn-no-answer" not in _rule_ids(fv)


def test_retrans_heavy(analyze):
    sig, fv = analyze("retrans_heavy")
    assert fv.primary.rule.id == "retrans-heavy"
    assert fv.verdict == "RESEAU"
    assert sig.retrans_c2s == 6
    assert sig.retrans_s2c == 0
    assert sig.retrans_rate >= 0.03
    assert "clean" not in _rule_ids(fv)


def test_zero_window_server(analyze):
    sig, fv = analyze("zero_window_server")
    assert fv.primary.rule.id == "zero-window-server"
    assert fv.verdict == "HOTE"
    assert sig.zw_from_server == 2
    assert sig.zw_from_client == 0
    assert 350 < sig.zw_max_ms < 450       # fenetre fermee 0.04 -> 0.44
    assert "slow-app-proven" not in _rule_ids(fv)


def test_slow_app(analyze):
    sig, fv = analyze("slow_app")
    assert fv.primary.rule.id == "slow-app-proven"
    assert fv.verdict == "APP"
    assert sig.exchanges == 3
    assert 750 < sig.ttfb_ms_p50 < 850
    assert sig.server_ack_delay_ms_p95 is not None
    assert sig.server_ack_delay_ms_p95 < 50
    assert sig.retrans_total == 0


def test_clean(analyze):
    sig, fv = analyze("clean")
    assert fv.primary.rule.id == "clean"
    assert fv.verdict == "RAS"
    assert sig.handshake_complete
    assert sig.retrans_total == 0
    assert sig.zw_from_client == sig.zw_from_server == 0
    assert sig.exchanges == 3
    assert sig.ttfb_ms_p95 < 100
    assert sig.closed_by == "fin"
    # Un flux sain ne doit declencher AUCUNE autre regle
    assert _rule_ids(fv) == ["clean"]


def test_midstream_rst(analyze):
    sig, fv = analyze("midstream_rst")
    assert fv.primary.rule.id == "rst-midstream"
    assert fv.verdict == "AMBIGU"
    assert sig.rst_midstream
    assert sig.rst_emitter == "10.0.0.5"
    assert sig.closed_by == "rst_server"


def test_mtu_blackhole(analyze):
    sig, fv = analyze("mtu_blackhole")
    assert fv.primary.rule.id == "mtu-blackhole"
    assert fv.verdict == "RESEAU"
    assert sig.icmp_frag_needed
    assert sig.retrans_c2s == 2
    # 2 retrans < plancher de 5 : retrans-heavy ne doit PAS matcher
    assert "retrans-heavy" not in _rule_ids(fv)
