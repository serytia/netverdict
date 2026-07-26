"""Comparaison de deux captures du meme trafic (v2).

Les fixtures sont fabriquees a partir d'une capture de reference dont on
derive une seconde vue : horloge decalee, et selon le test, des segments
retires — ce qui simule exactement une perte ENTRE les deux points.
"""

import json

import dpkt
import pytest

from make_fixtures import CLIENT, SERVER, _handshake, _tcp, write_pcap
from dpkt.tcp import TH_ACK, TH_PUSH

from netverdict.cli import main
from netverdict.compare import comparer, estimer_horloges


def _echange(t0=0.0, n_data=5):
    """Handshake + n segments client->serveur, chacun acquitte."""
    pkts = _handshake(t0, 51000, 80)
    seq, t = 1001, t0 + 0.01
    for i in range(n_data):
        pkts.append(_tcp(t, CLIENT, SERVER, 51000, 80, TH_PUSH | TH_ACK,
                         seq=seq, ack=2001, payload=bytes([i]) * 100))
        pkts.append(_tcp(t + 0.002, SERVER, CLIENT, 80, 51000, TH_ACK,
                         seq=2001, ack=seq + 100))
        seq += 100
        t += 0.01
    return pkts


def _decaler(pkts, offset, latence=0.001, perdre=()):
    """Vue du meme trafic depuis le point AVAL (cote serveur).

    Le signe de la latence DEPEND DU SENS, et s'y tromper invalide le test :
    un paquet client->serveur est vu en aval APRES l'amont (+L), mais un
    paquet serveur->client est emis en aval, donc vu la-bas AVANT (-L).
    Une premiere version appliquait +L aux deux sens : l'aller et le retour
    se compensaient et la latence estimee tombait a 0.
    """
    out = []
    for i, (ts, buf) in enumerate(pkts):
        if i in perdre:
            continue
        eth = dpkt.ethernet.Ethernet(buf)
        vers_serveur = eth.data.data.dport == 80
        out.append((ts + offset + (latence if vers_serveur else -latence), buf))
    return out


def _paire(tmp_path, offset=1234.5, perdre=()):
    amont, aval = tmp_path / "a.pcap", tmp_path / "b.pcap"
    pkts = _echange()
    write_pcap(amont, pkts)
    write_pcap(aval, _decaler(pkts, offset, perdre=perdre))
    return amont, aval


# --- appariement et comptage ----------------------------------------------

def test_sans_perte_le_chemin_est_hors_de_cause(tmp_path):
    a, b = _paire(tmp_path)
    resultats, diag = comparer(a, b)
    assert diag["flux_communs"] == 1
    assert not diag["nat_probable"]
    verdict, phrase = resultats[0].verdict()
    assert verdict == "RAS"
    assert "hors de cause" in phrase
    assert all(e.perdus == 0 for e in resultats[0].ecarts)


def test_segments_manquants_en_aval_designent_le_chemin(tmp_path):
    # On retire deux segments de donnees de la vue aval : ils ont ete emis
    # mais ne sont jamais arrives au second point.
    a, b = _paire(tmp_path, perdre=(3, 5))
    resultats, _ = comparer(a, b)
    verdict, phrase = resultats[0].verdict()
    assert verdict == "RESEAU"
    assert "ENTRE les deux points" in phrase
    assert sum(e.perdus for e in resultats[0].ecarts) == 2


# --- decalage d'horloge : le piege principal -------------------------------

def test_l_offset_d_horloge_est_estime_et_neutralise(tmp_path):
    """Sans estimation, une horloge decalee de 20 minutes donnerait une
    latence de 20 minutes presentee comme un fait."""
    a, b = _paire(tmp_path, offset=1200.0)
    resultats, _ = comparer(a, b)
    c = resultats[0]
    assert c.offset_horloge_s == pytest.approx(1200.0, abs=0.01)
    # La latence, elle, reste de l'ordre de la milliseconde simulee.
    assert c.latence_reseau_ms == pytest.approx(1.0, abs=0.5)


def test_un_syn_retransmis_ne_fausse_pas_l_horloge(tmp_path):
    """Bug trouve au lab kernel (26/07) : le SYN initial jete par le
    simulateur de perte, l'aval ne voyait que la RETRANSMISSION. Apparier
    « le premier de A » avec « le premier de B » comparait alors l'original
    a sa retransmission et comptait un RTO entier (1 s) comme de la latence
    — 511 ms annoncees sur un lien local. La reference doit etre unique des
    deux cotes."""
    pkts = _echange()
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    # Amont : le SYN est emis deux fois (original perdu, puis retransmis 1 s
    # plus tard). Aval : seule la retransmission arrive.
    syn_ts, syn_buf = pkts[0]
    amont = [(syn_ts, syn_buf), (syn_ts + 1.02, syn_buf)] + pkts[1:]
    write_pcap(a, amont)
    aval = _decaler([(syn_ts + 1.02, syn_buf)] + pkts[1:], offset=0.0)
    write_pcap(b, aval)

    resultats, _ = comparer(a, b)
    c = resultats[0]
    # Sans le correctif : ~0.5 s d'offset et ~510 ms de latence inventes.
    assert abs(c.offset_horloge_s or 0) < 0.05
    assert (c.latence_reseau_ms or 0) < 50


def test_sans_handshake_aucune_latence_n_est_inventee(tmp_path):
    """Capture demarree en pleine session : pas de reference commune. On
    doit se taire sur la latence, pas la deviner."""
    pkts = _echange()[3:]              # on coupe le handshake
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    write_pcap(a, pkts)
    write_pcap(b, _decaler(pkts, 5.0))
    resultats, _ = comparer(a, b)
    c = resultats[0]
    assert c.offset_horloge_s is None
    assert c.latence_reseau_ms is None
    assert "non estimable" in c.note
    # Les comptages, eux, restent exploitables.
    assert sum(e.segments_amont for e in c.ecarts) > 0


# --- NAT : ne pas rendre un rapport vide qui ressemble a « rien a signaler »

def test_nat_probable_est_signale(tmp_path):
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    write_pcap(a, _echange())
    # Meme trafic vu apres traduction d'adresse : autre IP cliente.
    autre = [_tcp(ts, "203.0.113.7", SERVER, 41000, 80, TH_ACK, seq=1, ack=1)
             for ts in (0.0, 0.1)]
    write_pcap(b, autre)
    resultats, diag = comparer(a, b)
    assert diag["nat_probable"] is True
    assert resultats == []


# --- bout en bout CLI ------------------------------------------------------

def test_cli_compare_json(tmp_path, capsys):
    a, b = _paire(tmp_path, perdre=(3,))
    rc = main(["compare", str(a), str(b), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1                                  # perte detectee
    assert out["flux"][0]["verdict"] == "RESEAU"
    assert out["flux"][0]["sens"][0]["perdus"] == 1


def test_cli_compare_nat_code_2(tmp_path, capsys):
    a, b = tmp_path / "a.pcap", tmp_path / "b.pcap"
    write_pcap(a, _echange())
    write_pcap(b, [_tcp(0.0, "203.0.113.7", SERVER, 41000, 80, TH_ACK,
                        seq=1, ack=1)])
    assert main(["compare", str(a), str(b)]) == 2
    assert "NAT" in capsys.readouterr().out
