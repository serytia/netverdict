"""La fenetre de scan : dedouaner ou accuser, avec des dates.

Un serveur tombe quelques minutes apres un balayage de ports. Tout le monde
accuse le balayage. Pour trancher, il faut deux choses que personne ne lit a la
main : la fenetre EXACTE du scan (debut ET fin), et sa position par rapport a ce
qui s'est reellement passe dans les journaux.

Ce fichier verrouille trois proprietes, dans l'ordre de ce qu'elles couteraient
si elles lachaient :

  1. Un balayage present dans la capture est vu, avec son compte de ports et sa
     duree.
  2. Un client qui TRAVAILLE n'est jamais pris pour un scanner. C'est le
     non-comportement central : accuser a tort est le seul defaut que cet outil
     ne peut pas se permettre, puisqu'il existe pour eviter cette accusation.
  3. Quand un scan et une rafale coexistent, le rapport les PLACE l'un par
     rapport a l'autre. Deux faits cote a cote laissent l'admin accuser le
     scan ; la phrase de synthese est ce qui le dedouane.
"""

from __future__ import annotations

import io
import json

import pytest
from dpkt.tcp import TH_ACK, TH_PUSH, TH_SYN
from rich.console import Console

from make_fixtures import CLIENT, SERVER, _handshake, _tcp, write_pcap
from netverdict.burst import BurstEvent
from netverdict.correlate import SUSPECT_CATEGORIES, suspects_for
from netverdict.flows import (SCAN_MIN_PORTS, SCAN_WINDOW_S, ScanEvent,
                              build_flows, detect_scans)
from netverdict.pcap import read_capture
from netverdict.report import (render_scans, scan_burst_summary, scans_of,
                               to_json)
from netverdict.timeline import CHANGE_CATEGORIES, SourceStats, Timeline

PORT_BASE = 1000


# --------------------------------------------------------------- fabrication

def _pcap_scan(tmp_path, nom="scan", ports=40, duree=5.0, t0=0.0):
    """`ports` SYN sans reponse vers autant de ports distincts, en `duree` s.

    Un scanner ouvre et abandonne : aucun SYN+ACK, aucune donnee. C'est
    exactement ce que produit un balayage TCP connect() sur des ports fermes.
    """
    pas = duree / max(1, ports - 1)
    pkts = [_tcp(t0 + i * pas, CLIENT, SERVER, 40000 + i, PORT_BASE + i,
                 TH_SYN, seq=1000 + i)
            for i in range(ports)]
    p = tmp_path / f"{nom}.pcap"
    write_pcap(p, pkts)
    return p


def _pcap_connexions_etablies(tmp_path, nom="etabli", n=40, duree=600.0,
                              meme_port=False):
    """`n` connexions ETABLIES qui echangent des octets, etalees sur `duree`.

    Le client emet, pour chaque connexion, un SYN puis un ACK, des donnees et un
    ACK final : les SYN y sont mecaniquement minoritaires. C'est un client qui
    travaille, pas un scanner — et c'est le cas qu'il ne faut jamais accuser.
    """
    pas = duree / max(1, n - 1)
    pkts = []
    for i in range(n):
        t = i * pas
        sport = PORT_BASE if meme_port else PORT_BASE + i
        pkts += _handshake(t, 40000 + i, sport)
        pkts.append(_tcp(t + 0.01, CLIENT, SERVER, 40000 + i, sport,
                         TH_PUSH | TH_ACK, seq=1001, ack=2001,
                         payload=b"GET / HTTP/1.1\r\n\r\n"))
        pkts.append(_tcp(t + 0.02, SERVER, CLIENT, sport, 40000 + i, TH_ACK,
                         seq=2001, ack=1019))
        pkts.append(_tcp(t + 0.03, CLIENT, SERVER, 40000 + i, sport, TH_ACK,
                         seq=1019, ack=2001))
    pkts.sort(key=lambda x: x[0])
    p = tmp_path / f"{nom}.pcap"
    write_pcap(p, pkts)
    return p


def _scans(chemin):
    return detect_scans(build_flows(read_capture(chemin)))


def _rafale(ts, *, span=60.0, lines=900):
    return BurstEvent(
        ts=ts, source="syslog", host="db01", category="burst", severity=2,
        ident="app",
        message=f"{lines} lines in {span:.0f} s (peak {lines}/min, "
                f"baseline 5/min): ORA-00060: deadlock detected",
        end=ts + span, lines=lines, peak_per_min=lines, baseline_per_min=5,
        sample="ORA-00060: deadlock detected")


def _balayage(ts, *, span=60.0, ports=40):
    return ScanEvent(
        ts=ts, source="pcap", host=SERVER, category="scan", severity=2,
        ident=CLIENT,
        message=f"port scan from {CLIENT} to {SERVER}: {ports} ports "
                f"in {span:.0f} s",
        end=ts + span, ports=ports, client=CLIENT, server=SERVER)


def _tl(*events):
    tl = Timeline()
    tl.add_source("test", list(events), SourceStats())
    return tl


# --------------------------------------- 1. Un balayage present est bien vu

def test_quarante_syn_vers_quarante_ports_en_cinq_secondes_est_un_scan(tmp_path):
    """Le cas d'ecole. Un seul evenement, pas quarante : la fenetre est UNE
    observation, sinon le rapport la compterait autant de fois qu'elle a de
    sondes."""
    out = _scans(_pcap_scan(tmp_path))
    assert len(out) == 1
    s = out[0]
    assert isinstance(s, ScanEvent)
    assert s.category == "scan"
    assert s.ports == 40
    assert s.client == CLIENT and s.server == SERVER
    # ts = PREMIER SYN, end = dernier : c'est la fin qui dedouane.
    assert s.ts == pytest.approx(0.0, abs=1e-3)
    assert s.end == pytest.approx(5.0, abs=1e-3)
    assert s.message == f"port scan from {CLIENT} to {SERVER}: 40 ports in 5 s"
    # L'hote du rapport est la CIBLE, l'ident est le sondeur.
    assert s.host == SERVER and s.ident == CLIENT
    assert s.severity == 2 and s.tz_known is True


def test_un_balayage_plus_long_que_la_fenetre_reste_un_seul_evenement(tmp_path):
    """80 ports sur 200 s : aucune fenetre de 120 s ne les contient tous, mais
    les fenetres se recouvrent. Sans la fusion, le rapport annoncerait des
    dizaines de scans pour un seul balayage."""
    out = _scans(_pcap_scan(tmp_path, ports=80, duree=200.0))
    assert len(out) == 1
    assert out[0].ports == 80
    assert out[0].end - out[0].ts == pytest.approx(200.0, abs=1e-2)


# ------------------------------------ 2. Un client qui travaille est epargne

def test_quarante_connexions_etablies_sur_dix_minutes_ne_sont_pas_un_scan(tmp_path):
    """LE non-comportement du chantier. Un client qui ouvre 40 services d'un
    serveur en 10 minutes et parle sur chacun n'est pas un scanner : ni le
    rythme (40 ports en 600 s), ni la forme (des sessions qui echangent des
    octets) ne sont ceux d'un balayage. Le declarer scan ferait accuser un
    integrateur a la place de la vraie cause."""
    assert _scans(_pcap_connexions_etablies(tmp_path)) == []


def test_quarante_connexions_etablies_en_cinq_secondes_non_plus(tmp_path):
    """Meme non-comportement, la fenetre temporelle mise hors jeu : les 40
    connexions tiennent dans 5 s. Ce qui les sauve ici est la MAJORITE de SYN
    sans donnees, pas le calendrier — les deux criteres tiennent seuls."""
    assert _scans(_pcap_connexions_etablies(tmp_path, duree=5.0)) == []


def test_quarante_connexions_vers_le_meme_port_ne_sont_pas_un_scan(tmp_path):
    """Un navigateur ouvre des dizaines de sockets vers le port 443. Compter
    les CONNEXIONS au lieu des PORTS DISTINCTS transformerait tout client
    charge en scanner."""
    assert _scans(_pcap_connexions_etablies(tmp_path, duree=5.0,
                                            meme_port=True)) == []


def test_juste_sous_le_seuil_de_ports_ne_declenche_pas(tmp_path):
    """29 ports : le seuil est un seuil, il ne s'arrondit pas vers le bas."""
    assert _scans(_pcap_scan(tmp_path, ports=SCAN_MIN_PORTS - 1)) == []
    assert len(_scans(_pcap_scan(tmp_path, nom="pile",
                                 ports=SCAN_MIN_PORTS))) == 1


def test_les_memes_ports_etales_au_dela_de_la_fenetre_ne_declenchent_pas(tmp_path):
    """40 ports repartis sur une heure : c'est le rythme d'un superviseur qui
    teste une liste de services, pas d'un scanner."""
    assert _scans(_pcap_scan(tmp_path, duree=SCAN_WINDOW_S * 30)) == []


def test_aucun_flux_donne_une_liste_vide():
    assert detect_scans([]) == []


# ----------------------------- 3. La categorie : suspecte, jamais changement

def test_scan_est_suspect_sans_etre_un_changement_d_infra(tmp_path):
    """Meme discipline que la rafale : rien n'a CHANGE dans l'infra parce que
    quelqu'un a sonde des ports. La fenetre reste hors de `Timeline.changes()`
    et entre dans les suspects, avec affinite RESEAU et APP."""
    from netverdict.correlate import _AFFINITY

    assert "scan" not in CHANGE_CATEGORIES
    assert "scan" in SUSPECT_CATEGORIES
    assert "scan" in _AFFINITY["RESEAU"] and "scan" in _AFFINITY["APP"]

    tl = _tl(_balayage(0.0))
    assert tl.changes() == []


def test_un_scan_avant_le_flux_est_un_suspect(analyze):
    """Verdict RESEAU (SYN sans reponse) et balayage 60 s avant : le rapport
    doit le montrer. C'est la moitie « accuser » de la fonctionnalite ; l'autre
    moitie est la phrase de synthese."""
    _sig, fv = analyze("syn_no_answer")
    assert fv.verdict == "RESEAU"
    t = fv.signals.t_first
    out = suspects_for(fv, _tl(_balayage(t - 120, span=60.0)))
    assert len(out) == 1
    assert out[0].event.category == "scan"
    assert out[0].affinity is True
    assert round(out[0].delay_s) == 120


# ------------------------------------------- 4. La phrase qui tranche (i18n)

def test_scan_puis_rafale_180_s_plus_tard_donne_le_delta():
    """Le scenario d'origine, reduit a sa phrase. Le scan se termine a 1060, la
    rafale commence a 1240 : 180 s d'ecart, et donc le scan etait FINI depuis
    trois minutes quand l'application est partie en boucle."""
    import re

    tl = _tl(_balayage(1000.0, span=60.0), _rafale(1240.0))
    for lang, gabarit in (("fr", "avant le debut de la rafale"),
                          ("en", "before the burst started")):
        phrase = scan_burst_summary(tl, lang)
        assert phrase is not None and gabarit in phrase
        secondes = float(re.search(r"(\d+(?:\.\d+)?) s", phrase).group(1))
        assert abs(secondes - 180.0) <= 1.0, phrase


def test_une_rafale_commencee_pendant_le_scan_le_dit():
    """L'autre branche : la rafale demarre a l'interieur de la fenetre. Aucun
    delta n'est affiche, parce qu'il n'y en a pas a afficher — le scan courait
    encore."""
    tl = _tl(_balayage(1000.0, span=120.0), _rafale(1030.0))
    assert scan_burst_summary(tl, "fr") == ("la rafale a commence pendant "
                                            "le scan")
    assert scan_burst_summary(tl, "en") == ("the burst started while the scan "
                                            "was running")


def test_pas_de_phrase_quand_il_manque_un_des_deux_faits():
    """La synthese est une COMPARAISON : sans les deux termes, elle n'existe
    pas. Une phrase inventee ici vaudrait un faux temoignage."""
    assert scan_burst_summary(_tl(_balayage(1000.0)), "fr") is None
    assert scan_burst_summary(_tl(_rafale(1000.0)), "fr") is None
    assert scan_burst_summary(None, "fr") is None
    # Rafale ANTERIEURE au scan : aucune des deux phrases n'est vraie.
    assert scan_burst_summary(_tl(_balayage(2000.0), _rafale(1000.0)),
                              "fr") is None


def test_la_section_console_sort_et_reste_muette_sans_scan():
    def _rendu(tl, lang="fr"):
        buf = io.StringIO()
        render_scans(tl, Console(file=buf, width=100), lang=lang)
        return buf.getvalue()

    assert _rendu(_tl()) == "", "aucune section quand il n'y a rien a dire"
    sortie = _rendu(_tl(_balayage(1000.0, span=60.0), _rafale(1240.0)))
    assert "Balayages de ports :" in sortie
    assert f"{CLIENT} -> {SERVER} : 40 ports en 60 s" in sortie
    assert "avant le debut de la rafale" in sortie

    en = _rendu(_tl(_balayage(1000.0, span=60.0), _rafale(1240.0)), "en")
    assert "Port scan windows:" in en
    assert "40 ports in 60 s" in en
    # Filet i18n : aucun mot francais ni accent dans la sortie anglaise.
    import re
    assert not re.search(r"\b(avant|pendant|ports en|balayage)\b", en, re.I)
    assert not re.search(r"[À-ÿ]", en)


# ------------------------------------------------ 5. Bout en bout, JSON, CLI

def test_le_json_expose_les_scans_avec_leur_fin(tmp_path):
    """`end` est le champ qui dedouane : sans lui, un consommateur machine ne
    peut pas dire si le balayage etait termine quand les ennuis ont commence."""
    cap = read_capture(_pcap_scan(tmp_path))
    tl = _tl(*detect_scans(build_flows(cap)))
    rapport = json.loads(to_json(cap, [], timeline=tl))
    assert len(rapport["scans"]) == 1
    s = rapport["scans"][0]
    assert s["client"] == CLIENT and s["server"] == SERVER
    assert s["ports"] == 40
    assert s["end"] - s["start"] == pytest.approx(5.0, abs=1e-2)
    # Cle toujours presente, liste vide comprise : « aucun scan » et « cette
    # version ne sait pas les detecter » ne doivent pas se ressembler.
    assert json.loads(to_json(cap, [], timeline=_tl()))["scans"] == []
    assert "scan_burst_summary" not in json.loads(to_json(cap, [], timeline=_tl()))


def test_le_cli_voit_le_scan_sans_aucune_source_de_journaux(tmp_path, capsys):
    """Un scan se lit dans la CAPTURE. Le taire parce que l'admin n'a pas passe
    --syslog serait une panne muette : il n'a aucune raison de deviner qu'une
    option lui cachait un fait deja present dans son pcap."""
    from netverdict.cli import main

    main(["analyze", str(_pcap_scan(tmp_path)), "--json", "--lang", "fr"])
    rapport = json.loads(capsys.readouterr().out)
    assert len(rapport["scans"]) == 1
    assert rapport["scans"][0]["ports"] == 40
    assert [e["category"] for e in rapport["timeline"]["events"]] == ["scan"]


def test_le_cli_ne_fabrique_pas_de_timeline_sans_scan(tmp_path, capsys):
    """Non-regression du branchement precedent : une capture ordinaire sans
    source ne gagne ni section timeline ni cle « scans »."""
    from netverdict.cli import main

    main(["analyze", str(_pcap_connexions_etablies(tmp_path, n=3, duree=1.0)),
          "--json"])
    rapport = json.loads(capsys.readouterr().out)
    assert "timeline" not in rapport and "scans" not in rapport


def test_le_corpus_du_lab_ne_bouge_pas_sans_l_option_burst(tmp_path, monkeypatch):
    """Les deux proprietes de la demo (10 002 lignes, exactement 400 « error »)
    doivent survivre a l'ajout de --burst. Une option qui change le defaut est
    une option qui casse la demo sans le dire."""
    import runpy
    import sys
    from pathlib import Path as _P

    lab = _P(__file__).parent.parent / "lab" / "gen_syslog_corpus.py"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(lab)])
    runpy.run_path(str(lab), run_name="__main__")
    corpus = (tmp_path / "central.log").read_text(encoding="utf-8").splitlines()
    assert len(corpus) == 10002
    assert sum(1 for l in corpus if "error" in l.lower()) == 400


def test_l_option_burst_ajoute_une_rafale_detectable(tmp_path, monkeypatch):
    """Avec l'option, le corpus porte une vraie rafale : c'est ce qui permet de
    rejouer la demonstration « scan hors de cause » en une commande."""
    import runpy
    import sys
    from datetime import datetime, timezone
    from pathlib import Path as _P

    from netverdict.burst import detect_bursts
    from netverdict.sources import syslog as syslog_src

    lab = _P(__file__).parent.parent / "lab" / "gen_syslog_corpus.py"
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(lab), "--burst", "app-billing:900:-180"])
    mod = runpy.run_path(str(lab), run_name="__main__")
    corpus = tmp_path / "central.log"
    assert len(corpus.read_text(encoding="utf-8").splitlines()) == 10902

    ancre = datetime.fromtimestamp(mod["T0"], timezone.utc)
    evs, _st = syslog_src.parse(corpus, now=ancre, tz=timezone.utc)
    rafales = detect_bursts(evs)
    assert len(rafales) == 1
    assert rafales[0].ident == "app-billing"
    assert rafales[0].lines == 900


def test_scans_of_trie_le_plus_large_en_premier():
    petit = _balayage(0.0, ports=31)
    gros = _balayage(500.0, ports=4000)
    assert [s.ports for s in scans_of(_tl(petit, gros))] == [4000, 31]
    assert scans_of(None) == []
