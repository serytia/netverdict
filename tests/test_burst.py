"""Detection des rafales de journaux (burst.py).

Ce que ces tests protegent, dans l'ordre de ce que ca couterait :

  1. Le NON-declenchement. Une section « rafale » qui s'allume sur un serveur
     normal serait pire qu'absente : l'admin apprendrait a l'ignorer, et elle
     ne servirait plus le jour ou elle a raison. D'ou autant de tests de
     silence que de tests de detection.
  2. Le compte et l'attribution. Une rafale attribuee au mauvais hote ou au
     mauvais programme envoie enqueter sur une machine saine.
  3. La fusion. Trois minutes de hurlement sont UN incident ; les compter
     trois fois ferait du « nombre de rafales » un artefact du decoupage.
"""

import io
import json
import runpy
from datetime import datetime, timezone
from pathlib import Path

import pytest
from rich.console import Console

from netverdict.burst import BurstEvent, detect_bursts
from netverdict.cli import main
from netverdict.pcap import read_capture
from netverdict.report import render_console, to_json
from netverdict.sources import syslog as syslog_src
from netverdict.timeline import SourceStats, Timeline, TimelineEvent

FIXTURES_DIR = Path(__file__).parent / "fixtures"
LAB_DIR = Path(__file__).resolve().parent.parent / "lab"

# Aligne sur une frontiere de minute : les seaux sont calcules sur l'epoch,
# un T0 quelconque ferait tomber « une minute de lignes » a cheval sur deux
# seaux et rendrait les comptes attendus dependants du choix de T0.
T0 = 1_800_000_000.0
assert T0 % 60 == 0


def _ev(ts: float, host: str = "srv-app01", ident: str = "app",
        message: str = "ORA-00060: deadlock detected",
        tz_known: bool = True) -> TimelineEvent:
    return TimelineEvent(ts=ts, source="syslog", host=host, category="error",
                         severity=2, ident=ident, message=message,
                         tz_known=tz_known)


def _rafale(n: int, seau: int = 0, **kw) -> list[TimelineEvent]:
    """`n` lignes reparties dans le seau de 60 s numero `seau`."""
    return [_ev(T0 + seau * 60 + (i * 59.0 / max(n - 1, 1)), **kw)
            for i in range(n)]


def _calme(par_minute: int, minutes: int, **kw) -> list[TimelineEvent]:
    return [e for m in range(minutes) for e in _rafale(par_minute, seau=m, **kw)]


# --- 1. Les silences : ce qui ne doit JAMAIS declencher ---------------------

def test_liste_vide():
    assert detect_bursts([]) == []


def test_un_seul_evenement():
    """Un evenement isole n'a ni rythme ni base : conclure quoi que ce soit
    a partir de lui serait de la divination."""
    assert detect_bursts([_ev(T0)]) == []


def test_rythme_regulier_sur_une_heure():
    """5 lignes/min pendant 60 min : c'est un serveur qui va bien. La base
    vaut 5, mais le plancher absolu de 200 lignes/min tient quand meme."""
    assert detect_bursts(_calme(5, 60)) == []


def test_juste_sous_le_plancher_ne_declenche_pas():
    """190 lignes en une minute face a une base de 10 : le ratio est atteint
    (19x), pas le plancher. Les deux conditions sont exigees ENSEMBLE, sinon
    un hote silencieux declencherait a 20 lignes."""
    evs = _calme(10, 30) + _rafale(190, seau=40)
    assert detect_bursts(evs) == []


def test_juste_au_dessus_du_plancher_declenche():
    """Le pendant du test precedent : a 250 lignes, les deux conditions sont
    remplies. Sans cette paire, le test du dessus passerait aussi avec une
    detection cassee qui ne trouve jamais rien."""
    evs = _calme(10, 30) + _rafale(250, seau=40)
    rafales = detect_bursts(evs)
    assert len(rafales) == 1
    assert rafales[0].lines == 250


def test_demon_bavard_ne_declenche_pas_au_plancher():
    """300 lignes/min en PERMANENCE, c'est un collecteur verbeux, pas une
    rafale : le ratio de 20 sur la base l'exige, et la base est ici de 300."""
    assert detect_bursts(_calme(300, 30)) == []


# --- 2. La detection, le compte et l'attribution ----------------------------

def test_une_rafale_sur_un_hote_pendant_qu_un_autre_est_calme():
    evs = (_rafale(900) + _calme(3, 60, host="srv-db01", ident="cron"))
    rafales = detect_bursts(evs)
    assert len(rafales) == 1
    r = rafales[0]
    assert (r.host, r.ident) == ("srv-app01", "app")
    assert r.peak_per_min == 900
    assert r.lines == 900
    assert r.ts == T0 and r.end == T0 + 60
    assert (r.category, r.severity, r.source) == ("burst", 2, "syslog")
    assert r.message == ("900 lines in 60 s (peak 900/min, baseline 0/min): "
                         "ORA-00060: deadlock detected")


def test_deux_programmes_en_rafale_donnent_deux_evenements():
    """Le regroupement est par (hote, programme) : deux applications qui
    hurlent sur la meme machine sont deux incidents a instruire."""
    evs = _rafale(900, ident="app") + _rafale(400, ident="worker")
    rafales = detect_bursts(evs)
    assert [r.ident for r in rafales] == ["app", "worker"]
    assert [r.lines for r in rafales] == [900, 400]


def test_seaux_consecutifs_fusionnes_en_un_evenement():
    """Trois minutes de rafale = UN evenement, avec la bonne fin."""
    evs = _calme(2, 20)
    evs += _rafale(300, seau=30) + _rafale(300, seau=31) + _rafale(300, seau=32)
    rafales = detect_bursts(evs)
    assert len(rafales) == 1
    r = rafales[0]
    assert r.ts == T0 + 30 * 60
    assert r.end == T0 + 33 * 60          # fin du TROISIEME seau
    assert r.end - r.ts == 180
    assert r.lines == 900
    assert r.peak_per_min == 300          # le pic reste par minute, pas cumule
    assert "900 lines in 180 s" in r.message


def test_seaux_non_consecutifs_restent_deux_evenements():
    """Non-comportement du test precedent : deux rafales separees par une
    minute calme ne se fusionnent pas."""
    evs = _calme(2, 20) + _rafale(300, seau=30) + _rafale(300, seau=32)
    assert len(detect_bursts(evs)) == 2


def test_extrait_pris_dans_la_rafale_et_tronque():
    """L'extrait doit etre la ligne QUI SE REPETE, pas le bruit de fond du
    programme : c'est elle qui explique la rafale."""
    long_message = "ORA-00060: deadlock detected while waiting for resource " \
                   "on segment PK_ORDERS_2026 in tablespace USERS"
    evs = _rafale(50, message="Started session for user svc_app")
    evs += _rafale(880, message=long_message)
    evs += _rafale(2, seau=1) + _rafale(2, seau=2)
    r = detect_bursts(evs)[0]
    assert r.sample == long_message[:80]
    assert len(r.sample) == 80


def test_tz_known_false_est_propage():
    """Un syslog RFC3164 sans --syslog-tz date a la louche : la rafale doit
    porter le meme doute, sinon le rapport affiche une minute qu'il ne tient
    pas."""
    r = detect_bursts(_rafale(900, tz_known=False))[0]
    assert r.tz_known is False
    assert detect_bursts(_rafale(900))[0].tz_known is True


def test_un_seul_evenement_mal_date_rend_toute_la_rafale_approximative():
    evs = _rafale(899) + [_ev(T0 + 59.5, tz_known=False)]
    assert detect_bursts(evs)[0].tz_known is False


def test_bucket_s_absurde_leve():
    with pytest.raises(ValueError):
        detect_bursts([_ev(T0)], bucket_s=0)


def test_horodatage_negatif_ne_melange_pas_les_seaux():
    """Les pcap synthetiques du projet vivent a l'epoch 0 : une division
    entiere qui tronquerait vers zero rangerait -30 s et +30 s dans le meme
    seau."""
    evs = [_ev(-30.0 + i * 0.03) for i in range(900)]
    r = detect_bursts(evs)[0]
    assert r.ts == -60.0 and r.end == 0.0


# --- 3. Non-regression sur le corpus de demonstration -----------------------

def test_le_corpus_du_lab_ne_produit_aucune_rafale(tmp_path, monkeypatch):
    """10 002 lignes reelles, 6 h, 400 erreurs reparties : c'est le corpus de
    la demo. S'il sortait une rafale, le seuil serait faux — et la demo
    mentirait avant meme d'etre montree."""
    monkeypatch.chdir(tmp_path)
    mod = runpy.run_path(str(LAB_DIR / "gen_syslog_corpus.py"),
                         run_name="__main__")
    corpus = tmp_path / "central.log"
    ancre = datetime.fromtimestamp(mod["T0"], timezone.utc)
    evs, st = syslog_src.parse(corpus, now=ancre, tz=timezone.utc)
    assert st.total_lines == 10002
    assert detect_bursts(evs) == []


# --- 4. Restitution : JSON et console ---------------------------------------

def _timeline_avec(evs: list[TimelineEvent]) -> Timeline:
    tl = Timeline(windowed=True)
    rafales = detect_bursts(evs)
    stats = SourceStats(total_lines=len(evs), parsed=len(evs),
                        bursts=len(rafales))
    tl.add_source("syslog:central.log", evs + rafales, stats)
    return tl


def test_le_json_porte_les_rafales():
    cap = read_capture(FIXTURES_DIR / "clean.pcap")
    tl = _timeline_avec(_rafale(900))
    out = json.loads(to_json(cap, [], timeline=tl))
    assert len(out["bursts"]) == 1
    b = out["bursts"][0]
    assert b["host"] == "srv-app01" and b["program"] == "app"
    assert b["lines"] == 900 and b["peak_per_min"] == 900
    assert b["end"] - b["start"] == 60
    assert b["baseline_per_min"] == 0 and b["tz_known"] is True
    assert b["sample"].startswith("ORA-00060")
    assert out["timeline"]["stats"]["syslog:central.log"]["bursts"] == 1


def test_le_json_porte_une_liste_vide_quand_il_n_y_a_rien():
    """« Aucune rafale » et « cette version ne sait pas les compter » ne
    doivent pas se ressembler pour un consommateur machine."""
    cap = read_capture(FIXTURES_DIR / "clean.pcap")
    out = json.loads(to_json(cap, [], timeline=_timeline_avec(_calme(5, 60))))
    assert out["bursts"] == []


def _console(tl: Timeline, lang: str) -> str:
    cap = read_capture(FIXTURES_DIR / "clean.pcap")
    buf = io.StringIO()
    render_console(cap, [], timeline=tl, console=Console(file=buf, width=100),
                   lang=lang)
    return buf.getvalue()


def test_la_console_affiche_la_section_quand_il_y_a_une_rafale():
    sortie = _console(_timeline_avec(_rafale(900)), "en")
    assert "Log bursts:" in sortie
    assert "900 lines in 60 s" in sortie
    assert "srv-app01" in sortie
    sortie_fr = _console(_timeline_avec(_rafale(900)), "fr")
    assert "Rafales de journaux :" in sortie_fr
    assert "900 lignes en 60 s" in sortie_fr


def test_la_console_ne_dit_rien_quand_il_n_y_a_pas_de_rafale():
    """Une section vide de plus noierait celles qui parlent."""
    sortie = _console(_timeline_avec(_calme(5, 60)), "en")
    assert "Log bursts" not in sortie
    assert "Rafales" not in sortie


def test_la_rafale_n_est_pas_comptee_comme_une_erreur_de_plus():
    """La rafale a sa section ; la compter aussi dans « erreurs hors
    changement » ferait compter deux fois le meme fait."""
    sortie = _console(_timeline_avec(_rafale(900)), "en")
    assert "901 error(s)" not in sortie
    assert "900 error(s)" in sortie      # les lignes brutes, elles, restent


def test_le_cli_detecte_une_rafale_de_bout_en_bout(tmp_path, capsys):
    """Le seul test qui traverse le branchement de cli.py. Sans lui, tous les
    autres resteraient verts avec une detection jamais appelee : la panne la
    plus silencieuse possible pour cet etage — l'outil dirait « rien a
    signaler » sur un serveur qui hurle."""
    log = tmp_path / "central.log"
    log.write_text("\n".join(
        f"<30>Jan  1 00:00:{i % 60:02d} srv-app01 app[7]: "
        f"ORA-00060: deadlock detected" for i in range(250)) + "\n",
        encoding="utf-8")
    main(["analyze", str(FIXTURES_DIR / "clean.pcap"), "--syslog", str(log),
          "--syslog-tz", "UTC", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert len(out["bursts"]) == 1
    b = out["bursts"][0]
    assert (b["host"], b["program"], b["lines"]) == ("srv-app01", "app", 250)
    assert b["tz_known"] is True          # --syslog-tz UTC a ete honore
    assert out["timeline"]["stats"]["syslog:central.log"]["bursts"] == 1
    # La rafale voyage AUSSI comme evenement de timeline, categorie fermee.
    assert [e["category"] for e in out["timeline"]["events"]
            if e["category"] == "burst"] == ["burst"]


def test_la_rafale_reste_hors_des_changements_d_infra():
    """« burst » n'est pas dans CHANGE_CATEGORIES : une application bavarde
    n'a rien change a l'infra, et elle ne doit pas polluer la liste des
    suspects (elle y entrera par correlate.py, autrement)."""
    tl = _timeline_avec(_rafale(900))
    assert any(isinstance(e, BurstEvent) for e in tl.events)
    assert tl.changes() == []
