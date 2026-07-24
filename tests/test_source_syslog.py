"""Unitaires du parseur syslog (RFC5424 + RFC3164 melanges) -> TimelineEvent.

sample_syslog.log est un fichier syslog "pur" (aucun commentaire dedans :
un vrai syslog n'en a pas). Les attentes -- ce que CHAQUE ligne doit
produire -- sont documentees ICI plutot que dans le fichier, pour ne pas
fabriquer un pseudo-format qui n'existe nulle part en pratique.

Contenu de la fixture, DANS L'ORDRE DU FICHIER (le parseur doit re-trier
par ts croissant ; l'ordre d'ecriture est volontairement melange) :

  1. kern.log SANS <PRI>        : "kernel: Booting Linux..."
                                   -> reboot, severite 1 (pas de PRI), tz_known=False
  2. RFC3164 <28>                : "ifplugd[812]: eth0: link down"
                                   -> network, severite 1, tz_known=False, ident="ifplugd" (pid retire)
  3. <14>Jul 24 08:07             : ligne TRONQUEE (pas d'heure complete) -> unparsed
  4. RFC5424 <38> tz +02:00       : "sshd ... Accepted publickey ..."
                                   -> info, severite 0, tz_known=True, EPOCH VERIFIE A LA MAIN
  5. RFC3164 <34>                 : "firewalld[955]: firewall rules reloaded"
                                   -> change, severite 3, tz_known=False, ident="firewalld"
  6. RFC3164 <27>                 : "systemd[1]: Started Session 42 of user root."
                                   -> service, severite 2, tz_known=False, ident="systemd" (pid retire)
  7. RFC5424 <83> tz Z, SD x2, APP "-" : "... authentication failure ..."
                                   -> error, severite 2, tz_known=True, ident=="" (APP nil)
  8. octets non-UTF-8 (ajoutes en mode binaire apres coup) -> unparsed

  Donc : total_lines=8, parsed=6, unparsed=2.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from netverdict.sources.syslog import parse, _rfc3164_epoch
from netverdict.timeline import SourceStats

FIXTURE = Path(__file__).parent / "fixtures" / "events" / "sample_syslog.log"

# Epoch UTC calcule A LA MAIN pour 2026-07-24T14:02:11.532+02:00 (ligne 4),
# par DEUX chemins independants qui doivent converger :
#
#   Chemin 1 (jours depuis epoch 1970-01-01) :
#     annees 1970->2026 = 56 ans, bissextiles dans [1972..2024] pas de 4
#     (2000 compte, /400) = 14 -> 56*365 + 14 = 20454 jours jusqu'au 01/01/2026
#     + (31+28+31+30+31+30)=181 j jusqu'au 01/07 + 23 j jusqu'au 24/07 = 204 j
#     -> 20454+204 = 20658 j *86400 = 1 784 851 200 s (2026-07-24T00:00:00Z)
#
#   Chemin 2 (ancre differente, 2000-01-01T00:00:00Z = 946684800, reference
#   connue independamment) :
#     2000->2026 = 26 ans, bissextiles [2000..2024] pas de 4 = 7
#     -> 26*365+7 = 9497 j + 204 j = 9701 j *86400 = 838 166 400
#     946684800 + 838166400 = 1 784 851 200  <- MEME RESULTAT, les 2 chemins concordent.
#
#   + 14h02m11.532s locales - 2h de fuseau = 12h02m11.532s UTC
#     = 43331.532 s -> 1 784 851 200 + 43 331.532 = 1 784 894 531.532
_EPOCH_2026_07_24_00Z = 1_784_851_200
_EXPECTED_TS_L4 = _EPOCH_2026_07_24_00Z + 12 * 3600 + 2 * 60 + 11 + 0.532


def _parsed():
    return parse(FIXTURE)


def _by_ident(events, ident):
    return next(e for e in events if e.ident == ident)


# ------------------------------------------------------------------ comptes

def test_counts_total_parsed_unparsed():
    events, stats = _parsed()
    assert stats.total_lines == 8
    assert stats.parsed == 6
    assert stats.unparsed == 2          # ligne tronquee + ligne binaire
    assert len(events) == 6


def test_events_sorted_by_ts_croissant():
    events, _ = _parsed()
    tss = [e.ts for e in events]
    assert tss == sorted(tss)


# ------------------------------------------------------------------- RFC5424

def test_rfc5424_tz_aware_epoch_exact_a_la_main():
    """La ligne avec fuseau +02:00 est LE cas que la mission demande de
    verifier a la main (cf. commentaire epoch plus haut, 2 chemins)."""
    events, _ = _parsed()
    ev = _by_ident(events, "sshd")
    assert abs(ev.ts - _EXPECTED_TS_L4) < 1e-6
    assert ev.tz_known is True
    assert ev.host == "srv-core01"
    assert ev.severity == 0                 # syslog sev 6 (pri 38 % 8) -> projet 0
    assert ev.category == "info"            # aucun pattern, severite < 2
    assert ev.message == (
        "Accepted publickey for admin from 10.0.0.5 port 51820 ssh2"
    )


def test_rfc5424_app_dash_devient_ident_vide_et_sd_multiples_retires():
    events, _ = _parsed()
    ev = _by_ident(events, "")              # APP-NAME "-" -> ident inconnu, ""
    assert ev.tz_known is True
    assert ev.severity == 2                 # syslog sev 3 (pri 83 % 8) -> projet 2
    assert ev.category == "error"           # rien de specifique, severite >= 2
    # Les DEUX blocs de structured-data sont retires, pas juste le premier.
    assert "[" not in ev.message and "]" not in ev.message
    assert ev.message == (
        "authentication failure for user unknown from 203.0.113.9"
    )
    # La ligne 7 (09:15:00Z) est avant la ligne 4 (12:02:11.532Z) le meme jour.
    ev_ssh = _by_ident(events, "sshd")
    assert ev.ts < ev_ssh.ts


# ------------------------------------------------------------------- RFC3164

def test_rfc3164_network_ifdown_ident_sans_pid():
    events, _ = _parsed()
    ev = _by_ident(events, "ifplugd")
    assert ev.category == "network"
    assert ev.severity == 1                 # syslog sev 4 (pri 28 % 8) -> projet 1
    assert ev.tz_known is False
    assert ev.host == "rtr-edge01"
    assert ev.message == "eth0: link down"
    assert "[" not in ev.ident              # pid retire de l'ident


def test_rfc3164_change_reload_firewall():
    events, _ = _parsed()
    ev = _by_ident(events, "firewalld")
    assert ev.category == "change"
    assert ev.severity == 3                 # syslog sev 2 (pri 34 % 8) -> projet 3
    assert ev.tz_known is False


def test_rfc3164_service_systemd_started_ident_sans_pid():
    events, _ = _parsed()
    ev = _by_ident(events, "systemd")
    assert ev.category == "service"
    assert ev.severity == 2                 # syslog sev 3 (pri 27 % 8) -> projet 2
    assert ev.tz_known is False
    assert ev.ident == "systemd"            # pas "systemd[1]"


def test_kernlog_sans_pri_categorise_et_severite_par_defaut():
    events, _ = _parsed()
    ev = _by_ident(events, "kernel")
    assert ev.category == "reboot"          # "Booting"
    assert ev.severity == 1                 # pas de PRI -> 1, valeur neutre
    assert ev.tz_known is False


def test_ordre_chronologique_complet_tz_aware_et_local_melanges():
    """Reconstruit l'ordre attendu INDEPENDAMMENT (meme mecanisme heure
    locale que le parseur -- datetime naif -> .timestamp() -- mais code
    separement ici) et le compare a l'ordre produit. Ne suppose AUCUN
    fuseau fixe : portable quelle que soit la machine qui execute le test.
    """
    events, _ = _parsed()
    expected_epoch = {
        "kernel": datetime(2026, 7, 24, 8, 0, 0).timestamp(),
        "ifplugd": datetime(2026, 7, 24, 8, 12, 3).timestamp(),
        "systemd": datetime(2026, 7, 24, 8, 15, 2).timestamp(),
        "firewalld": datetime(2026, 7, 24, 8, 20, 11).timestamp(),
        "": 1_784_884_500.0,                # RFC5424 explicite : 09:15:00Z
        "sshd": _EXPECTED_TS_L4,             # RFC5424 explicite : 12:02:11.532Z
    }
    expected_order = [k for k, _ in sorted(expected_epoch.items(), key=lambda kv: kv[1])]
    assert [e.ident for e in events] == expected_order


# --------------------------------------------------------------- cas limites

def test_fichier_vide():
    import tempfile
    import os
    fd, tmp = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    try:
        events, stats = parse(tmp)
        assert events == []
        assert stats == SourceStats()
    finally:
        os.remove(tmp)


def test_fichier_introuvable_leve_valueerror():
    # cli.py n'attrape que ValueError autour de sources.syslog.parse() : un
    # chemin absent doit passer par la, pas par un FileNotFoundError brut.
    import pytest
    with pytest.raises(ValueError):
        parse("ce/chemin/n_existe/vraiment/pas.log")


def test_rfc3164_bascule_annee_precedente_si_plus_de_26h_dans_le_futur():
    """Log de decembre relu en janvier : l'annee courante placerait le
    timestamp a plus de 26h dans le futur -> on doit reculer d'un an.
    Teste _rfc3164_epoch en isolation (now injectable), independant de la
    date reelle d'execution des tests."""
    now = datetime(2027, 1, 2, 3, 0, 0)
    ts = _rfc3164_epoch("Dec 31 23:59:00", now=now)
    assert datetime.fromtimestamp(ts).year == 2026


def test_rfc3164_pas_de_bascule_si_dans_la_marge_de_26h():
    now = datetime(2027, 1, 1, 2, 0, 0)
    # "Jan 1 23:00" est ~21h dans le futur par rapport a 02:00 : sous le
    # seuil de 26h, donc PAS de recul (log de la nuit qui vient d'arriver).
    ts = _rfc3164_epoch("Jan 1 23:00:00", now=now)
    assert datetime.fromtimestamp(ts).year == 2027
