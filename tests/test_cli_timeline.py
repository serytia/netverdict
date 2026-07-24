"""Bout en bout CLI v1.1 : pcap + syslog -> rapport JSON avec timeline.

Les fixtures pcap synthetiques vivent en epoch ~0 (1970) : le syslog de test
utilise donc des timestamps RFC5424 explicites autour de 1970 — tordu a
l'oeil mais deterministe, et ca teste REELLEMENT le fenetrage (un event
apres la fin de capture doit disparaitre du rapport).
"""

import json

from netverdict.cli import main

# slow_app.pcap : premier paquet a t=0.0, dernier a t~3.002 (epoch 1970).
# Fenetre attendue : [0 - 900, 3.002].
SYSLOG_CONTENT = "\n".join([
    # Dans la fenetre (epoch -120) : rechargement firewall = changement,
    # 2 min avant l'incident -> doit etre marque suspect et present au JSON.
    "<134>1 1969-12-31T23:58:00.000Z fw01 firewalld 512 - - "
    "Configuration reloaded: 42 rules applied",
    # Hors fenetre (epoch 3600 : APRES la fin de la capture) : exclu.
    "<134>1 1970-01-01T01:00:00.000Z fw01 firewalld 512 - - "
    "Configuration reloaded: late change",
]) + "\n"


def test_analyze_with_syslog_timeline(tmp_path, capsys):
    log = tmp_path / "fw.log"
    log.write_text(SYSLOG_CONTENT, encoding="utf-8")

    rc = main(["analyze", "tests/fixtures/slow_app.pcap",
               "--syslog", str(log), "--json"])
    out = json.loads(capsys.readouterr().out)

    assert rc == 1                          # verdict non-RAS present (slow app)
    tl = out["timeline"]
    # Fenetrage : seul l'event d'AVANT la capture survit.
    assert len(tl["events"]) == 1
    ev = tl["events"][0]
    assert ev["category"] == "change"
    assert ev["host"] == "fw01"
    assert ev["ident"] == "firewalld"
    assert ev["tz_known"] is True
    assert ev["ts"] == -120.0
    # Les stats de lecture remontent bien par source.
    (name, st), = tl["stats"].items()
    assert name.startswith("syslog:")
    assert st["parsed"] == 2                # les 2 lignes se parsent...
    assert st["unparsed"] == 0              # ...le fenetrage n'est pas du unparsed


def test_analyze_bad_events_path_clean_error(tmp_path, capsys):
    rc = main(["analyze", "tests/fixtures/clean.pcap",
               "--events", str(tmp_path / "absent.xml"), "--json"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "--events" in err                # message propre, pas un traceback
