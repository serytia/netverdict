"""Non-regression des findings de l'audit de portabilite multi-OS (26/07).

Le verdict de cet audit etait contre-intuitif : les defauts serieux sont des
pannes WINDOWS declenchees par des DONNEES LINUX. Un test par finding.
"""

import json
import platform
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from netverdict.cli import main
from netverdict.pcap import _detect_mixed_linktypes, read_capture

FIXTURES = Path(__file__).parent / "fixtures"


# --- H1 : pcapng multi-interfaces -> la moitie de la capture disparait -----

def _pcapng_two_interfaces(path: Path) -> None:
    """pcapng minimal : SHB + deux IDB de linktypes DIFFERENTS (Ethernet et
    LINUX_SLL2), tel qu'en produit un mergecap de deux captures heterogenes."""
    def block(btype: bytes, body: bytes) -> bytes:
        total = len(body) + 12
        return btype + struct.pack("<I", total) + body + struct.pack("<I", total)

    shb = block(struct.pack("<I", 0x0A0D0D0A),
                struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb_eth = block(struct.pack("<I", 1), struct.pack("<HHI", 1, 0, 65535))
    idb_sll = block(struct.pack("<I", 1), struct.pack("<HHI", 276, 0, 65535))
    path.write_bytes(shb + idb_eth + idb_sll)


def test_pcapng_multi_linktypes_est_signale(tmp_path):
    f = tmp_path / "merged.pcapng"
    _pcapng_two_interfaces(f)
    assert _detect_mixed_linktypes(f) is True
    cap = read_capture(f)
    assert cap.stats.mixed_linktypes is True


def test_pcap_mono_interface_non_signale():
    cap = read_capture(FIXTURES / "clean.pcap")
    assert cap.stats.mixed_linktypes is False


def test_le_rapport_annonce_les_linktypes_mixtes(tmp_path, capsys):
    f = tmp_path / "merged.pcapng"
    _pcapng_two_interfaces(f)
    main(["analyze", str(f)])
    sortie = capsys.readouterr().out
    assert "PLUSIEURS interfaces" in sortie
    assert "N'APPARAISSENT PAS" in sortie


# --- H2 : ancre RFC3164 datee dans le mauvais millesime -------------------

def test_ancre_syslog_est_aware_utc(tmp_path, capsys):
    """Une capture a l'epoch + un syslog RFC3164 : l'evenement doit rester
    date de 1970 quel que soit le fuseau du poste. Avec une ancre naive, un
    poste a l'ouest de Greenwich basculait la reference sur 1969 et l'event
    sortait de la fenetre — « aucun changement detecte », faux."""
    log = tmp_path / "sys.log"
    log.write_text("<134>Jan  1 00:00:00 fw01 firewalld[1]: Configuration "
                   "reloaded\n", encoding="utf-8")
    main(["analyze", str(FIXTURES / "slow_app.pcap"),
          "--syslog", str(log), "--syslog-tz", "UTC", "--json"])
    d = json.loads(capsys.readouterr().out)
    events = (d.get("timeline") or {}).get("events", [])
    assert events, "l'evenement syslog a disparu de la fenetre"
    assert events[0]["ts"] == 0.0


# --- H3 : --json vide sur donnee non-cp1252 -------------------------------

def test_json_survit_a_une_donnee_non_latin1(tmp_path):
    """Hostname cyrillique dans un syslog : donnee Linux banale qui faisait
    lever UnicodeEncodeError en plein print sous Windows, produisant un
    fichier JSON de 0 octet avec un code retour ambigu."""
    log = tmp_path / "sys.log"
    log.write_text("<134>1 1970-01-01T00:00:01Z сервер "
                   "app 1 - - Configuration reloaded\n", encoding="utf-8")
    sortie = tmp_path / "rapport.json"
    with open(sortie, "wb") as f:
        r = subprocess.run(
            [sys.executable, "-m", "netverdict.cli", "analyze",
             str(FIXTURES / "slow_app.pcap"), "--syslog", str(log), "--json"],
            stdout=f, stderr=subprocess.PIPE,
            cwd=str(Path(__file__).parent.parent))
    assert sortie.stat().st_size > 0, "JSON vide : la sortie a ete perdue"
    d = json.loads(sortie.read_text(encoding="utf-8"))
    assert d["flows"], "rapport tronque"
    assert r.returncode in (0, 1)


# --- M2 : capture refusee proprement hors Windows/Linux --------------------

def test_capture_refuse_les_os_non_supportes(monkeypatch, capsys):
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    assert main(["capture"]) == 2
    err = capsys.readouterr().err
    assert "Darwin" in err
    assert "tcpdump" in err                 # l'alternative est donnee


@pytest.mark.skipif(platform.system() not in ("Windows", "Linux"),
                    reason="verifie le chemin nominal des OS supportes")
def test_capture_accepte_les_os_supportes(monkeypatch, capsys):
    """Le garde-fou ne doit pas bloquer les plateformes reelles : on echoue
    plus loin (interpreteur/script), jamais sur le test d'OS."""
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(subprocess, "call", lambda *a, **k: 0)
    assert main(["capture"]) == 0
