"""Non-regression des findings de la revue adversariale v1.1 (2026-07-24).

Un test par finding corrige : si l'un revient, on sait exactement lequel.
"""

import io
from datetime import datetime

import pytest
from rich.console import Console

from netverdict.report import _fmt_ts, render_timeline
from netverdict.sources import evtx, syslog
from netverdict.timeline import SourceStats, Timeline, TimelineEvent


# --- H1 : _fmt_ts ne plante jamais, meme sur ts negatif (Windows) ----------

def test_fmt_ts_negative_epoch_does_not_crash():
    assert isinstance(_fmt_ts(-120.0, True), str)
    # SystemTime 1601 (FILETIME vide) : fallback lisible, pas d'exception.
    out = _fmt_ts(-11644473600.0, True)
    assert "@" in out or ":" in out


# --- H2 : les timestamps python-evtx (espace, sans Z) sont acceptes --------

def test_evtx_timestamp_python_evtx_form():
    ts = evtx._parse_system_time("2026-07-24 14:03:22.123456")
    assert ts is not None
    # Meme instant que la forme wevtutil : les deux formes convergent.
    assert ts == evtx._parse_system_time("2026-07-24T14:03:22.123456Z")


# --- H3 : timeline fournie mais vide -> le rapport PARLE quand meme --------

def test_render_timeline_empty_still_reports():
    buf = io.StringIO()
    con = Console(file=buf, width=100)
    tl = Timeline(windowed=True)
    tl.add_source("syslog:x.log", [],
                  SourceStats(total_lines=500, parsed=0, unparsed=500))
    render_timeline(tl, incident_ts=None, con=con, windowed=True)
    out = buf.getvalue()
    # render_timeline() sans lang explicite rend desormais l'anglais (defaut
    # de l'outil depuis 0.7.0) : voir test_i18n.py pour la bascule --lang.
    assert "no infrastructure changes detected" in out
    assert "500 unreadable" in out


# --- H4 : injection ANSI neutralisee a l'emission (dans le contrat) --------

def test_timeline_event_strips_control_chars_and_bounds_length():
    ev = TimelineEvent(ts=0.0, source="syslog", host="h\x1b[2J",
                       category="change", severity=1, ident="evil",
                       message="a\x1b[2J\x07b" + "x" * 10000)
    assert "\x1b" not in ev.message and "\x07" not in ev.message
    assert "\x1b" not in ev.host
    assert len(ev.message) <= 300


# --- M1/M5 : fenetre non appliquee signalee ; stats homonymes preservees ---

def test_render_timeline_unwindowed_header():
    buf = io.StringIO()
    con = Console(file=buf, width=100)
    tl = Timeline()
    tl.add_source("s", [], SourceStats())
    render_timeline(tl, None, con, windowed=False)
    # render_timeline() sans lang explicite rend desormais l'anglais (defaut
    # de l'outil depuis 0.7.0) : voir test_i18n.py pour la bascule --lang.
    assert "NOT applied" in buf.getvalue()


def test_add_source_same_name_keeps_both_stats():
    tl = Timeline()
    tl.add_source("syslog:syslog.log", [], SourceStats(total_lines=1))
    tl.add_source("syslog:syslog.log", [], SourceStats(total_lines=9))
    assert len(tl.stats) == 2
    assert sorted(s.total_lines for s in tl.stats.values()) == [1, 9]


# --- M3 : annee RFC3164 ancree sur la capture, pas sur l'horloge -----------

def test_syslog_rfc3164_year_anchored_on_capture(tmp_path):
    log = tmp_path / "old.log"
    log.write_text("<34>Feb 10 03:00:00 h1 sshd[1]: link down on eth0\n",
                   encoding="utf-8")
    evs, _ = syslog.parse(log, now=datetime(2025, 7, 24, 12, 0, 0))
    assert len(evs) == 1
    assert datetime.fromtimestamp(evs[0].ts).year == 2025


# --- M6 : fichier XML melant <Event> namespaces et bruts -------------------

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_MIXED_XML = f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='EventLog'/><EventID>6005</EventID><Level>4</Level>
  <TimeCreated SystemTime='2026-07-24T10:00:00.0Z'/><Computer>h1</Computer>
</System></Event>
<Event><System>
  <Provider Name='EventLog'/><EventID>6006</EventID><Level>4</Level>
  <TimeCreated SystemTime='2026-07-24T11:00:00.0Z'/><Computer>h1</Computer>
</System></Event>
"""


def test_evtx_mixed_namespace_file_keeps_both(tmp_path):
    f = tmp_path / "mixed.xml"
    f.write_text(_MIXED_XML, encoding="utf-8")
    evs, stats = evtx.parse(f)
    assert stats.total_lines == 2
    assert sorted(e.ident for e in evs) == ["6005", "6006"]


# --- M8 : lignes de reboot Linux courantes categorisees reboot -------------

@pytest.mark.parametrize("line,expected", [
    ("<30>Jul 24 08:00:00 h1 systemd-shutdown: Rebooting.", "reboot"),
    ("<30>Jul 24 08:00:00 h1 systemd-shutdown: Powering off.", "reboot"),
    ("<30>Jul 24 08:00:05 h1 kernel: Linux version 6.1.0-18-amd64", "reboot"),
])
def test_syslog_common_reboot_lines(tmp_path, line, expected):
    log = tmp_path / "r.log"
    log.write_text(line + "\n", encoding="utf-8")
    evs, _ = syslog.parse(log, now=datetime(2026, 7, 24, 12, 0, 0))
    assert len(evs) == 1 and evs[0].category == expected


# --- B1 : ']' echappe dans un structured-data ne tronque plus --------------

def test_syslog_sd_with_escaped_bracket(tmp_path):
    log = tmp_path / "sd.log"
    log.write_text('<134>1 2026-07-24T10:00:00Z h1 app 1 - '
                   '[x@1 m="a\\]b"] le vrai message\n', encoding="utf-8")
    evs, _ = syslog.parse(log)
    assert evs[0].message == "le vrai message"


# --- XXE : le DOCTYPE hostile echoue proprement, sans expansion ------------

def test_evtx_xxe_doctype_rejected_cleanly(tmp_path):
    f = tmp_path / "evil.xml"
    f.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
                 '"file:///C:/Windows/win.ini">]>'
                 f'<Event xmlns="{_NS}"><System>&x;</System></Event>',
                 encoding="utf-8")
    with pytest.raises(ValueError):
        evtx.parse(f)
