"""Garde-fou « Sysmon sans NetworkConnect » (constate sur machine reelle le
26/07 : `sysmon -i` sans config n'active pas l'EID3 — les events se parsent,
la jointure ne matche jamais, et rien ne le disait)."""

from netverdict.sources import evtx

_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _sysmon_event(eid: str, extra_data: str = "") -> str:
    return f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='Microsoft-Windows-Sysmon'/><EventID>{eid}</EventID>
  <Level>4</Level>
  <TimeCreated SystemTime='2026-07-26T10:00:00.0Z'/><Computer>h1</Computer>
</System><EventData>{extra_data}</EventData></Event>
"""


def test_sysmon_without_eid3_sets_actionable_note(tmp_path):
    f = tmp_path / "sysmon.xml"
    f.write_text(_sysmon_event("1") + _sysmon_event("5"), encoding="utf-8")
    events, stats = evtx.parse(f)
    assert len(events) == 2
    assert "NetworkConnect" in stats.note
    assert "sysmon -c" in stats.note


def test_sysmon_with_eid3_no_note(tmp_path):
    eid3_data = "".join(
        f"<Data Name='{k}'>{v}</Data>"
        for k, v in [("Image", r"C:\Windows\System32\curl.exe"),
                     ("ProcessId", "1234"), ("Protocol", "tcp"),
                     ("SourceIp", "10.0.0.1"), ("SourcePort", "50000"),
                     ("DestinationIp", "10.0.0.2"), ("DestinationPort", "443"),
                     ("Initiated", "true"), ("User", "H1\\user")])
    f = tmp_path / "sysmon.xml"
    f.write_text(_sysmon_event("1") + _sysmon_event("3", eid3_data),
                 encoding="utf-8")
    events, stats = evtx.parse(f)
    assert any(e.connection is not None for e in events)
    assert stats.note == ""


def test_non_sysmon_events_no_note(tmp_path):
    f = tmp_path / "system.xml"
    f.write_text(f"""
<Event xmlns='{_NS}'><System>
  <Provider Name='EventLog'/><EventID>6005</EventID><Level>4</Level>
  <TimeCreated SystemTime='2026-07-26T10:00:00.0Z'/><Computer>h1</Computer>
</System></Event>
""", encoding="utf-8")
    _events, stats = evtx.parse(f)
    assert stats.note == ""
