"""Unitaires du parseur d'evenements Windows (netverdict/sources/evtx.py)."""

from datetime import datetime, timezone

import pytest

from netverdict.sources.evtx import parse

try:
    import Evtx.Evtx  # noqa: F401
    _EVTX_LIB_PRESENT = True
except ImportError:
    _EVTX_LIB_PRESENT = False


NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event_xml(provider, event_id, level, system_time,
               computer="POSTE-LAB-01", data=None):
    """Construit le fragment XML d'un seul <Event>, au format wevtutil
    (namespace declare directement sur l'element Event)."""
    time_part = f"<TimeCreated SystemTime='{system_time}' />" if system_time else ""
    data_part = ""
    if data:
        fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
        data_part = f"<EventData>{fields}</EventData>"
    return (
        f"<Event xmlns='{NS}'>"
        f"<System>"
        f"<Provider Name='{provider}' />"
        f"<EventID>{event_id}</EventID>"
        f"<Level>{level}</Level>"
        f"{time_part}"
        f"<Computer>{computer}</Computer>"
        f"</System>"
        f"{data_part}"
        f"</Event>"
    )


def _build_doc(fragments, with_root):
    body = "\n".join(fragments)
    if with_root:
        return f"<Events>{body}</Events>"
    return body


# Cinq records, places dans le texte dans le DESORDRE chronologique (le plus
# recent, 7036 a 14:10, en tete) : un tri qui marcherait "par hasard" parce
# que l'entree etait deja triee ne prouverait rien.
_FRAG_7036 = _event_xml("Service Control Manager", 7036, 4,
                        "2026-07-24T14:10:00.0000000Z",
                        data={"param1": "Windows Update", "param2": "running"})
_FRAG_105 = _event_xml("Microsoft-Windows-Kernel-Power", 105, 4,
                       "2026-07-24T14:03:22.1234567Z",
                       data={"OldPowerSource": "1", "NewPowerSource": "0"})
_FRAG_7045 = _event_xml("Service Control Manager", 7045, 4,
                        "2026-07-24T14:05:00.0000000Z",
                        data={"ServiceName": "WazuhSvc"})
_FRAG_UNKNOWN = _event_xml("Some-Other-Provider", 9999, 3,
                           "2026-07-24T14:07:30.5000000Z")
_FRAG_NO_TS = _event_xml("Some-Other-Provider", 1, 4, system_time=None)

_ALL_FRAGMENTS = [_FRAG_7036, _FRAG_105, _FRAG_7045, _FRAG_UNKNOWN, _FRAG_NO_TS]


def _check_full_fixture(events, stats):
    # 5 records rencontres, 1 illisible (pas de TimeCreated) -> 4 events.
    assert stats.total_lines == 5
    assert stats.parsed == 4
    assert stats.unparsed == 1
    assert len(events) == 4

    by_ident = {e.ident: e for e in events}
    assert set(by_ident) == {"7036", "105", "7045", "9999"}

    # Tri croissant, et preuve que le tri fait quelque chose : l'ordre
    # d'entree (7036 d'abord) n'est PAS l'ordre de sortie attendu.
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    assert events[0].ident == "105"     # le plus ancien (14:03:22)
    assert events[-1].ident == "7036"   # le plus recent (14:10:00)

    assert all(e.source == "evtx" for e in events)
    assert all(e.tz_known for e in events)
    assert all(e.host == "POSTE-LAB-01" for e in events)
    assert all(isinstance(e.ident, str) for e in events)

    e105 = by_ident["105"]
    assert e105.category == "power"
    assert e105.severity == 1
    expected_ts = datetime(2026, 7, 24, 14, 3, 22, 123456,
                          tzinfo=timezone.utc).timestamp()
    assert abs(e105.ts - expected_ts) < 1e-6
    assert e105.message.startswith(
        "Microsoft-Windows-Kernel-Power: changement de source d'alimentation")

    e7045 = by_ident["7045"]
    assert e7045.category == "change"
    assert e7045.severity == 2
    assert e7045.message.startswith(
        "Service Control Manager: nouveau service installe")

    e7036 = by_ident["7036"]
    assert e7036.category == "service"
    assert e7036.severity == 0

    e9999 = by_ident["9999"]
    assert e9999.category == "error"      # Level=3 (warning) -> error sev 1
    assert e9999.severity == 1
    assert e9999.message == "Some-Other-Provider: EventID 9999"


def test_parse_bare_sequence_no_root(tmp_path):
    """Format par defaut de `wevtutil qe /f:xml` : une sequence brute de
    <Event>, sans racine <Events> commune (document non bien forme au sens
    XML strict) -- doit quand meme etre accepte."""
    p = tmp_path / "events_no_root.xml"
    p.write_text(_build_doc(_ALL_FRAGMENTS, with_root=False), encoding="utf-8")
    events, stats = parse(p)
    _check_full_fixture(events, stats)


def test_parse_with_events_root(tmp_path):
    """Meme contenu, enveloppe cette fois dans une racine <Events> : les
    deux formats doivent produire un resultat identique."""
    p = tmp_path / "events_with_root.xml"
    p.write_text(_build_doc(_ALL_FRAGMENTS, with_root=True), encoding="utf-8")
    events, stats = parse(p)
    _check_full_fixture(events, stats)


def test_parse_accepts_str_path(tmp_path):
    """Le contrat dit `path: str | Path` : verifier que str marche aussi,
    pas seulement Path."""
    p = tmp_path / "events.xml"
    p.write_text(_build_doc(_ALL_FRAGMENTS, with_root=False), encoding="utf-8")
    events, stats = parse(str(p))
    assert len(events) == 4


def test_record_without_timestamp_is_unparsed_not_fatal(tmp_path):
    """Un record sans TimeCreated ne doit pas faire perdre les autres
    records du meme fichier (contrairement a un vrai XML tronque/mal
    forme, qui casse tout le document -- cas couvert separement)."""
    doc = _event_xml("EventLog", 6005, 4, "2026-07-24T08:00:00.0000000Z") + _FRAG_NO_TS
    p = tmp_path / "one_bad.xml"
    p.write_text(doc, encoding="utf-8")
    events, stats = parse(p)

    assert stats.total_lines == 2
    assert stats.parsed == 1
    assert stats.unparsed == 1
    assert len(events) == 1
    assert events[0].ident == "6005"
    assert events[0].category == "reboot"
    assert events[0].severity == 1


def test_empty_events_root_is_not_an_error(tmp_path):
    """Un <Events></Events> vide (requete wevtutil sans resultat) reussit
    avec zero evenement -- meme philosophie que pcap.read_capture sur un
    pcap vide (test_engine.test_empty_capture) : un resultat vide n'est
    pas une erreur de format."""
    p = tmp_path / "empty.xml"
    p.write_text("<Events></Events>", encoding="utf-8")
    events, stats = parse(p)
    assert events == []
    assert stats.total_lines == 0
    assert stats.parsed == 0
    assert stats.unparsed == 0


def test_malformed_xml_raises_actionable_valueerror(tmp_path):
    """Un document XML vraiment mal forme (ici : balises croisees) doit
    lever un ValueError actionnable, pas laisser fuiter une ParseError
    brute ni planter silencieusement."""
    p = tmp_path / "broken.xml"
    p.write_text("<Event><System></Event></System>", encoding="utf-8")
    with pytest.raises(ValueError, match="wevtutil"):
        parse(p)


@pytest.mark.skipif(_EVTX_LIB_PRESENT,
                    reason="python-evtx est installe : le cas 'absent' ne s'applique pas")
def test_evtx_binary_without_python_evtx_raises_actionable_error(tmp_path):
    """Fichier .evtx binaire reconnu par sa signature, mais python-evtx
    n'est pas installe dans cet environnement : le message doit donner la
    commande wevtutil de secours, pas juste 'ModuleNotFoundError'."""
    p = tmp_path / "fake.evtx"
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    with pytest.raises(ValueError, match="wevtutil"):
        parse(p)


@pytest.mark.skipif(not _EVTX_LIB_PRESENT,
                    reason="python-evtx non installe : rien a tester ici")
def test_evtx_binary_with_python_evtx_present_does_not_raise_import_error(tmp_path):
    """Si python-evtx EST installe, un faux .evtx (mauvais contenu apres la
    signature) ne doit ni lever d'ImportError ni laisser fuir une exception
    de la librairie.

    ATTENTE CORRIGEE (CI du 26/07, premier passage reel de cette branche) :
    python-evtx traverse ce fichier SANS lever — il rend simplement zero
    record. Exiger un ValueError decrivait donc un comportement imaginaire.
    Et lever serait faux de toute facon : un canal legitimement vide existe.
    Ce qui compte, c'est que le silence soit ROMPU — d'ou la note."""
    p = tmp_path / "fake.evtx"
    p.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    events, stats = parse(p)          # ne doit pas lever
    assert events == []
    assert "aucun evenement lu" in stats.note
    assert "wevtutil" in stats.note   # la sortie de secours est donnee
