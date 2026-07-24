"""Unitaires du contrat timeline : fenetrage, changements, validation."""

import pytest

from netverdict.timeline import SourceStats, Timeline, TimelineEvent


def _ev(ts, category="info", severity=0, **kw):
    base = dict(ts=ts, source="syslog", host="h1", category=category,
                severity=severity, ident="test", message="m")
    base.update(kw)
    return TimelineEvent(**base)


def test_category_validation():
    with pytest.raises(ValueError):
        _ev(0.0, category="n_importe_quoi")


def test_window_keeps_lookback_and_drops_after_capture():
    tl = Timeline()
    tl.add_source("s", [
        _ev(100.0),                       # bien avant : hors fenetre
        _ev(1000.0, category="change"),   # dans le lookback de 15 min
        _ev(1600.0, category="service"),  # pendant la capture
        _ev(2100.0, category="change"),   # APRES la capture : exclu
    ], SourceStats(total_lines=4, parsed=4))
    win = tl.window(t_start=1500.0, t_end=2000.0)   # lookback 900 s -> lo=600
    assert [e.ts for e in win.events] == [1000.0, 1600.0]


def test_window_without_bounds_keeps_all():
    tl = Timeline()
    tl.add_source("s", [_ev(1.0), _ev(2.0)], SourceStats())
    assert len(tl.window(None, None).events) == 2


def test_changes_sorted_most_recent_first_and_filtered():
    tl = Timeline()
    tl.add_source("s", [
        _ev(10.0, category="change"),
        _ev(30.0, category="power"),
        _ev(20.0, category="info"),       # pas un changement
        _ev(25.0, category="error"),      # pas un changement non plus
    ], SourceStats())
    assert [e.ts for e in tl.changes()] == [30.0, 10.0]


def test_add_source_merges_and_sorts():
    tl = Timeline()
    tl.add_source("a", [_ev(5.0)], SourceStats())
    tl.add_source("b", [_ev(1.0), _ev(9.0)], SourceStats())
    assert [e.ts for e in tl.events] == [1.0, 5.0, 9.0]
    assert set(tl.stats) == {"a", "b"}
