"""Correlation changement d'infra <-> verdict de flux (v1.2).

Ces tests verrouillent surtout des NON-comportements, parce que le risque de
cette fonctionnalite n'est pas de rater un suspect : c'est d'en designer un
faux, ou de faire disparaitre le vrai. Trois proprietes a ne jamais casser :

  1. On CLASSE, on ne FILTRE pas : un changement sans affinite avec le verdict
     reste present, simplement plus bas.
  2. Un flux sain ne recoit aucun suspect (sinon le rapport devient du bruit).
  3. Sans fuseau fiable, aucune precision a la seconde n'est affichee.

Les verdicts viennent de la fixture `analyze` (vrais pcaps, vraies regles) :
fabriquer des FlowVerdict a la main testerait ma comprehension du moteur, pas
le moteur.
"""

from __future__ import annotations

import pytest

from netverdict.correlate import (MAX_SUSPECTS_PER_FLOW, STRONG_WINDOW_S,
                                 correlate, suspects_for)
from netverdict.timeline import SourceStats, Timeline, TimelineEvent


def _ev(ts, category="change", *, host="fw01", message="firewall rules reloaded",
        tz_known=True, severity=1, source="syslog", ident="firewalld"):
    return TimelineEvent(ts=ts, source=source, host=host, category=category,
                         severity=severity, ident=ident, message=message,
                         tz_known=tz_known)


def _tl(*events):
    tl = Timeline()
    tl.add_source("test", list(events), SourceStats())
    return tl


@pytest.fixture
def flux_reseau(analyze):
    """Un vrai verdict RESEAU (SYN sans reponse) issu d'un pcap synthetique."""
    _sig, fv = analyze("syn_no_answer")
    assert fv.verdict == "RESEAU"
    return fv


@pytest.fixture
def flux_sain(analyze):
    _sig, fv = analyze("clean")
    return fv


class TestCeQuOnNeRattachePas:
    def test_un_flux_sain_ne_recoit_aucun_suspect(self, flux_sain):
        """Rattacher des changements a un flux qui va bien ne produirait que
        du bruit dans un rapport dont la valeur est de trier."""
        tl = _tl(_ev(flux_sain.signals.t_first - 10))
        assert suspects_for(flux_sain, tl) == []

    def test_les_evenements_hors_changement_sont_ignores(self, flux_reseau):
        """Les categories info/error ne sont pas des changements d'infra :
        elles restent dans la timeline globale, pas dans le panneau."""
        t = flux_reseau.signals.t_first
        tl = _tl(_ev(t - 10, "info"), _ev(t - 20, "error", severity=2))
        assert suspects_for(flux_reseau, tl) == []

    def test_un_changement_trop_ancien_est_ecarte(self, flux_reseau):
        t = flux_reseau.signals.t_first
        tl = _tl(_ev(t - STRONG_WINDOW_S - 1))
        assert suspects_for(flux_reseau, tl) == []

    def test_un_changement_posterieur_a_la_fin_du_flux_est_ecarte(self, flux_reseau):
        """Rien apres la fin du flux ne peut expliquer ce qu'il contient."""
        s = flux_reseau.signals
        tl = _tl(_ev(s.t_first + s.duration_s + 30))
        assert suspects_for(flux_reseau, tl) == []

    def test_sans_timeline_la_correlation_est_vide(self, flux_reseau):
        assert correlate([flux_reseau], None) == {}


class TestClassementSansFiltrage:
    def test_l_affinite_passe_devant_la_proximite(self, flux_reseau):
        """Un changement du BON type mais plus ancien doit passer devant un
        changement du mauvais type plus proche : c'est tout l'apport du
        classement. Et le second reste present."""
        t = flux_reseau.signals.t_first
        proche_sans_affinite = _ev(t - 5, "power", ident="kernel",
                                   message="passage sur batterie")
        lointain_avec_affinite = _ev(t - 200, "network", ident="ifplugd",
                                     message="eth0: link down")
        out = suspects_for(flux_reseau, _tl(proche_sans_affinite,
                                           lointain_avec_affinite))
        assert [s.event.category for s in out] == ["network", "power"]
        assert [s.affinity for s in out] == [True, False]
        # Non-filtrage : les deux sont la.
        assert len(out) == 2

    def test_a_affinite_egale_le_plus_proche_gagne(self, flux_reseau):
        t = flux_reseau.signals.t_first
        out = suspects_for(flux_reseau, _tl(_ev(t - 200, "network"),
                                            _ev(t - 20, "network")))
        assert [round(s.delay_s) for s in out] == [20, 200]

    def test_le_plafond_garde_les_meilleurs(self, flux_reseau):
        """Quand on tronque, on ne doit pas jeter le suspect le plus pertinent."""
        t = flux_reseau.signals.t_first
        sans_affinite = [_ev(t - 1 - i, "power") for i in range(MAX_SUSPECTS_PER_FLOW + 3)]
        avec_affinite = _ev(t - 250, "network")
        out = suspects_for(flux_reseau, _tl(*sans_affinite, avec_affinite))
        assert len(out) == MAX_SUSPECTS_PER_FLOW
        assert out[0].event.category == "network"   # le pertinent survit

    def test_ambigu_n_attribue_aucune_affinite(self, analyze):
        """AMBIGU l'est par construction : afficher une affinite donnerait une
        fausse piste."""
        _sig, fv = analyze("midstream_rst")
        assert fv.verdict == "AMBIGU"
        t = fv.signals.t_first
        out = suspects_for(fv, _tl(_ev(t - 10, "network"), _ev(t - 20, "service")))
        assert out, "des changements dans la fenetre doivent rester affiches"
        assert all(not s.affinity for s in out)


class TestHonneteteDeLAffichage:
    def test_un_changement_pendant_le_flux_est_signale_comme_tel(self, flux_reseau):
        """L'instant exact de l'anomalie est inconnu : un changement survenu
        apres le premier paquet peut etre la cause d'un RST en pleine session.
        On l'affiche, en disant qu'il est PENDANT et non AVANT."""
        s = flux_reseau.signals
        assert s.duration_s > 1, "fixture inadaptee a ce test"
        out = suspects_for(flux_reseau, _tl(_ev(s.t_first + 1, "network")))
        assert len(out) == 1
        assert out[0].during_flow is True
        assert out[0].delay_s < 0
        assert "pendant le flux" in out[0].describe()

    def test_sans_fuseau_fiable_aucune_precision_a_la_seconde(self, flux_reseau):
        t = flux_reseau.signals.t_first
        approx = suspects_for(flux_reseau, _tl(_ev(t - 138, tz_known=False)))[0]
        exact = suspects_for(flux_reseau, _tl(_ev(t - 138, tz_known=True)))[0]
        assert "environ" in approx.describe()
        assert "approximative" in approx.describe()
        assert "138 s" in exact.describe()
        assert "environ" not in exact.describe()


class TestCorrelateTable:
    def test_indexation_par_position_et_pas_par_objet(self, flux_reseau, flux_sain):
        """FlowVerdict est une dataclass mutable, donc non hashable : la table
        doit etre indexee par position. Un flux sain n'y figure pas du tout."""
        tl = _tl(_ev(flux_reseau.signals.t_first - 10, "network"))
        table = correlate([flux_sain, flux_reseau], tl)
        assert set(table) == {1}
        assert table[1][0].event.category == "network"

    def test_le_json_expose_les_suspects_du_bon_flux(self, analyze, fixtures):
        """Bout en bout : le rapport JSON doit porter les suspects sous le flux
        concerne, avec le vocabulaire du soupcon (`suspects`, `affinity`)."""
        import json

        from netverdict.pcap import read_capture
        from netverdict.report import to_json

        _sig, fv = analyze("syn_no_answer")
        cap = read_capture(fixtures["syn_no_answer"])
        tl = _tl(_ev(fv.signals.t_first - 42, "network", message="eth0: link down"))
        data = json.loads(to_json(cap, [fv], None, tl))
        suspects = data["flows"][0]["suspects"]
        assert len(suspects) == 1
        assert suspects[0]["affinity"] is True
        assert suspects[0]["during_flow"] is False
        assert round(suspects[0]["delay_s"]) == 42
        assert "link down" in suspects[0]["message"]
