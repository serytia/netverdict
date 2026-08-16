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
        # describe() sans lang explicite suit desormais le defaut de l'outil
        # (anglais depuis 0.7.0) : voir test_i18n.py pour la bascule --lang.
        assert "during the flow" in out[0].describe()

    def test_sans_fuseau_fiable_aucune_precision_a_la_seconde(self, flux_reseau):
        t = flux_reseau.signals.t_first
        approx = suspects_for(flux_reseau, _tl(_ev(t - 138, tz_known=False)))[0]
        exact = suspects_for(flux_reseau, _tl(_ev(t - 138, tz_known=True)))[0]
        assert "about" in approx.describe()
        assert "approximate" in approx.describe()
        assert "138 s" in exact.describe()
        assert "approximate" not in exact.describe()


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


def test_une_attribution_hors_du_flux_annonce_la_tolerance_d_horloge():
    """La tolerance d'horloge est appliquee symetriquement - une derive de
    30 s entre deux machines est banale - si bien qu'un connect() POSTERIEUR
    a la fin du flux peut etre retenu. C'est voulu, mais l'attribution repose
    alors sur cette tolerance et non sur une concordance directe : le rapport
    doit le dire (revue du 26/07/2026).
    """
    from netverdict.correlate import attribution_for
    from netverdict.signals import FlowSignals
    from netverdict.rules.engine import FlowVerdict
    from netverdict.timeline import Timeline, TimelineEvent, ConnectionInfo

    sig = FlowSignals(client="10.0.0.1", server="10.0.0.2", cport=5000,
                      sport=443, t_first=100.0, duration_s=2.0)
    fv = FlowVerdict(signals=sig)

    def event(ts):
        return TimelineEvent(
            ts=ts, source="sysmon", host="h", category="service", severity=1,
            ident="sysmon", message="connect", tz_known=True,
            connection=ConnectionInfo(
                src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2",
                dst_port=443, protocol="tcp", image="app.exe", pid=1))

    dedans = attribution_for(fv, Timeline(events=[event(101.0)]))
    assert dedans is not None and dedans.within_flow is True
    assert "tolerance" not in dedans.describe("fr")

    # 40 s APRES la fin du flux : retenu, mais signale comme tel.
    dehors = attribution_for(fv, Timeline(events=[event(142.0)]))
    assert dehors is not None and dehors.within_flow is False
    assert "tolerance" in dehors.describe("fr")

    # Et quand les deux existent, celui qui tombe DANS le flux gagne.
    les_deux = attribution_for(fv, Timeline(events=[event(142.0), event(101.0)]))
    assert les_deux.within_flow is True


def test_le_connect_qui_a_CREE_le_flux_est_bien_dans_le_flux():
    """Regression introduite le 15/08 et trouvee en revue : `dans_le_flux`
    comparait a `sig.t_first` tout court, alors qu'un connect() PRECEDE
    toujours le paquet qu'il produit. L'attribution la plus banale qui soit -
    le connect() journalise trois millisecondes avant le SYN - etait donc
    declaree hors du flux, affichait un avertissement de derive d'horloge sans
    raison, et passait DERRIERE au tri."""
    from netverdict.correlate import attribution_for
    from netverdict.signals import FlowSignals
    from netverdict.rules.engine import FlowVerdict
    from netverdict.timeline import Timeline, TimelineEvent, ConnectionInfo

    sig = FlowSignals(client="10.0.0.1", server="10.0.0.2", cport=5000,
                      sport=443, t_first=100.0, duration_s=2.0)
    fv = FlowVerdict(signals=sig)

    def ev(ts, pid, image):
        return TimelineEvent(
            ts=ts, source="sysmon", host="h", category="service", severity=1,
            ident="sysmon", message="connect", tz_known=True,
            connection=ConnectionInfo(
                src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2",
                dst_port=443, protocol="tcp", image=image, pid=pid))

    # 3 ms AVANT le premier paquet : c'est le cas NORMAL.
    a = attribution_for(fv, Timeline(events=[ev(99.997, 1, "app.exe")]))
    assert a.within_flow is True
    assert "tolerance" not in a.describe("fr")

    # Et il doit BATTRE un evenement parasite tombant au milieu du flux.
    deux = attribution_for(fv, Timeline(events=[ev(99.997, 1, "le-vrai.exe"),
                                                ev(101.5, 2, "un-autre.exe")]))
    assert deux.connection.pid == 1, "un parasite a battu le connect() du flux"


def test_un_evenement_DANS_le_flux_prime_sur_un_plus_proche_mais_dehors():
    """Verrou du terme `not dans_le_flux` du tri (correlate.py).

    Le test precedent ne le prouvait pas : ses deux evenements tombaient tous
    deux dans le flux, si bien que le tri par ecart suffisait a departager et
    que retirer le terme laissait la suite verte (revue du 15/08/2026).
    Il faut un evenement HORS du flux mais PLUS PROCHE de t_first que le bon.
    """
    from netverdict.correlate import attribution_for
    from netverdict.signals import FlowSignals
    from netverdict.rules.engine import FlowVerdict
    from netverdict.timeline import Timeline, TimelineEvent, ConnectionInfo

    # Flux de 100.0 a 102.0 ; marge causale = 1 s, donc « dans le flux » va
    # de 99.0 a 102.0.
    sig = FlowSignals(client="10.0.0.1", server="10.0.0.2", cport=5000,
                      sport=443, t_first=100.0, duration_s=2.0)
    fv = FlowVerdict(signals=sig)

    def ev(ts, pid, image):
        return TimelineEvent(
            ts=ts, source="sysmon", host="h", category="service", severity=1,
            ident="sysmon", message="connect", tz_known=True,
            connection=ConnectionInfo(
                src_ip="10.0.0.1", src_port=5000, dst_ip="10.0.0.2",
                dst_port=443, protocol="tcp", image=image, pid=pid))

    dehors_mais_proche = ev(98.5, 1, "parasite.exe")   # ecart 1.5, HORS flux
    dedans_mais_loin = ev(102.0, 2, "le-vrai.exe")     # ecart 2.0, DANS le flux
    a = attribution_for(fv, Timeline(events=[dehors_mais_proche,
                                             dedans_mais_loin]))
    assert a.connection.pid == 2, (
        "un evenement hors du flux, mais plus proche, a ete prefere")
    assert a.within_flow is True
