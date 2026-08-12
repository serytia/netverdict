"""Attribution par correspondance PARTIELLE (source sans port source).

Un record auditd connect() ne porte que la destination : le noyau n'a pas
encore attribue le port source au moment de l'appel. Sans ce chemin, la
jointure Linux serait silencieusement inerte (constate le 26/07 : _side_of
renvoyait None sur 100 % des events auditd).

Ces tests verrouillent les DEUX cotes du compromis : la jointure marche, et
elle annonce sa propre faiblesse.
"""

from netverdict.correlate import ProcessAttribution, _side_of, attribution_for
from netverdict.rules.engine import FlowVerdict, Match, Rule
from netverdict.rules.engine import Clause
from netverdict.signals import FlowSignals
from netverdict.timeline import ConnectionInfo, SourceStats, Timeline, TimelineEvent


def _sig(t_first=1000.0, duration=5.0):
    return FlowSignals(client="10.0.0.42", cport=51001,
                       server="10.0.0.5", sport=443,
                       t_first=t_first, duration_s=duration)


def _fv(sig=None):
    """FlowVerdict minimal avec un verdict non-RAS (l'attribution vaut aussi
    pour les flux sains, mais on reste proche du cas d'usage)."""
    rule = Rule(id="x", verdict="APP", priority=50, confidence="haute",
                title="t", when=Clause(mode="all", children=[]), unless=None,
                evidence=[], remediation="")
    return FlowVerdict(signals=sig or _sig(),
                       matches=[Match(rule=rule, evidence=[])])


def _conn_event(ts, dst_ip="10.0.0.5", dst_port=443, src_ip="", src_port=0,
                pid=4242, image="/usr/bin/curl"):
    return TimelineEvent(
        ts=ts, source="auditd", host="", category="info", severity=0,
        ident="connect", message="auditd: connexion reseau",
        connection=ConnectionInfo(src_ip=src_ip, src_port=src_port,
                                  dst_ip=dst_ip, dst_port=dst_port,
                                  protocol="tcp", pid=pid, image=image,
                                  initiated=True))


def _timeline(*events):
    tl = Timeline()
    tl.add_source("auditd:audit.log", list(events), SourceStats())
    return tl


# --- le chemin partiel existe et marche -----------------------------------

def test_destination_seule_attribue_le_flux():
    match = _side_of(_conn_event(1000.0).connection, _sig())
    assert match == ("client", False)


def test_attribution_partielle_de_bout_en_bout():
    attr = attribution_for(_fv(), _timeline(_conn_event(1000.2)))
    assert attr is not None
    assert attr.side == "client"
    assert attr.exact is False
    assert attr.connection.pid == 4242


def test_le_rapport_annonce_la_faiblesse():
    attr = attribution_for(_fv(), _timeline(_conn_event(1000.2)))
    texte = attr.describe()
    # describe() sans lang explicite suit desormais le defaut de l'outil
    # (anglais depuis 0.7.0) : voir test_i18n.py pour la bascule --lang.
    assert "DESTINATION only" in texte
    assert "indistinguishable" in texte


# --- il ne doit pas produire de faux positifs ------------------------------

def test_destination_differente_ne_matche_pas():
    assert _side_of(_conn_event(1000.0, dst_ip="10.0.0.99").connection,
                    _sig()) is None
    assert _side_of(_conn_event(1000.0, dst_port=8080).connection,
                    _sig()) is None


def test_flux_entrant_ne_matche_pas():
    """Un connect() local ne peut pas expliquer un flux ENTRANT : la
    destination de l'event serait notre propre cote client."""
    conn = _conn_event(1000.0, dst_ip="10.0.0.42", dst_port=51001).connection
    assert _side_of(conn, _sig()) is None


# --- la qualite prime sur la proximite temporelle --------------------------

def test_une_correspondance_exacte_bat_une_partielle_plus_proche():
    exact_loin = _conn_event(1004.0, src_ip="10.0.0.42", src_port=51001,
                             pid=111, image="/usr/bin/exact")
    partiel_proche = _conn_event(1000.1, pid=222, image="/usr/bin/partiel")
    attr = attribution_for(_fv(), _timeline(partiel_proche, exact_loin))
    assert attr.exact is True
    assert attr.connection.pid == 111


def test_candidates_ne_compte_que_la_meme_qualite():
    tl = _timeline(_conn_event(1000.1, pid=1), _conn_event(1000.2, pid=2),
                   _conn_event(1004.0, src_ip="10.0.0.42", src_port=51001,
                               pid=9))
    attr = attribution_for(_fv(), tl)
    # L'exacte gagne, et n'annonce pas les deux partielles comme rivales.
    assert attr.exact is True and attr.candidates == 1


def test_plusieurs_partielles_signalent_l_ambiguite():
    attr = attribution_for(_fv(), _timeline(_conn_event(1000.1, pid=1),
                                            _conn_event(1000.9, pid=2)))
    assert attr.exact is False
    assert attr.candidates == 2
    assert "2 connections matched" in attr.describe()
