"""Validation terrain de l'etage UDP : pcaps produits par un VRAI kernel.

Ce que seul un vrai noyau apporte ici : les erreurs ICMP sont emises par la
pile Linux elle-meme. Un port sans listener declenche un ICMP type 3 code 3
sans que personne ne le fabrique - et c'est precisement le signal qui portait
le verdict manquant. Avant cet etage (mesure du 15/08), un service UDP arrete
donnait :

    4 packets read - 0 TCP, 2 UDP, 2 ICMP, 0 non-IP - 0 conversations
    (rien)                                             # code retour 0

L'ICMP etait pourtant parfaitement decode : il n'etait rattache a rien.

Le dernier test est un TEMOIN NEGATIF, et c'est le plus important du fichier :
il verifie que netverdict SE TAIT sur un flux syslog unidirectionnel. La
premiere version de l'etage accusait tout port inconnu, et cinq datagrammes
syslog suffisaient a produire un panneau AMBIGU et un code retour 1 - sur a
peu pres n'importe quelle capture de serveur.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netverdict.pcap import read_capture
from netverdict.rules.engine import evaluate_udp, load_udp_rules
from netverdict.udp import build_udp_conversations, compute_udp_signals

LAB_DIR = Path(__file__).parent / "fixtures" / "lab"

pytestmark = pytest.mark.skipif(
    not (LAB_DIR / "udp_port_ferme.pcap").is_file(),
    reason="pcaps UDP du lab absents (generer avec lab/udp_scenario.sh)",
)


def analyse(nom):
    cap = read_capture(LAB_DIR / f"{nom}.pcap")
    convs = build_udp_conversations(cap)
    return cap, evaluate_udp([compute_udp_signals(c) for c in convs],
                             load_udp_rules())


ATTENDU = {
    "udp_port_ferme": ("APP", "udp-port-unreachable"),
    "udp_reject": ("RESEAU", "udp-reject-icmp"),
    "udp_ntp_muet": ("AMBIGU", "udp-known-service-silent"),
    "udp_echange": ("RAS", "udp-exchange-ok"),
}


@pytest.mark.parametrize("nom, attendu", sorted(ATTENDU.items()))
def test_le_verdict_terrain_concorde(nom, attendu):
    verdict, regle = attendu
    _, vs = analyse(nom)
    assert len(vs) == 1, f"{nom}: {len(vs)} conversations, 1 attendue"
    assert vs[0].verdict == verdict
    obtenu = vs[0].primary.rule.id if vs[0].primary else None
    assert obtenu == regle, f"{nom}: {obtenu!r} au lieu de {regle!r}"


def test_l_icmp_du_kernel_nomme_bien_son_emetteur():
    """L'erreur vient de la pile du serveur lui-meme, pas d'un equipement
    intermediaire : c'est ce qui distingue « rien n'ecoute » de « filtrage »."""
    _, vs = analyse("udp_port_ferme")
    s = vs[0].signals
    assert s.icmp_port_unreachable is True
    assert s.icmp_from == s.server        # le serveur repond pour lui-meme
    assert s.answered is False            # aucun datagramme applicatif en retour


def test_le_reject_nomme_l_equipement_qui_filtre():
    _, vs = analyse("udp_reject")
    s = vs[0].signals
    assert s.icmp_admin_prohibited is True
    assert s.icmp_from != ""


def test_le_service_connu_muet_reste_un_ambigu_et_jamais_un_reseau():
    """Un service peut recevoir et IGNORER (secret RADIUS inconnu, mauvaise
    communaute SNMP) : indiscernable d'un DROP vu du client. Affirmer
    « RESEAU » ici serait une accusation que la capture ne soutient pas."""
    _, vs = analyse("udp_ntp_muet")
    assert vs[0].verdict == "AMBIGU"
    s = vs[0].signals
    assert s.expects_reply is True
    assert s.service_hint == "NTP"
    assert s.icmp_count == 0              # ni port ferme, ni filtrage explicite


def test_TEMOIN_NEGATIF_un_syslog_unidirectionnel_ne_produit_aucun_verdict():
    """Le garde-fou de tout l'etage, sur un vrai listener qui ne repond
    jamais. Si ce test tombe, netverdict s'est remis a accuser le
    fonctionnement normal de la moitie de l'infrastructure."""
    cap, vs = analyse("udp_syslog_unidirectionnel")
    assert cap.stats.udp >= 5             # les datagrammes sont bien la
    assert len(vs) == 1
    assert vs[0].primary is None, (
        f"verdict {vs[0].primary.rule.id if vs[0].primary else None} rendu sur "
        f"un flux syslog a sens unique")
    assert vs[0].signals.expects_reply is False


def test_le_compte_de_paquets_boucle_sur_toutes_les_captures_udp():
    for nom in list(ATTENDU) + ["udp_syslog_unidirectionnel"]:
        st = read_capture(LAB_DIR / f"{nom}.pcap").stats
        somme = (st.tcp + st.udp + st.icmp + st.other_ip + st.non_ip
                 + st.fragments_skipped + st.parse_errors)
        assert st.total == somme, f"{nom}: {st.total - somme} paquets perdus"
