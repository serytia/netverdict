"""Conversations UDP : ce qu'on affirme, et surtout ce qu'on refuse d'affirmer.

Le risque de cet etage n'est pas de rater une panne, c'est d'en inventer.
UDP n'a ni handshake, ni acquittement, ni retransmission : la seule chose
qu'une capture prouve, c'est ce qu'un ICMP a DIT. Le reste est du silence, et
le silence y est souvent le fonctionnement normal.

Le defaut de la premiere version, mesure le 15/08 et verrouille ici : la
regle du silence accusait TOUT port inconnu. Cinq datagrammes syslog - c'est
a dire a peu pres n'importe quelle capture de serveur - suffisaient a sortir
un panneau AMBIGU et a faire passer le code retour a 1.
"""

from __future__ import annotations

import socket

import dpkt
import pytest

from netverdict.pcap import read_capture
from netverdict.rules.engine import evaluate_udp, load_udp_rules
from netverdict.udp import (SESSION_GAP_S, build_udp_conversations,
                            compute_udp_signals)

CLIENT = "10.0.0.1"
SERVEUR = "10.0.0.9"


@pytest.fixture(scope="module")
def udp_rules():
    return load_udp_rules()


def _eth(ip):
    e = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                               type=dpkt.ethernet.ETH_TYPE_IP)
    e.data = ip
    return bytes(e)


def _ip(src, dst, proto, payload, ident=1):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=proto, ttl=64, id=ident)
    ip.data = payload
    ip.len = 20 + len(bytes(payload))
    return ip


def udp(ts, src, dst, sport, dport, taille=20, ident=1):
    u = dpkt.udp.UDP(sport=sport, dport=dport)
    u.data = b"\x01" * taille
    u.ulen = 8 + taille
    return (ts, _eth(_ip(src, dst, dpkt.ip.IP_PROTO_UDP, u, ident)))


def icmp_pour_udp(ts, code, src=SERVEUR, sport=40000, dport=1812, ident=99):
    """Erreur ICMP embarquant un datagramme UDP fautif."""
    orig_u = dpkt.udp.UDP(sport=sport, dport=dport)
    orig_u.data = b"\x01" * 20
    orig_u.ulen = 28
    orig_ip = _ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_UDP, orig_u, ident)
    ic = dpkt.icmp.ICMP(type=3, code=code)
    ic.data = dpkt.icmp.ICMP.Unreach(data=orig_ip)
    return (ts, _eth(_ip(src, CLIENT, dpkt.ip.IP_PROTO_ICMP, ic, ident + 1)))


def capture(tmp_path, trames, nom="udp.pcap"):
    chemin = tmp_path / nom
    with open(chemin, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in trames:
            w.writepkt(buf, ts=ts)
    return read_capture(chemin)


def verdicts(tmp_path, trames, udp_rules, nom="udp.pcap"):
    cap = capture(tmp_path, trames, nom)
    convs = build_udp_conversations(cap)
    return evaluate_udp([compute_udp_signals(c) for c in convs],
                        udp_rules, lang="fr")


# ------------------------------------------------------- regroupement / sens

def test_le_premier_a_parler_est_le_client(tmp_path):
    cap = capture(tmp_path, [udp(0.0, CLIENT, SERVEUR, 40000, 1812),
                             udp(0.1, SERVEUR, CLIENT, 1812, 40000)])
    conv = build_udp_conversations(cap)[0]
    assert (conv.client, conv.cport) == (CLIENT, 40000)
    assert (conv.server, conv.sport) == (SERVEUR, 1812)
    s = compute_udp_signals(conv)
    assert s.pkts_c2s == 1 and s.pkts_s2c == 1
    assert s.answered is True
    assert s.first_response_ms == pytest.approx(100, abs=5)


def test_une_capture_commencee_en_pleine_session_signale_son_doute(tmp_path):
    """Premier paquet vu = celui du SERVEUR. Le port bas sert alors d'indice,
    et le doute doit remonter jusqu'aux regles."""
    cap = capture(tmp_path, [udp(0.0, SERVEUR, CLIENT, 1812, 40000),
                             udp(0.1, CLIENT, SERVEUR, 40000, 1812)])
    conv = build_udp_conversations(cap)[0]
    assert conv.direction_confident is False
    assert (conv.server, conv.sport) == (SERVEUR, 1812)


def test_un_long_silence_ouvre_une_nouvelle_conversation(tmp_path):
    """Les ports ephemeres se recyclent : fusionner deux echanges sans rapport
    fabriquerait des latences absurdes."""
    cap = capture(tmp_path, [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812),
        udp(SESSION_GAP_S + 10.0, CLIENT, SERVEUR, 40000, 1812),
    ])
    assert len(build_udp_conversations(cap)) == 2


def test_la_taille_vient_de_l_en_tete_pas_des_octets_captures(tmp_path):
    """Meme discipline que le TCP : sous snaplen, len(payload) mentirait."""
    ts, trame = udp(0.0, CLIENT, SERVEUR, 40000, 1812, taille=1000)
    cap = capture(tmp_path, [(ts, trame[:96])])   # tronque comme -s 96
    # La trame coupee n'est plus decodable en entier ; ce qui compte est que la
    # lecture ne plante pas et que le compte reste coherent.
    st = cap.stats
    assert st.total == 1
    assert st.udp + st.non_ip + st.parse_errors == 1


# --------------------------------------------------------------- les actes

def test_un_port_ferme_est_impute_au_service(tmp_path, udp_rules):
    """L'equivalent UDP du RST au SYN : la machine a repondu, et elle a dit
    que rien n'ecoutait. Avant cet etage, ces deux paquets ne produisaient
    AUCUN verdict et un code retour 0."""
    vs = verdicts(tmp_path, [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812),
        icmp_pour_udp(0.01, 3),
        udp(1.0, CLIENT, SERVEUR, 40000, 1812, ident=5),
        icmp_pour_udp(1.01, 3, ident=101),
    ], udp_rules)
    assert len(vs) == 1
    assert vs[0].verdict == "APP"
    assert vs[0].primary.rule.id == "udp-port-unreachable"
    assert vs[0].signals.icmp_from == SERVEUR


def test_un_refus_administratif_nomme_l_equipement(tmp_path, udp_rules):
    vs = verdicts(tmp_path, [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812),
        icmp_pour_udp(0.01, 13, src="10.0.0.254"),
    ], udp_rules)
    assert vs[0].verdict == "RESEAU"
    assert vs[0].primary.rule.id == "udp-reject-icmp"
    assert vs[0].signals.icmp_from == "10.0.0.254"


def test_fragmentation_requise_sur_un_gros_datagramme(tmp_path, udp_rules):
    vs = verdicts(tmp_path, [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812, taille=1400),
        icmp_pour_udp(0.01, 4, src="10.0.0.254"),
    ], udp_rules)
    assert vs[0].verdict == "RESEAU"
    assert vs[0].primary.rule.id == "udp-mtu-blackhole"


# ---------------------------------------------------------------- le silence

@pytest.mark.parametrize("port, service", [(123, "NTP"), (161, "SNMP"),
                                           (1812, "RADIUS (auth)")])
def test_un_service_cense_repondre_qui_se_tait_sort_en_ambigu(tmp_path, udp_rules,
                                                              port, service):
    vs = verdicts(tmp_path, [udp(i * 2.0, CLIENT, SERVEUR, 40000, port, ident=i)
                             for i in range(3)], udp_rules)
    assert vs[0].verdict == "AMBIGU"       # jamais RESEAU : le service peut
    assert vs[0].primary.rule.id == "udp-known-service-silent"   # ignorer
    assert vs[0].signals.service_hint == service


@pytest.mark.parametrize("port", [514, 2055, 8125, 45000])
def test_un_emetteur_unidirectionnel_ne_produit_aucun_verdict(tmp_path,
                                                              udp_rules, port):
    """LE garde-fou. syslog (514), NetFlow (2055), StatsD (8125) et n'importe
    quel port maison emettent sans reponse par conception. Un verdict ici
    serait un faux positif sur presque toute capture de serveur - et ferait
    passer le code retour a 1 pour rien."""
    vs = verdicts(tmp_path, [udp(i * 0.2, CLIENT, SERVEUR, 41000, port, ident=i)
                             for i in range(5)], udp_rules)
    assert len(vs) == 1
    assert vs[0].primary is None, (
        f"port {port}: verdict {vs[0].primary.rule.id if vs[0].primary else None} "
        f"rendu sur un flux potentiellement unidirectionnel")


def test_un_envoi_unique_ne_dit_rien(tmp_path, udp_rules):
    """Un seul datagramme peut n'etre qu'un keepalive, ou la capture qui
    s'arrete juste apres."""
    vs = verdicts(tmp_path, [udp(0.0, CLIENT, SERVEUR, 40000, 123)], udp_rules)
    assert vs[0].primary is None


def test_un_echange_bidirectionnel_est_RAS(tmp_path, udp_rules):
    vs = verdicts(tmp_path, [udp(0.0, CLIENT, SERVEUR, 40000, 123),
                             udp(0.05, SERVEUR, CLIENT, 123, 40000)], udp_rules)
    assert vs[0].verdict == "RAS"
    assert vs[0].primary.rule.id == "udp-exchange-ok"


# ------------------------------------------------- frontiere avec les autres

def test_un_icmp_concernant_de_l_udp_ne_va_pas_aux_flux_tcp(tmp_path):
    """Le protocole du paquet fautif fait partie de l'identite : sans lui, une
    erreur UDP pouvait etre collee a une conversation TCP de memes ports."""
    from netverdict.flows import build_flows
    from dpkt.tcp import TH_SYN
    seg = dpkt.tcp.TCP(sport=40000, dport=1812, flags=TH_SYN, seq=1, win=1024)
    seg.data = b""
    tcp_trame = (0.0, _eth(_ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_TCP, seg, 3)))
    cap = capture(tmp_path, [tcp_trame, icmp_pour_udp(0.02, 3)])
    flux = build_flows(cap)
    assert len(flux) == 1
    assert flux[0].icmp == [], "l'erreur UDP a ete rattachee a un flux TCP"
    # La capture ne contient AUCUN datagramme UDP : il n'y a donc pas de
    # conversation a laquelle rattacher l'erreur. L'ancienne assertion
    # (`conv == [] or ...`) etait vraie par construction et ne prouvait rien.
    # Ce qui compte est verifie plus haut : le flux TCP ne l'a pas prise.
    assert build_udp_conversations(cap) == []
    # Et le pendant : la MEME erreur, avec cette fois la conversation UDP
    # correspondante, doit bien lui etre rattachee.
    cap2 = capture(tmp_path, [udp(0.0, CLIENT, SERVEUR, 40000, 1812),
                              icmp_pour_udp(0.02, 3)], nom="avec-udp.pcap")
    conv2 = build_udp_conversations(cap2)
    assert len(conv2) == 1 and len(conv2[0].icmp) == 1


def test_le_compte_de_paquets_boucle_avec_de_l_udp(tmp_path):
    cap = capture(tmp_path, [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812),
        icmp_pour_udp(0.01, 3),
        udp(0.2, CLIENT, SERVEUR, 41000, 514),
    ])
    st = cap.stats
    assert st.total == (st.tcp + st.udp + st.icmp + st.other_ip + st.non_ip
                        + st.fragments_skipped + st.parse_errors)


# ---------------------------------------------- verrous poses par la revue

def test_un_icmp_emis_par_le_CLIENT_n_accuse_pas_le_serveur(tmp_path, udp_rules):
    """Le rattachement enregistrait les DEUX sens du quadruplet. Un ICMP
    port-unreachable emis par le CLIENT - a propos d'une reponse arrivee apres
    la fermeture de son socket, ce qui est banal - declenchait « rien n'ecoute
    sur ce port » CONTRE LE SERVEUR, confiance haute. L'outil accusait la
    machine qui avait correctement repondu (revue du 15/08/2026)."""
    orig_u = dpkt.udp.UDP(sport=1812, dport=40000)   # le paquet fautif est la
    orig_u.data = b"\x01" * 20                       # REPONSE du serveur
    orig_u.ulen = 28
    orig_ip = _ip(SERVEUR, CLIENT, dpkt.ip.IP_PROTO_UDP, orig_u, 42)
    ic = dpkt.icmp.ICMP(type=3, code=3)
    ic.data = dpkt.icmp.ICMP.Unreach(data=orig_ip)
    trames = [
        udp(0.0, CLIENT, SERVEUR, 40000, 1812),
        udp(0.1, SERVEUR, CLIENT, 1812, 40000),
        (0.2, _eth(_ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_ICMP, ic, 43))),
    ]
    vs = verdicts(tmp_path, trames, udp_rules)
    assert vs[0].signals.icmp_port_unreachable is False, (
        "l'ICMP du client a ete retenu contre le serveur")
    ids = [m.rule.id for m in vs[0].matches]
    assert "udp-port-unreachable" not in ids


def test_une_reponse_ANTERIEURE_a_la_question_ne_vaut_pas_reponse(tmp_path,
                                                                  udp_rules):
    """`answered = bool(s2c)` comptait n'importe quel datagramme serveur, meme
    anterieur a la question : une conversation totalement sans reponse passait
    pour un « echange bidirectionnel sans erreur »."""
    trames = [
        udp(0.0, SERVEUR, CLIENT, 123, 40000, ident=1),   # reste d'avant
        udp(5.0, CLIENT, SERVEUR, 40000, 123, ident=2),   # la question
        udp(7.0, CLIENT, SERVEUR, 40000, 123, ident=3),   # reemise, en vain
    ]
    vs = verdicts(tmp_path, trames, udp_rules)
    assert vs[0].signals.answered is False
    ids = [m.rule.id for m in vs[0].matches]
    assert "udp-exchange-ok" not in ids, "un flux muet a ete declare sain"


def test_un_icmp_non_reconnu_ne_fait_plus_taire_l_etage(tmp_path, udp_rules):
    """Une erreur ICMP hors des trois categories connues (ici host-unreachable,
    type 3 code 1) ne declenchait aucun verdict ET armait le garde
    `icmp_count == 0` : RECEVOIR une preuve rendait MOINS de verdict que ne
    rien recevoir, et le code retour repassait a 0."""
    trames = [udp(i * 2.0, CLIENT, SERVEUR, 40000, 123, ident=i)
              for i in range(3)]
    trames.append(icmp_pour_udp(6.5, 1, dport=123))     # code 1 = host unreach
    vs = verdicts(tmp_path, trames, udp_rules)
    assert vs[0].signals.icmp_other is True
    assert vs[0].primary is not None, "l'etage s'est taci malgre une erreur ICMP"
    assert vs[0].primary.rule.id == "udp-icmp-non-interprete"
    assert "type 3 code 1" in vs[0].primary.evidence[0]


def test_deux_ports_hauts_laissent_le_sens_INCERTAIN(tmp_path):
    """La troisieme branche de _oriente - aucun indice de port - pose aussi
    direction_confident=False, et rien ne le verifiait : si ce False regressait
    en True, le rapport cesserait d'afficher « sens devine » et presenterait
    comme etabli un client que rien dans la capture ne distingue du serveur."""
    cap = capture(tmp_path, [udp(0.0, CLIENT, SERVEUR, 41000, 45000),
                             udp(0.1, CLIENT, SERVEUR, 41000, 45000, ident=2)])
    conv = build_udp_conversations(cap)[0]
    assert conv.direction_confident is False
    # Et le cas nominal reste sur, lui.
    cap2 = capture(tmp_path, [udp(0.0, CLIENT, SERVEUR, 40000, 123)],
                   nom="nominal.pcap")
    assert build_udp_conversations(cap2)[0].direction_confident is True


def test_un_ulen_menteur_ne_gonfle_pas_les_octets_comptes(tmp_path):
    """Un datagramme peut annoncer 65535 octets dans un paquet IP qui en fait
    48. Ce mensonge passait entier dans bytes_c2s, donc dans la preuve de
    udp-mtu-blackhole - c'est-a-dire precisement la ou la taille est
    l'argument du verdict."""
    u = dpkt.udp.UDP(sport=40000, dport=1812)
    u.data = b"\x01" * 20
    u.ulen = 65535                       # mensonge
    trame = _eth(_ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_UDP, u, 1))
    cap = capture(tmp_path, [(0.0, trame)])
    s = compute_udp_signals(build_udp_conversations(cap)[0])
    assert s.bytes_c2s <= 40, f"ulen menteur passe : {s.bytes_c2s} octets"


def test_le_port_53_compte_parmi_les_services_qui_repondent(tmp_path, udp_rules):
    """Quand une question DNS est illisible (nom coupe par le snaplen), l'etage
    DNS ne produit aucune resolution : `dns_handled` est faux, et c'est
    l'etage UDP qui doit parler. Sans le port 53 dans la liste, personne ne
    disait rien du silence de ce resolveur - le trou que le commentaire de
    cli.py affirmait avoir bouche."""
    from netverdict.udp import ATTENDENT_UNE_REPONSE
    assert 53 in ATTENDENT_UNE_REPONSE
    vs = verdicts(tmp_path, [udp(i * 5.0, CLIENT, SERVEUR, 40000, 53, ident=i)
                             for i in range(3)], udp_rules)
    assert vs[0].primary is not None
    assert vs[0].primary.rule.id == "udp-known-service-silent"
    assert vs[0].signals.service_hint == "DNS"
