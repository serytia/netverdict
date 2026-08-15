"""Conversations UDP : ce que le datagramme permet de dire, et rien de plus.

UDP n'offre aucun des reperes sur lesquels l'etage TCP s'appuie : pas de
handshake qui prouve qui est le client, pas d'acquittement qui prouve la
reception, pas de retransmission qui trahit la perte. Un etage UDP honnete
est donc BEAUCOUP plus pauvre en verdicts qu'un etage TCP - et c'est la
bonne nouvelle, parce que le seul risque serieux ici est d'en inventer.

Deux garde-fous portent tout le reste :

1. **L'absence de reponse n'est PAS une panne en UDP.** syslog, NetFlow,
   StatsD, les traps SNMP emettent en aveugle, par conception : personne ne
   repond, et tout va bien. Un verdict « le service ne repond pas » sur un
   flux syslog serait un faux positif de la pire espece - affirmatif, dans un
   outil dont le produit est la confiance. Le silence unidirectionnel sort
   donc en AMBIGU, avec la phrase qui dit exactement pourquoi on ne tranche
   pas, et JAMAIS en RESEAU.

2. **Ce qui porte un verdict fort, c'est l'ICMP.** Un « port unreachable »
   est l'equivalent exact du RST au SYN : la machine cible a repondu, et elle
   a dit que rien n'ecoutait. Un « administratively prohibited » nomme
   l'equipement qui filtre. Ces deux la sont des ACTES, pas des absences.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Optional

import dpkt

from .pcap import Capture, IcmpEvent, UdpPkt

# Au-dela de ce silence, un meme quadruplet ne designe plus la meme
# conversation : les ports ephemeres se recyclent, et fusionner deux echanges
# sans rapport fabriquerait des latences absurdes. Deux minutes couvrent
# largement les protocoles requete-reponse (DNS, RADIUS, SNMP, NTP repondent
# en secondes) sans jamais couper un echange en cours.
SESSION_GAP_S = 120.0

# Ports dont le serveur DOIT repondre : sur eux, et sur eux seuls, un silence
# total est une information.
#
# La charge de la preuve est volontairement inversee. La premiere version
# listait les protocoles unidirectionnels (syslog, NetFlow...) pour les
# excuser, et accusait tout le reste - mesure du 15/08 : cinq datagrammes
# syslog suffisaient a sortir un panneau AMBIGU et a faire passer le code
# retour a 1. Or a peu pres toute capture de serveur contient du syslog. Une
# liste d'exceptions est toujours incomplete ; une liste de ce qu'on CONNAIT
# ne se trompe que par omission, et l'omission est ici silencieuse - donc
# sans dommage.
#
# DHCP, SSDP, NetBIOS et mDNS en sont volontairement absents malgre leurs
# reponses : elles arrivent en broadcast/multicast, souvent depuis une autre
# adresse que celle interrogee, et ne se rattachent donc pas a la
# conversation. Les inclure fabriquerait des « sans reponse » systematiques.
ATTENDENT_UNE_REPONSE = {
    # Le DNS en fait partie, et c'est ce qui ferme le trou annonce par le
    # commentaire de cli.py : quand une question DNS est illisible (nom coupe
    # par le snaplen), l'etage DNS ne produit AUCUNE resolution, donc
    # `dns_handled` est faux - et sans le port 53 ici, personne ne disait rien
    # du silence de ce resolveur (revue du 15/08/2026).
    53: "DNS",
    123: "NTP", 161: "SNMP", 69: "TFTP", 88: "Kerberos", 111: "portmapper",
    389: "CLDAP", 500: "IKE", 4500: "IPsec NAT-T", 623: "IPMI", 2049: "NFS",
    1812: "RADIUS (auth)", 1813: "RADIUS (compta)", 1645: "RADIUS (auth, ancien)",
    1646: "RADIUS (compta, ancien)", 3799: "RADIUS (CoA)", 5060: "SIP",
}


@dataclass
class UdpConversation:
    client: str
    server: str
    cport: int
    sport: int
    pkts: list[tuple[float, bool, int]] = field(default_factory=list)
    icmp: list[IcmpEvent] = field(default_factory=list)
    # False quand le sens a ete DEVINE (port bas = serveur) faute d'avoir vu
    # qui a parle en premier. Les regles doivent le savoir : en UDP il n'y a
    # pas de SYN pour trancher.
    direction_confident: bool = True

    @property
    def key(self) -> str:
        return f"{self.client}:{self.cport} -> {self.server}:{self.sport}"


def _canon(p: UdpPkt) -> tuple:
    a, b = (p.src, p.sport), (p.dst, p.dport)
    return (a, b) if a <= b else (b, a)


def _est_un_service(port: int) -> bool:
    """Un port qu'un SERVEUR est susceptible d'ecouter. Sous 1024 il est
    reserve par le systeme, et nos ports requete-reponse connus s'y ajoutent."""
    return port < 1024 or port in ATTENDENT_UNE_REPONSE


def _oriente(p: UdpPkt) -> tuple[str, int, str, int, bool]:
    """(client, cport, serveur, sport, sens_sur) pour le premier datagramme.

    Deux indices, dans cet ordre, et jamais melanges - c'est le bug corrige
    le 15/08 : appliquer la comparaison de ports SYSTEMATIQUEMENT retournait
    la conversation des que le port source etait le plus bas des deux. Un
    emetteur 41000 -> 45000 (deux ports hauts, aucun service) se retrouvait
    ainsi oriente a l'envers ; ses cinq datagrammes comptaient alors comme des
    REPONSES, et un flux strictement unidirectionnel ressortait « echange
    bidirectionnel sans erreur ».
    """
    src_service = _est_un_service(p.sport)
    dst_service = _est_un_service(p.dport)
    if dst_service and not src_service:
        # Le cas normal : port ephemere -> port de service.
        return p.src, p.sport, p.dst, p.dport, True
    if src_service and not dst_service:
        # La capture a commence sur la REPONSE du service.
        return p.dst, p.dport, p.src, p.sport, False
    # Aucun indice (deux ports hauts, ou deux services qui se parlent, comme
    # deux pairs NTP en 123 -> 123) : le premier a parler fait foi, et le
    # doute est signale plutot que masque.
    return p.src, p.sport, p.dst, p.dport, False


def build_udp_conversations(cap: Capture) -> list[UdpConversation]:
    conversations: list[UdpConversation] = []
    ouvertes: dict[tuple, UdpConversation] = {}
    for p in cap.udp_packets:
        k = _canon(p)
        conv = ouvertes.get(k)
        if conv is not None and conv.pkts and p.ts - conv.pkts[-1][0] > SESSION_GAP_S:
            conv = None
        if conv is None:
            cli, cp, srv, sp, sur = _oriente(p)
            conv = UdpConversation(client=cli, server=srv, cport=cp, sport=sp,
                                   direction_confident=sur)
            ouvertes[k] = conv
            conversations.append(conv)
        from_client = (p.src, p.sport) == (conv.client, conv.cport)
        conv.pkts.append((p.ts, from_client, p.payload_len))

    # Rattachement des erreurs ICMP concernant de l'UDP. Elles portent le
    # quadruplet du datagramme fautif, donc le sens de la QUESTION.
    # UN SEUL SENS : le paquet fautif doit aller du client vers le serveur.
    # Enregistrer aussi le sens inverse faisait qu'un ICMP port-unreachable
    # emis par le CLIENT - a propos d'une reponse arrivee apres la fermeture
    # de son socket, ce qui est banal - declenchait « rien n'ecoute sur ce
    # port » CONTRE LE SERVEUR, avec confiance haute. L'outil accusait la
    # machine qui avait correctement repondu (revue du 15/08/2026).
    par_endpoints: dict[tuple, list[UdpConversation]] = {}
    for conv in conversations:
        cle = ((conv.client, conv.cport), (conv.server, conv.sport))
        par_endpoints.setdefault(cle, []).append(conv)
    for ev in cap.icmp_events:
        if ev.orig_proto != dpkt.ip.IP_PROTO_UDP:
            continue
        candidats = par_endpoints.get(
            ((ev.orig_src, ev.orig_sport), (ev.orig_dst, ev.orig_dport)))
        if candidats:
            # Le plus proche dans le temps : un meme quadruplet peut porter
            # plusieurs echanges successifs, et coller l'erreur au mauvais
            # ferait chercher la panne a la mauvaise minute.
            min(candidats, key=lambda c: abs(c.pkts[0][0] - ev.ts)
                if c.pkts else float("inf")).icmp.append(ev)
    return conversations


@dataclass
class UdpSignals:
    """Contrat entre les conversations UDP et les regles (scope `udp`)."""

    client: str = ""
    server: str = ""
    cport: int = 0
    sport: int = 0
    direction_confident: bool = True
    t_first: float = 0.0
    duration_s: float = 0.0
    pkts_c2s: int = 0
    pkts_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    answered: bool = False
    # Delai entre le premier datagramme client et le premier retour serveur.
    first_response_ms: Optional[float] = None
    icmp_port_unreachable: bool = False
    icmp_admin_prohibited: bool = False
    icmp_frag_needed: bool = False
    icmp_from: str = ""
    icmp_count: int = 0
    # Une erreur ICMP recue mais qu'aucune des trois categories ci-dessus ne
    # couvre (host-unreachable, network-unreachable, TTL exceeded, un code
    # v6...). Sans ce champ, elle ne declenchait AUCUN verdict tout en armant
    # le garde `icmp_count == 0` : plus de preuve rendait MOINS de verdict, et
    # le code retour repassait a 0 (revue du 15/08/2026).
    icmp_other: bool = False
    icmp_other_label: str = ""
    # Le port serveur est-il un service dont on SAIT qu'il repond ? C'est la
    # seule condition qui autorise a dire quoi que ce soit d'un silence.
    expects_reply: bool = False
    service_hint: str = ""
    # Vrai quand l'etage DNS a produit une resolution pour cette conversation :
    # ses verdicts sont plus precis, l'etage UDP se tait alors.
    dns_handled: bool = False
    is_dns_port: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


def compute_udp_signals(conv: UdpConversation,
                        dns_handled: bool = False) -> UdpSignals:
    c2s = [p for p in conv.pkts if p[1]]
    s2c = [p for p in conv.pkts if not p[1]]
    t0 = conv.pkts[0][0] if conv.pkts else 0.0
    t1 = conv.pkts[-1][0] if conv.pkts else 0.0
    # `repondu` exige une reponse POSTERIEURE a la premiere question. Compter
    # n'importe quel datagramme serveur (bool(s2c)) faisait passer une
    # conversation totalement sans reponse pour un « echange bidirectionnel
    # sans erreur » des qu'un datagramme du serveur - reste d'un echange
    # precedent sur le meme quadruplet, ou capture commencee en plein milieu -
    # trainait AVANT la question (revue du 15/08/2026).
    premiere_reponse = None
    repondu = False
    if c2s and s2c:
        apres = [p[0] for p in s2c if p[0] >= c2s[0][0]]
        if apres:
            repondu = True
            premiere_reponse = (apres[0] - c2s[0][0]) * 1000.0
    elif s2c and not c2s:
        # Que du trafic serveur et aucune question : l'orientation a ete
        # devinee, on ne prononce pas le mot « repondu ».
        repondu = False
    ic_unreach = any(e.is_port_unreachable for e in conv.icmp)
    ic_admin = any(e.is_admin_prohibited for e in conv.icmp)
    ic_frag = any(e.is_frag_needed for e in conv.icmp)
    emetteur = next((e.icmp_src for e in conv.icmp), "")
    autres = [e for e in conv.icmp
              if not (e.is_port_unreachable or e.is_admin_prohibited
                      or e.is_frag_needed)]
    label_autre = (f"type {autres[0].type} code {autres[0].code}"
                   if autres else "")
    service = ATTENDENT_UNE_REPONSE.get(conv.sport, "")
    return UdpSignals(
        client=conv.client, server=conv.server,
        cport=conv.cport, sport=conv.sport,
        direction_confident=conv.direction_confident,
        t_first=t0, duration_s=max(0.0, t1 - t0),
        pkts_c2s=len(c2s), pkts_s2c=len(s2c),
        bytes_c2s=sum(p[2] for p in c2s), bytes_s2c=sum(p[2] for p in s2c),
        answered=repondu,
        first_response_ms=premiere_reponse,
        icmp_port_unreachable=ic_unreach,
        icmp_admin_prohibited=ic_admin,
        icmp_frag_needed=ic_frag,
        icmp_from=emetteur,
        icmp_count=len(conv.icmp),
        icmp_other=bool(autres),
        icmp_other_label=label_autre,
        expects_reply=bool(service),
        service_hint=service,
        dns_handled=dns_handled,
        is_dns_port=conv.sport == 53 or conv.cport == 53,
    )
