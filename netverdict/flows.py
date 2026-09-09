"""Regroupe les paquets en conversations TCP orientees client -> serveur.

Toujours l'etage "parse" : on etablit QUI parle a QUI et dans quel sens,
sans rien juger. Le sens compte enormement pour la suite : "zero window
cote serveur" et "zero window cote client" menent a des verdicts opposes.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

import dpkt

from .pcap import Capture, IcmpEvent, TcpPkt
from .timeline import TimelineEvent

# En dessous de ce delta, deux segments identiques (meme seq/len/ip_id) sont
# un doublon de capture (le sniffer a vu la meme trame deux fois, classique
# avec 'tcpdump -i any' sur un bridge), PAS une retransmission. Les confondre
# fabriquerait de fausses pertes reseau — le pire faux positif possible ici.
DUP_CAPTURE_WINDOW_S = 0.0001


@dataclass
class OrientedPkt:
    pkt: TcpPkt
    from_client: bool


@dataclass
class Flow:
    client: str
    server: str
    cport: int
    sport: int
    pkts: list[OrientedPkt] = field(default_factory=list)
    icmp: list[IcmpEvent] = field(default_factory=list)
    # False quand aucun SYN n'a ete vu : le sens client/serveur est alors une
    # heuristique (port bas = serveur) et les regles doivent le savoir.
    direction_confident: bool = True
    dup_capture_skipped: int = 0

    @property
    def key(self) -> str:
        return f"{self.client}:{self.cport} -> {self.server}:{self.sport}"


def _canon_key(p: TcpPkt) -> tuple:
    """Cle de conversation independante du sens du paquet."""
    a = (p.src, p.sport)
    b = (p.dst, p.dport)
    return (a, b) if a <= b else (b, a)


def _is_dup_capture(flow_pkts: list[OrientedPkt], p: TcpPkt, from_client: bool) -> bool:
    # On ne regarde que le dernier paquet du meme sens : les doublons de
    # capture sont adjacents dans le temps par construction.
    for op in reversed(flow_pkts):
        if op.from_client != from_client:
            continue
        q = op.pkt
        return (q.seq == p.seq and q.payload_len == p.payload_len
                and q.ip_id == p.ip_id and q.flags == p.flags
                and abs(p.ts - q.ts) < DUP_CAPTURE_WINDOW_S)
    return False


def _nouveau_flux(p: TcpPkt, syn_ep: Optional[tuple[str, int]]) -> Flow:
    """Cree la conversation a laquelle ce paquet appartient, et oriente-la."""
    if p.syn and not p.ack_flag:
        # Le SYN pur EST le debut de la connexion : son emetteur est le client,
        # sans aucune heuristique. Prioritaire sur syn_ep, qui porte le client
        # de la PREMIERE connexion vue sur ce quadruplet.
        c_ip, c_port, confident = p.src, p.sport, True
    elif syn_ep is not None:
        (c_ip, c_port), confident = syn_ep, True
    else:
        # Capture demarree en pleine session : on suppose que le port
        # le plus bas est le service (vrai pour l'ecrasante majorite
        # des services d'infra ; faux parfois en P2P — d'ou le flag).
        if p.sport >= p.dport:
            c_ip, c_port = p.src, p.sport
        else:
            c_ip, c_port = p.dst, p.dport
        confident = False
    if (p.src, p.sport) == (c_ip, c_port):
        s_ip, s_port = p.dst, p.dport
    else:
        s_ip, s_port = p.src, p.sport
    return Flow(client=c_ip, server=s_ip, cport=c_port, sport=s_port,
                direction_confident=confident)


def _ecart_temporel(fl: Flow, ts: float) -> float:
    """Distance de `ts` a la duree de vie du flux ; 0 s'il tombe dedans."""
    if not fl.pkts:
        return float("inf")
    t0, t1 = fl.pkts[0].pkt.ts, fl.pkts[-1].pkt.ts
    if t0 <= ts <= t1:
        return 0.0
    return t0 - ts if ts < t0 else ts - t1


def build_flows(cap: Capture) -> list[Flow]:
    # Passe 1 : reperer le client de chaque conversation via son SYN pur.
    # Le SYN est le seul marqueur fiable ; tout le reste est heuristique.
    syn_client: dict[tuple, tuple[str, int]] = {}
    for p in cap.tcp_packets:
        if p.syn and not p.ack_flag:
            syn_client.setdefault(_canon_key(p), (p.src, p.sport))

    # Passe 2. Un quadruplet peut porter PLUSIEURS connexions successives : le
    # noyau recycle les ports ephemeres, et une capture un peu longue sur un
    # hote charge en voit forcement. Les fusionner melangeait deux espaces de
    # numeros de sequence sans rapport : chaque segment de la seconde
    # connexion, plus bas que le maximum atteint par la premiere, etait compte
    # comme une retransmission. Deux sessions HTTPS parfaites ressortaient
    # « 50 % de perte, RESEAU, confiance haute » (durcissement du 08/08/2026).
    #
    # Le decoupage se fait sur l'ISN, jamais sur un delai : un SYN RETRANSMIS
    # reemet le meme ISN, une nouvelle connexion en tire un nouveau. C'est la
    # seule frontiere qui ne casse pas le diagnostic de DROP silencieux, ou
    # trois SYN sans reponse doivent rester UN flux.
    flows: list[Flow] = []
    ouverts: dict[tuple, Flow] = {}
    isn_courant: dict[tuple, int] = {}
    for p in cap.tcp_packets:
        k = _canon_key(p)
        fl = ouverts.get(k)
        if p.syn and not p.ack_flag:
            precedent = isn_courant.get(k)
            if precedent is None:
                isn_courant[k] = p.seq
            elif p.seq != precedent:
                isn_courant[k] = p.seq
                fl = None                  # nouvelle connexion, meme quadruplet
        if fl is None:
            fl = _nouveau_flux(p, syn_client.get(k))
            ouverts[k] = fl
            flows.append(fl)

        from_client = (p.src, p.sport) == (fl.client, fl.cport)
        if _is_dup_capture(fl.pkts, p, from_client):
            fl.dup_capture_skipped += 1
            continue
        fl.pkts.append(OrientedPkt(pkt=p, from_client=from_client))

    # Rattacher les erreurs ICMP a leur conversation d'origine. Quand le meme
    # quadruplet en porte plusieurs, c'est l'HORODATAGE qui tranche : coller le
    # REJECT de 5,1 s a une connexion morte a 0,3 s ferait chercher a l'admin
    # le changement de configuration a la mauvaise minute.
    by_endpoints: dict[tuple, list[Flow]] = {}
    for fl in flows:
        for cle in (((fl.client, fl.cport), (fl.server, fl.sport)),
                    ((fl.server, fl.sport), (fl.client, fl.cport))):
            by_endpoints.setdefault(cle, []).append(fl)
    for ev in cap.icmp_events:
        # Le PROTOCOLE du paquet fautif fait partie de l'identite : depuis que
        # les conversations UDP existent, un « port unreachable » concernant un
        # datagramme UDP ne doit pas etre colle a une conversation TCP qui
        # porterait par hasard les memes ports. 0 = protocole illisible : on
        # garde l'ancien comportement plutot que de priver le TCP d'une preuve.
        if ev.orig_proto not in (0, dpkt.ip.IP_PROTO_TCP):
            continue
        candidats = by_endpoints.get(
            ((ev.orig_src, ev.orig_sport), (ev.orig_dst, ev.orig_dport)))
        if candidats:
            min(candidats, key=lambda f: _ecart_temporel(f, ev.ts)).icmp.append(ev)

    return flows


# ---------------------------------------------------------------------------
# Fenetre de scan : le "qui a balaye qui, et quand"
#
# Une machine qui tombe apres un scan de vulnerabilites fait accuser le scan.
# Pour DEDOUANER ou ACCUSER, il faut d'abord la fenetre exacte du balayage :
# c'est ce que ce bloc calcule, et rien de plus. Il ne conclut pas (c'est
# correlate.py) et ne juge aucun flux (c'est le moteur de regles) — meme
# discipline que partout ailleurs : l'etage qui mesure ne conclut jamais.
# ---------------------------------------------------------------------------

# 30 ports distincts : un client legitime en contacte une poignee sur un meme
# serveur (web + api + metriques font 3 ou 4) ; passe 30, on n'est plus dans
# l'usage, on est dans l'enumeration. Le seuil est volontairement bien au-dessus
# de ce qu'un client bavard atteint, parce que le cout d'un faux "scan" est
# eleve : c'est exactement l'accusation que cet outil existe pour arbitrer.
SCAN_MIN_PORTS = 30
# 120 s : un balayage TCP outille fait ses centaines de ports en quelques
# secondes. Etaler 30 ports sur plus de deux minutes, c'est le rythme d'un
# superviseur qui teste une liste de services, pas d'un scanner.
SCAN_WINDOW_S = 120.0


@dataclass
class ScanEvent(TimelineEvent):
    """Une fenetre de scan, vue comme un TimelineEvent (contrat timeline.py).

    Meme choix de sous-typage que BurstEvent : la fenetre voyage dans
    `Timeline.events` comme n'importe quel evenement — la correlation, le tri
    et le fenetrage n'apprennent pas un type de plus. Les consommateurs qui
    veulent le detail chiffre testent `isinstance`.

    end   : dernier SYN de la fenetre (epoch, UTC), donc `end - ts` = duree.
    ports : nombre de ports DISTINCTS vises.
    """

    end: float = 0.0
    ports: int = 0
    client: str = ""
    server: str = ""


def _est_sonde(p: TcpPkt) -> bool:
    """SYN pur sans donnee : la seule forme qu'on accepte de compter.

    Un SYN+ACK est une REPONSE et un SYN portant des donnees (TCP Fast Open)
    est une connexion qui travaille : ni l'un ni l'autre n'est un coup de sonde.
    """
    return p.syn and not p.ack_flag and p.payload_len == 0


def detect_scans(flows: Iterable[Flow], min_ports: int = SCAN_MIN_PORTS,
                 window_s: float = SCAN_WINDOW_S) -> list[TimelineEvent]:
    """Fenetres de balayage de ports presentes dans une capture.

    Un scan = un MEME client qui sonde au moins `min_ports` ports DISTINCTS
    d'un MEME serveur en `window_s` secondes au plus, avec une majorite de SYN
    sans donnees. Les trois conditions ensemble, jamais l'une seule :

      - meme couple (client, serveur) : 40 ports repartis sur 40 serveurs est
        une carte du reseau, pas le balayage d'une machine — et ce n'est pas la
        question posee ici (« ce serveur a-t-il ete scanne avant de tomber ? ») ;
      - ports distincts : 40 connexions vers le port 443 d'un serveur web sont
        un client normal, meme si elles sont simultanees ;
      - majorite de SYN sans donnees : 40 connexions ETABLIES qui echangent des
        octets sont un client qui travaille. Un scanner ouvre et abandonne.

    Retourne les fenetres triees par date, une par salve de sondes chainees :
    un balayage de 300 s reste UN evenement, sinon « le scan » deviendrait un
    artefact du decoupage et le rapport en compterait trois pour un.
    """
    if min_ports <= 0 or window_s < 0:
        raise ValueError(f"min_ports must be > 0 and window_s >= 0 "
                         f"(got {min_ports}, {window_s})")

    # Par couple (client, serveur) : les sondes d'un cote, TOUS les paquets du
    # client de l'autre. Le second compte sert a juger « majoritairement des
    # SYN sans donnees » sur la fenetre retenue, pas sur la capture entiere.
    sondes: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    emis: dict[tuple[str, str], list[float]] = defaultdict(list)
    for fl in flows:
        cle = (fl.client, fl.server)
        for op in fl.pkts:
            if not op.from_client:
                continue
            emis[cle].append(op.pkt.ts)
            if _est_sonde(op.pkt):
                sondes[cle].append((op.pkt.ts, fl.sport))

    out: list[TimelineEvent] = []
    for (client, server), pts in sondes.items():
        pts.sort()
        dates = sorted(emis[(client, server)])
        # Deux pointeurs : la fenetre glissante [g, d] ne garde que les sondes
        # a moins de window_s l'une de l'autre. Un Counter suit le nombre de
        # ports DISTINCTS dedans sans le recalculer a chaque pas.
        vus: Counter = Counter()
        g = 0
        chaudes: list[tuple[int, int]] = []
        for d, (ts, port) in enumerate(pts):
            vus[port] += 1
            while pts[g][0] < ts - window_s:
                vus[pts[g][1]] -= 1
                if not vus[pts[g][1]]:
                    del vus[pts[g][1]]
                g += 1
            if len(vus) >= min_ports:
                chaudes.append((g, d))

        # Fusion des fenetres qui se recouvrent : un balayage plus long que
        # window_s en produit une par sonde, et c'est le MEME scan.
        groupes: list[list[int]] = []
        for g0, d0 in chaudes:
            if groupes and g0 <= groupes[-1][1]:
                groupes[-1][1] = d0
            else:
                groupes.append([g0, d0])

        for g0, d0 in groupes:
            fenetre = pts[g0:d0 + 1]
            debut, fin = fenetre[0][0], fenetre[-1][0]
            ports = len({p for _ts, p in fenetre})
            # « Majoritairement des SYN sans donnees » : sur la fenetre, les
            # sondes doivent etre la MAJORITE STRICTE de ce que le client a
            # emis vers ce serveur. Une session etablie emet un ACK puis des
            # donnees pour un seul SYN : elle est mecaniquement minoritaire.
            envoyes = sum(1 for ts in dates if debut <= ts <= fin)
            if len(fenetre) * 2 <= envoyes:
                continue
            out.append(ScanEvent(
                ts=debut,
                # La capture est la source : ses horodatages sont des epochs
                # absolus, jamais une heure locale a deviner (d'ou tz_known).
                source="pcap",
                # L'hote du rapport est la CIBLE : c'est la machine dont
                # l'admin cherche a savoir ce qui lui est arrive.
                host=server,
                category="scan",
                # 2 = "erreur" sur l'echelle du projet : a lire avant les
                # infos, jamais avant un crash machine.
                severity=2,
                ident=client,
                message=(f"port scan from {client} to {server}: "
                         f"{ports} ports in {fin - debut:.0f} s"),
                end=fin,
                ports=ports,
                client=client,
                server=server,
            ))

    out.sort(key=lambda e: (e.ts, e.host, e.ident))
    return out
