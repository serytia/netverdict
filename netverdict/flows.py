"""Regroupe les paquets en conversations TCP orientees client -> serveur.

Toujours l'etage "parse" : on etablit QUI parle a QUI et dans quel sens,
sans rien juger. Le sens compte enormement pour la suite : "zero window
cote serveur" et "zero window cote client" menent a des verdicts opposes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .pcap import Capture, IcmpEvent, TcpPkt

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
        candidats = by_endpoints.get(
            ((ev.orig_src, ev.orig_sport), (ev.orig_dst, ev.orig_dport)))
        if candidats:
            min(candidats, key=lambda f: _ecart_temporel(f, ev.ts)).icmp.append(ev)

    return flows
