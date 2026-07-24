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


def build_flows(cap: Capture) -> list[Flow]:
    # Passe 1 : reperer le client de chaque conversation via son SYN pur.
    # Le SYN est le seul marqueur fiable ; tout le reste est heuristique.
    syn_client: dict[tuple, tuple[str, int]] = {}
    for p in cap.tcp_packets:
        if p.syn and not p.ack_flag:
            syn_client.setdefault(_canon_key(p), (p.src, p.sport))

    flows: dict[tuple, Flow] = {}
    for p in cap.tcp_packets:
        k = _canon_key(p)
        fl = flows.get(k)
        if fl is None:
            if k in syn_client:
                c_ip, c_port = syn_client[k]
                confident = True
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
            fl = Flow(client=c_ip, server=s_ip, cport=c_port, sport=s_port,
                      direction_confident=confident)
            flows[k] = fl

        from_client = (p.src, p.sport) == (fl.client, fl.cport)
        if _is_dup_capture(fl.pkts, p, from_client):
            fl.dup_capture_skipped += 1
            continue
        fl.pkts.append(OrientedPkt(pkt=p, from_client=from_client))

    # Rattacher les erreurs ICMP a leur conversation d'origine.
    by_endpoints: dict[tuple, Flow] = {}
    for fl in flows.values():
        by_endpoints[((fl.client, fl.cport), (fl.server, fl.sport))] = fl
        by_endpoints[((fl.server, fl.sport), (fl.client, fl.cport))] = fl
    for ev in cap.icmp_events:
        fl = by_endpoints.get(((ev.orig_src, ev.orig_sport), (ev.orig_dst, ev.orig_dport)))
        if fl is not None:
            fl.icmp.append(ev)

    return list(flows.values())
