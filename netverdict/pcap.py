"""Lecture d'une capture (pcap ou pcapng) -> flux de paquets normalises.

Etage "decoder" au sens Wazuh : ce module PARSE, il ne juge rien.
Tout ce qui ressemble a une interpretation (retransmission, RTT, verdict)
vit plus haut (flows.py, signals.py, rules/).

Choix assumes v1 :
- dpkt plutot que tshark : aucune dependance systeme, l'outil doit tourner
  sur un poste d'admin nu (pip install et c'est tout).
- Les paquets non parsables sont COMPTES puis ignores, jamais fatals :
  une capture reelle contient toujours du bruit (trames tronquees par le
  snaplen, protocoles exotiques, padding).
- Fragments IP non-premiers ignores : le premier fragment porte l'en-tete
  TCP, c'est lui qui nous interesse ; reassembler serait du travail pour
  un gain nul en triage.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator, Optional

import dpkt

from .dns import DNS_PORTS, DnsMsg, parse_dns_datagram

# Plafond des octets conserves par segment TCP/53. Une reponse DNS sur TCP
# peut atteindre 64 Ko, mais celles qui comptent en diagnostic (une zone qui a
# grossi, un AXFR refuse) tiennent tres en dessous : 8 Ko bornent la memoire
# sans rien perdre d'utile.
MAX_TCP_PAYLOAD_KEPT = 8192
from .i18n import DEFAULT_LANG, t

# Linktypes rencontres en pratique sur les captures d'admins.
# (tcpdump Linux = EN10MB ou LINUX_SLL selon -i any ; pktmon Windows = EN10MB ;
#  loopback Windows/Npcap et BSD = NULL ; certains equipements exportent du RAW.)
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_OLD = 12
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276


@dataclass
class TcpPkt:
    """Vue plate d'un segment TCP : uniquement des faits bruts du fil."""

    ts: float                     # epoch en secondes (float, precision de la capture)
    src: str
    dst: str
    sport: int
    dport: int
    flags: int                    # bitmask dpkt.tcp.TH_*
    seq: int
    ack: int
    win: int                      # fenetre BRUTE (avant window scale)
    payload_len: int
    ip_id: int                    # utile pour reperer les doublons de capture
    ws_opt: Optional[int] = None  # option window-scale si presente (SYN/SYNACK)
    # Octets applicatifs, conserves UNIQUEMENT pour le port 53. Les garder
    # partout multiplierait par mille l'empreinte memoire d'une grosse capture
    # (un million de segments a 1400 octets), pour un outil qui ne lit
    # deliberement aucun contenu applicatif ailleurs. Le DNS sur TCP fait
    # exception parce que c'est le repli obligatoire d'une reponse tronquee :
    # sans ces octets, on sait qu'un repli a eu lieu mais pas ce qu'il a donne.
    payload: bytes = b""

    @property
    def syn(self) -> bool: return bool(self.flags & dpkt.tcp.TH_SYN)
    @property
    def ack_flag(self) -> bool: return bool(self.flags & dpkt.tcp.TH_ACK)
    @property
    def rst(self) -> bool: return bool(self.flags & dpkt.tcp.TH_RST)
    @property
    def fin(self) -> bool: return bool(self.flags & dpkt.tcp.TH_FIN)
    @property
    def psh(self) -> bool: return bool(self.flags & dpkt.tcp.TH_PUSH)


@dataclass
class IcmpEvent:
    """Erreur ICMP rattachable a un flux : c'est le reseau qui PARLE.

    Un "destination unreachable" contient l'en-tete IP+TCP du paquet fautif ;
    on extrait ce quintuplet pour rattacher l'erreur a sa conversation.
    Distinction qui compte pour le verdict : un firewall en DROP se tait,
    un firewall en REJECT emet admin-prohibited (code 9/10/13) ou un RST.
    """

    ts: float
    icmp_src: str                 # qui emet l'erreur (souvent un routeur/firewall)
    orig_src: str                 # quintuplet du paquet qui a declenche l'erreur
    orig_dst: str
    orig_sport: int
    orig_dport: int
    type: int
    code: int
    # Protocole du paquet FAUTIF (6 = TCP, 17 = UDP). Sans lui, le rattachement
    # ne se fait que sur le quadruplet : une erreur concernant un datagramme
    # UDP pourrait etre collee a une conversation TCP portant par hasard les
    # memes ports, et surtout les erreurs UDP n'avaient nulle part ou aller.
    orig_proto: int = 0

    # Codes ICMPv4 type 3 qui signent un refus administratif (REJECT).
    ADMIN_PROHIBITED = {9, 10, 13}
    FRAG_NEEDED = 4
    PORT_UNREACHABLE = 3

    @property
    def is_admin_prohibited(self) -> bool:
        return self.type == 3 and self.code in self.ADMIN_PROHIBITED

    @property
    def is_frag_needed(self) -> bool:
        return self.type == 3 and self.code == self.FRAG_NEEDED

    @property
    def is_port_unreachable(self) -> bool:
        """« Rien n'ecoute sur ce port » — l'equivalent UDP du RST au SYN.
        En ICMPv6 c'est le type 1 code 4 (port unreachable)."""
        return ((self.type == 3 and self.code == self.PORT_UNREACHABLE)
                or (self.type == 1 and self.code == 4))


def _detect_mixed_linktypes(path) -> bool:
    """Le pcapng declare-t-il plusieurs linktypes distincts ?

    Lecture directe des blocs IDB (type 0x00000001) : dpkt n'expose pas cette
    information. Toute anomalie de structure retourne False — cette fonction
    est un DETECTEUR D'AVERTISSEMENT, elle ne doit jamais empecher une lecture
    par ailleurs valide.
    """
    import struct

    try:
        data = open(path, "rb").read(1 << 20)      # les IDB sont en tete
    except OSError:
        return False
    if not data.startswith(PCAPNG_MAGIC):
        return False                               # pcap classique : 1 seul linktype
    endian = "<"
    if len(data) >= 12 and struct.unpack_from("<I", data, 8)[0] == 0x4D3C2B1A:
        endian = ">"
    linktypes: set[int] = set()
    pos = 0
    while pos + 12 <= len(data):
        try:
            btype, blen = struct.unpack_from(endian + "II", data, pos)
        except struct.error:
            break
        if blen < 12 or pos + blen > len(data):
            break
        if btype == 0x00000001:                    # IDB
            try:
                linktypes.add(struct.unpack_from(endian + "H", data, pos + 8)[0])
            except struct.error:
                break
        pos += blen
    return len(linktypes) > 1


@dataclass
class ParseStats:
    """Comptabilite de lecture — publiee dans le rapport pour l'honnetete :
    un verdict rendu sur une capture illisible a 40 % ne vaut rien."""

    total: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    # Tout paquet IP dont le transport n'est ni TCP, ni UDP, ni ICMP (GRE,
    # ESP, IGMP, ou un transport que dpkt a laisse en octets bruts). Existe
    # pour que la ligne de comptes BOUCLE : avant, un paquet UDP etait lu,
    # compte dans total, et n'apparaissait dans AUCUNE colonne du rapport.
    other_ip: int = 0
    non_ip: int = 0
    fragments_skipped: int = 0
    parse_errors: int = 0
    # Paquets UDP vers ou depuis le port 53, comptes SANS etre decodes :
    # cette version n'analyse pas le DNS, et une capture qui en contient
    # merite de l'apprendre. Une resolution lente ou en echec se produit
    # AVANT le SYN et n'apparait donc dans aucun verdict TCP : sans cette
    # ligne, le rapport rend un "transport sain" qui se lit "tout va bien".
    udp_dns: int = 0
    # Datagrammes UDP/53 dont il ne reste meme pas les douze octets d'en-tete :
    # comptes a part pour ne pas les faire passer pour du DNS analyse.
    dns_unreadable: int = 0
    linktype: int = -1
    unsupported_linktype: bool = False
    # Le pcapng declare plusieurs interfaces de linktypes differents : les
    # paquets de la ou des autres interfaces sont decodes avec le mauvais
    # format et finissent en non_ip. Le rapport DOIT le dire (voir report.py).
    mixed_linktypes: bool = False


@dataclass
class UdpPkt:
    """Un datagramme UDP. Volontairement pauvre : hors du DNS, tout ce qu'on
    peut dire honnetement tient dans le quadruplet, l'instant et la taille."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload_len: int


@dataclass
class Capture:
    tcp_packets: list[TcpPkt] = field(default_factory=list)
    udp_packets: list[UdpPkt] = field(default_factory=list)
    icmp_events: list[IcmpEvent] = field(default_factory=list)
    dns_msgs: list["DnsMsg"] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)
    # Horodatage du dernier paquet lu, TOUS protocoles confondus. Distinct de
    # t_last, qui ne parle que du TCP : une resolution DNS restee sans reponse
    # doit etre bornee par la fin REELLE de la capture, sinon on la declarerait
    # « sans reponse » alors que la capture s'est simplement arretee avant.
    t_last_seen: Optional[float] = None

    @property
    def t_first(self) -> Optional[float]:
        return self.tcp_packets[0].ts if self.tcp_packets else None

    @property
    def t_last(self) -> Optional[float]:
        return self.tcp_packets[-1].ts if self.tcp_packets else None


PCAP_MAGICS = {b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",   # pcap classique (big/little)
               b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"}   # pcap nanoseconde
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _open_reader(f: BinaryIO, lang: str = DEFAULT_LANG):
    """Choisit le lecteur d'apres le magic, pas d'apres l'extension :
    les admins renomment les fichiers, le magic ne ment pas."""
    head = f.read(4)
    f.seek(0)
    if head == PCAPNG_MAGIC:
        return dpkt.pcapng.Reader(f)
    if head in PCAP_MAGICS:
        return dpkt.pcap.Reader(f)
    raise ValueError(t("err.pcap_format", lang))


def _ip_from_frame(buf: bytes, linktype: int):
    """Extrait le paquet IP (dpkt.ip.IP ou ip6.IP6) de la trame, selon linktype.

    Retourne None si la trame ne transporte pas d'IP (ARP, LLDP, STP...).
    Leve dpkt.Error / struct.error sur trame corrompue (gere par l'appelant).
    """
    if linktype == LINKTYPE_ETHERNET:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        # dpkt deballe le VLAN 802.1Q tout seul (eth.data traverse le tag),
        # mais un QinQ ou un ethertype inconnu laisse des bytes bruts.
        if isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return ip
        # pktmon etl2pcap declare "Ethernet" mais ecrit du RAW IP pour les
        # paquets captes aux couches NDIS sans en-tete Ethernet (loopback,
        # composants IP) — constate sur capture reelle : trames commencant
        # par 0x45. Si l'interpretation Ethernet ne donne pas d'IP et que le
        # premier nibble est une version IP plausible, on retente en brut.
        if buf and (buf[0] >> 4) in (4, 6):
            try:
                return (dpkt.ip.IP(buf) if buf[0] >> 4 == 4
                        else dpkt.ip6.IP6(buf))
            except Exception:
                return None
        return None
    if linktype in (LINKTYPE_LINUX_SLL,):
        sll = dpkt.sll.SLL(buf)
        return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (LINKTYPE_LINUX_SLL2,):
        sll = dpkt.sll2.SLL2(buf)
        return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype == LINKTYPE_NULL:
        lo = dpkt.loopback.Loopback(buf)
        return lo.data if isinstance(lo.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_OLD):
        version = buf[0] >> 4
        if version == 4:
            return dpkt.ip.IP(buf)
        if version == 6:
            return dpkt.ip6.IP6(buf)
        return None
    return None


def _ip_str(raw: bytes) -> str:
    import socket
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw)
    return socket.inet_ntop(socket.AF_INET6, raw)


def _parse_ws_option(tcp: dpkt.tcp.TCP) -> Optional[int]:
    """Option window-scale (kind 3), presente uniquement sur SYN/SYNACK.

    On la garde pour information ; la detection zero-window n'en depend pas
    (une fenetre annoncee a 0 est 0 quel que soit le scale)."""
    try:
        for kind, data in dpkt.tcp.parse_opts(tcp.opts):
            if kind == 3 and len(data) == 1:
                return data[0]
    except Exception:
        # Options malformees : frequentes sur captures tronquees, non fatal.
        pass
    return None


def _extract_icmp_event(ts: float, ip, icmp_payload: bytes, icmp_type: int,
                        icmp_code: int) -> Optional[IcmpEvent]:
    """Le payload d'un ICMP d'erreur = en-tete IP + >=8 octets du transport
    du paquet fautif. Assez pour retrouver (src, dst, sport, dport)."""
    try:
        version = icmp_payload[0] >> 4
        if version == 4:
            orig = dpkt.ip.IP(icmp_payload)
        elif version == 6:
            orig = dpkt.ip6.IP6(icmp_payload)
        else:
            return None
        # Le transport embarque est souvent tronque a 8 octets : dpkt peut ne
        # pas produire un objet TCP complet, on lit les ports a la main.
        transport = bytes(orig.data) if not isinstance(orig.data, bytes) else orig.data
        if len(transport) < 4:
            return None
        sport, dport = struct.unpack("!HH", transport[:4])
        # IPv4 porte le protocole dans `p`, IPv6 dans `nxt`. Une extension
        # IPv6 rendrait `nxt` non transport, mais un ICMP d'erreur n'embarque
        # que le debut du paquet : le cas est marginal et se solde par un
        # rattachement inerte, jamais par une erreur.
        proto = getattr(orig, "p", None)
        if proto is None:
            proto = getattr(orig, "nxt", 0)
        return IcmpEvent(
            ts=ts,
            icmp_src=_ip_str(ip.src),
            orig_src=_ip_str(orig.src),
            orig_dst=_ip_str(orig.dst),
            orig_sport=sport,
            orig_dport=dport,
            type=icmp_type,
            code=icmp_code,
            orig_proto=int(proto or 0),
        )
    except Exception:
        return None


def read_capture(path: str | Path, lang: str = DEFAULT_LANG) -> Capture:
    """Lit toute la capture en memoire.

    v1 assume le chargement complet : un pcap de triage fait quelques Mo a
    quelques centaines de Mo, et TcpPkt ne garde PAS le payload (on stocke
    sa longueur, pas ses octets) — l'empreinte memoire reste ~100 octets/pkt.
    Si un jour il faut du multi-Go, ce module est le seul a changer (streaming).
    """
    cap = Capture()
    st = cap.stats
    # Un pcapng peut declarer PLUSIEURS interfaces (un bloc IDB chacune), aux
    # linktypes differents — c'est exactement ce que produit un `mergecap`
    # d'une capture client et d'une capture serveur, geste que la remediation
    # AMBIGU de cet outil recommande elle-meme. Or dpkt.pcapng ne retient que
    # le PREMIER IDB et n'expose pas l'interface de chaque paquet : tout
    # serait decode avec le mauvais linktype pour l'une des deux moities, qui
    # tomberait silencieusement en « non-IP » (audit du 26/07). On ne peut pas
    # decoder correctement sans sortir de dpkt, mais on peut REFUSER DE MENTIR.
    st.mixed_linktypes = _detect_mixed_linktypes(path)
    with open(path, "rb") as f:
        reader = _open_reader(f, lang)
        st.linktype = getattr(reader, "datalink", lambda: -1)()

        for ts, buf in reader:
            st.total += 1
            # Un max, pas le dernier vu : un pcap issu d'un mergecap n'est pas
            # forcement dans l'ordre (c'est deja pourquoi les listes sont
            # triees plus bas).
            if cap.t_last_seen is None or ts > cap.t_last_seen:
                cap.t_last_seen = float(ts)
            try:
                ip = _ip_from_frame(buf, st.linktype)
            except Exception:
                st.parse_errors += 1
                continue
            if ip is None:
                if st.linktype not in (LINKTYPE_ETHERNET, LINKTYPE_NULL,
                                       LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
                                       LINKTYPE_RAW, LINKTYPE_RAW_OLD):
                    st.unsupported_linktype = True
                st.non_ip += 1
                continue

            # Fragment IPv4 non-premier : pas d'en-tete TCP dedans, on saute.
            if isinstance(ip, dpkt.ip.IP) and ip.offset > 0:
                st.fragments_skipped += 1
                continue

            data = ip.data

            if isinstance(data, dpkt.tcp.TCP):
                st.tcp += 1
                tcp = data
                # Longueur du payload calculee depuis les EN-TETES, jamais
                # depuis les octets captures : une capture en-tetes-seuls
                # (pktmon 128 octets, tcpdump -s96) tronque les payloads et
                # len(tcp.data) mentirait sur toutes les longueurs.
                try:
                    if isinstance(ip, dpkt.ip.IP):
                        payload_len = ip.len - (ip.hl * 4) - (tcp.off * 4)
                    else:  # IPv6 sans extensions (le cas courant)
                        payload_len = ip.plen - (tcp.off * 4)
                    if payload_len < 0:
                        raise ValueError
                except Exception:
                    payload_len = len(tcp.data) if isinstance(tcp.data, bytes) \
                        else len(bytes(tcp.data))
                cap.tcp_packets.append(TcpPkt(
                    ts=float(ts),
                    src=_ip_str(ip.src),
                    dst=_ip_str(ip.dst),
                    sport=tcp.sport,
                    dport=tcp.dport,
                    flags=tcp.flags,
                    seq=tcp.seq,
                    ack=tcp.ack,
                    win=tcp.win,
                    payload_len=payload_len,
                    ip_id=getattr(ip, "id", 0),
                    ws_opt=_parse_ws_option(tcp) if (tcp.flags & dpkt.tcp.TH_SYN) else None,
                    payload=(bytes(tcp.data)[:MAX_TCP_PAYLOAD_KEPT]
                             if (tcp.sport == 53 or tcp.dport == 53)
                                and tcp.data else b""),
                ))
            elif isinstance(data, dpkt.icmp.ICMP):
                st.icmp += 1
                # Seul le type 3 (unreachable) porte un verdict ; echo/reply
                # et TTL exceeded viendront avec l'analyse traceroute (v2).
                if data.type == 3:
                    ev = _extract_icmp_event(float(ts), ip, bytes(data.data.data)
                                             if hasattr(data.data, "data") else b"",
                                             data.type, data.code)
                    if ev:
                        cap.icmp_events.append(ev)
            elif isinstance(data, dpkt.icmp6.ICMP6):
                st.icmp += 1
                # ICMPv6 type 1 = destination unreachable (code 1 = admin prohibited).
                if data.type == 1:
                    ev = _extract_icmp_event(float(ts), ip, bytes(data.data)[4:],
                                             data.type, data.code)
                    if ev:
                        cap.icmp_events.append(ev)
            elif isinstance(data, dpkt.udp.UDP):
                st.udp += 1
                # Longueur prise dans l'EN-TETE (ulen - 8) et non dans les
                # octets capturés : sous snaplen, len(data.data) mentirait sur
                # toutes les tailles - meme raisonnement que pour le TCP.
                charge_len = (data.ulen - 8) if data.ulen >= 8 \
                    else len(data.data or b"")
                cap.udp_packets.append(UdpPkt(
                    ts=float(ts), src=_ip_str(ip.src), dst=_ip_str(ip.dst),
                    sport=data.sport, dport=data.dport,
                    payload_len=max(0, charge_len)))
                # Le port suffit a reconnaitre le DNS. Les deux sens comptent :
                # la query part vers 53, la reponse en vient.
                if data.sport in DNS_PORTS or data.dport in DNS_PORTS:
                    st.udp_dns += 1
                    charge = data.data if isinstance(data.data, bytes) \
                        else bytes(data.data)
                    # ulen compte l'en-tete UDP (8 octets). L'ecart avec ce qui
                    # a ete capture EST la troncature du snaplen : c'est la
                    # seule occasion de la mesurer, l'information n'existe plus
                    # une fois le paquet oublie.
                    annonce = (data.ulen - 8) if data.ulen >= 8 else None
                    msg = parse_dns_datagram(
                        float(ts), _ip_str(ip.src), _ip_str(ip.dst),
                        data.sport, data.dport, charge, annonce)
                    if msg is not None:
                        cap.dns_msgs.append(msg)
                    else:
                        st.dns_unreadable += 1
            else:
                st.other_ip += 1

    # Les lecteurs livrent normalement dans l'ordre du fichier = ordre de
    # capture, mais un merge de captures (mergecap) peut desordonner :
    # tout l'etage signaux suppose le temps croissant, on garantit ici.
    cap.tcp_packets.sort(key=lambda p: p.ts)
    cap.icmp_events.sort(key=lambda e: e.ts)
    return cap
