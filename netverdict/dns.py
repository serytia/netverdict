"""Resolutions DNS : le temps que le TCP ne peut pas montrer.

Une resolution lente se produit AVANT le SYN. Elle est donc hors de tout ce
que l'etage TCP sait mesurer : sur une capture ou l'utilisateur a attendu
2,4 s, netverdict 0.7.0 rendait « transport sain », code retour 0. Le verdict
TCP etait juste - c'est le silence qui mentait.

Trois choix de conception, tous imposes par une mesure, pas par une intuition :

1. **L'en-tete DNS est lu a la main.** `dpkt.dns` leve (`NeedData`,
   `UnpackError`) des que le message est coupe, MEME quand les douze octets
   d'en-tete sont intacts. Or les scripts de capture tronquent
   (`tcpdump -s 96` laisse 54 octets de payload, `pktmon --pkt-size 128` en
   laisse 86) : s'appuyer sur dpkt seul perdrait tout le DNS d'une capture de
   production, en silence. Les douze premiers octets portent txid, QR, TC et
   RCODE - donc la latence, les tentatives et les echecs restent mesurables
   meme tronques. Seules les REPONSES (nom -> adresse) demandent le message
   entier ; quand elles manquent, on le dit au lieu de deviner.

2. **Une resolution regroupe les tentatives par (client, nom, type)**, pas
   par identifiant de transaction. Les resolveurs se partagent en deux
   familles : ceux qui reemettent avec le meme txid (glibc) et ceux qui en
   tirent un nouveau a chaque essai. Grouper par txid ne verrait qu'une
   moitie du monde, et compterait les retries de l'autre comme autant de
   resolutions distinctes - donc « trois resolutions rapides » la ou il faut
   lire « une resolution de 2,4 s ».

3. **Un nom DNS vient d'un paquet brut** : n'importe qui sur le chemin le
   fabrique. Il est neutralise (`timeline._clean`) avant d'entrer dans le
   rapport, controles bidi compris.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import asdict, dataclass, field
from typing import Iterable, Optional

import dpkt

from .timeline import _clean

# En-tete DNS (RFC 1035 §4.1.1) : id, flags, qdcount, ancount, nscount, arcount.
_HDR = struct.Struct("!HHHHHH")
_HDR_LEN = 12

# 5353 = mDNS, meme format de message, donc meme parseur. Il est DECODE (pour
# etre compte, nomme et lisible dans le rapport) mais les regles qui ACCUSENT
# s'en abstiennent : une question mDNS multicast sans reponse est le
# fonctionnement normal du protocole - le nom demande n'existe simplement pas
# sur ce segment. Les traiter comme du DNS unicast fabriquerait des « le
# serveur ne repond pas » en serie sur n'importe quelle capture de LAN.
MDNS_PORT = 5353
DNS_PORTS = frozenset({53, MDNS_PORT})

# Au-dela de ce delai depuis la derniere tentative, une nouvelle question pour
# le meme nom n'est plus une reemission : c'est une nouvelle resolution (TTL
# expire, nouvelle requete applicative). Les resolveurs de la vraie vie
# reemettent entre 1 et 5 s (glibc : RES_TIMEOUT = 5 s, deux essais par
# serveur) ; aucun n'attend une demi-minute. Le seuil est donc large sans
# risquer de fusionner deux resolutions reellement distinctes.
NEW_RESOLUTION_GAP_S = 30.0

RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
    5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH",
    10: "NOTZONE", 16: "BADVERS",
}

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 48: "DNSKEY", 64: "SVCB",
    65: "HTTPS", 255: "ANY",
}


def qtype_name(qtype: Optional[int]) -> str:
    if qtype is None:
        return ""
    return QTYPES.get(qtype, f"TYPE{qtype}")


def rcode_name(rcode: Optional[int]) -> str:
    if rcode is None:
        return ""
    return RCODES.get(rcode, f"RCODE{rcode}")


@dataclass
class DnsMsg:
    """Un datagramme DNS observe. Les champs issus des douze premiers octets
    sont toujours fiables ; ceux qui suivent peuvent manquer (troncature)."""

    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    txid: int
    is_response: bool
    opcode: int
    rcode: int
    dns_truncated: bool          # TC=1 : le SERVEUR annonce sa reponse coupee
    qdcount: int
    ancount: int
    qname: Optional[str] = None
    qtype: Optional[int] = None
    answers: list[str] = field(default_factory=list)
    # Distinct de dns_truncated : ici c'est NOTRE capture qui a coupe (snaplen),
    # pas le serveur qui annonce une reponse trop grande pour UDP. Confondre
    # les deux ferait recommander un repli TCP/53 a cause d'un snaplen.
    capture_truncated: bool = False
    answers_readable: bool = False
    # Message lu sur TCP/53 et non en datagramme : c'est le repli obligatoire
    # apres une reponse tronquee, et son ABOUTISSEMENT devient alors visible.
    over_tcp: bool = False


def _read_question(buf: bytes) -> tuple[Optional[str], Optional[int]]:
    """Lit la section question a la main, en s'arretant proprement des que le
    buffer est epuise. Rend (None, None) plutot qu'un nom partiel : un nom
    tronque a « api.corp » designerait un autre hote que « api.corp.local »."""
    pos = _HDR_LEN
    labels: list[str] = []
    complet = False
    while pos < len(buf):
        n = buf[pos]
        if n == 0:
            pos += 1
            complet = True
            break
        if n & 0xC0:
            # Pointeur de compression : interdit dans la question (RFC 1035
            # §4.1.2). Le suivre demanderait le message entier, que la
            # troncature ne garantit pas - on renonce sans inventer.
            return None, None
        pos += 1
        if pos + n > len(buf):
            return None, None
        labels.append(buf[pos:pos + n].decode("ascii", "replace"))
        pos += n
    if not complet:
        return None, None
    nom = _clean(".".join(labels)) if labels else "."
    qtype = None
    if pos + 2 <= len(buf):
        qtype = struct.unpack_from("!H", buf, pos)[0]
    return nom, qtype


def _read_answers(buf: bytes) -> tuple[list[str], bool]:
    """Adresses des enregistrements A/AAAA. Necessite le message ENTIER : les
    enregistrements utilisent la compression de noms, qui pointe en arriere
    dans le message. Rend ([], False) des que dpkt refuse - jamais une liste
    partielle presentee comme complete."""
    try:
        d = dpkt.dns.DNS(buf)
    except Exception:
        return [], False
    out: list[str] = []
    for rr in getattr(d, "an", []) or []:
        try:
            if rr.type == dpkt.dns.DNS_A:
                out.append(socket.inet_ntoa(rr.ip))
            elif rr.type == dpkt.dns.DNS_AAAA:
                out.append(socket.inet_ntop(socket.AF_INET6, rr.ip6))
        except Exception:
            continue
    return out, True


def parse_dns_datagram(ts: float, src: str, dst: str, sport: int, dport: int,
                       payload: bytes,
                       declared_len: Optional[int] = None) -> Optional[DnsMsg]:
    """Un datagramme UDP/53 -> DnsMsg, ou None s'il n'y a meme pas d'en-tete.

    `declared_len` est la longueur du payload annoncee par l'en-tete UDP
    (ulen - 8). Comparee a ce qui a ete capture, elle dit si le snaplen a
    coupe - information qu'on ne peut pas retrouver plus tard."""
    if len(payload) < _HDR_LEN:
        return None
    txid, flags, qd, an, _ns, _ar = _HDR.unpack_from(payload, 0)
    coupe = declared_len is not None and declared_len >= 0 and len(payload) < declared_len
    qname, qtype = _read_question(payload) if qd else (None, None)
    answers, lisible = ([], False) if coupe else _read_answers(payload)
    return DnsMsg(
        ts=ts, src=src, dst=dst, sport=sport, dport=dport,
        txid=txid,
        is_response=bool(flags & 0x8000),
        opcode=(flags >> 11) & 0x0F,
        rcode=flags & 0x000F,
        dns_truncated=bool(flags & 0x0200),
        qdcount=qd, ancount=an,
        qname=qname, qtype=qtype,
        answers=answers, answers_readable=lisible,
        capture_truncated=coupe,
    )


def reassemble_stream(segments: Iterable[tuple[int, bytes]]) -> tuple[bytes, bool]:
    """Recolle les octets d'un sens d'un flux TCP. Rend (octets, complet).

    `segments` : (numero de sequence, octets). Volontairement minimaliste - le
    DNS sur TCP tient presque toujours en un ou deux segments, et un
    reassembleur general serait un projet a lui seul. Les doublons de
    retransmission sont ecartes, et le PREMIER TROU arrete tout : rendre des
    octets non contigus fabriquerait un message qui n'a jamais existe.
    `complet` dit si l'on est alle jusqu'au bout sans trou."""
    par_seq = {}
    for seq, data in segments:
        if data and seq not in par_seq:
            par_seq[seq] = data
    if not par_seq:
        return b"", True
    ordonnes = sorted(par_seq.items())
    attendu = ordonnes[0][0]
    out = bytearray()
    for seq, data in ordonnes:
        if seq < attendu:                 # chevauchement : deja pris
            recouvre = attendu - seq
            if recouvre >= len(data):
                continue
            data = data[recouvre:]
            seq = attendu
        if seq != attendu:
            return bytes(out), False      # trou : on s'arrete et on le dit
        out += data
        attendu = seq + len(data)
    return bytes(out), True


def parse_dns_over_tcp(ts: float, src: str, dst: str, sport: int, dport: int,
                       stream: bytes, complet: bool = True) -> list[DnsMsg]:
    """Messages DNS d'un flux TCP/53 (RFC 1035 §4.2.2 : chaque message est
    precede de sa longueur sur deux octets).

    Un flux peut en porter plusieurs (pipelining, transfert de zone). Le
    dernier message incomplet est ignore plutot que devine."""
    out: list[DnsMsg] = []
    pos = 0
    while pos + 2 <= len(stream):
        (taille,) = struct.unpack_from("!H", stream, pos)
        pos += 2
        corps = stream[pos:pos + taille]
        pos += taille
        if len(corps) < _HDR_LEN:
            break
        msg = parse_dns_datagram(ts, src, dst, sport, dport, corps,
                                 declared_len=taille)
        if msg is not None:
            # Un flux tronque rend des octets manquants indiscernables d'une
            # reponse courte : on marque la troncature plutot que de laisser
            # croire que tout a ete lu.
            if not complet or len(corps) < taille:
                msg.capture_truncated = True
                msg.answers = []
                msg.answers_readable = False
            msg.over_tcp = True
            out.append(msg)
    return out


@dataclass
class DnsResolution:
    """Toutes les tentatives d'un client pour resoudre UN nom, et l'issue."""

    client: str
    qname: str
    qtype: Optional[int]
    attempts: list[DnsMsg] = field(default_factory=list)
    response: Optional[DnsMsg] = None
    resolvers: list[str] = field(default_factory=list)
    # Vrai quand la capture se termine sans qu'aucune reponse ne soit arrivee :
    # la duree observee est alors une BORNE INFERIEURE, pas une mesure.
    capture_ends_first: bool = False
    # TENTE et ABOUTI sont deux choses differentes, et les confondre annulait
    # la regle : au lab (15/08), dig a bien rejoue sa question en TCP/53 apres
    # un TC=1, mais le pare-feu simule a jete les SYN. Le repli etait donc
    # visible ET mort. Compter « tente » comme « resolu » faisait taire le
    # verdict exactement dans le cas qu'il existe pour attraper.
    tcp_retry_seen: bool = False
    tcp_retry_ok: bool = False

    @property
    def t_first(self) -> float:
        return self.attempts[0].ts if self.attempts else 0.0

    @property
    def t_last_attempt(self) -> float:
        return self.attempts[-1].ts if self.attempts else 0.0


def _cle(msg: DnsMsg) -> Optional[tuple]:
    """Identifie la resolution a laquelle un message appartient. Le client est
    l'emetteur de la question ; sur une reponse, c'est le destinataire."""
    if msg.qname is None:
        return None
    client = msg.dst if msg.is_response else msg.src
    return (client, msg.qname.lower(), msg.qtype)


def build_resolutions(msgs: Iterable[DnsMsg], capture_end: Optional[float] = None,
                      tcp53: Optional[Iterable[tuple]] = None,
                      ) -> list[DnsResolution]:
    """Regroupe les messages en resolutions, dans l'ordre du temps.

    `tcp53` : les flux TCP vers le port 53 observes, sous la forme
    (ts_debut, client, serveur, etabli). Ils servent a repondre a UNE
    question, mais elle est decisive : quand un serveur repond TC=1 (« ma
    reponse ne tient pas dans un datagramme »), le client DOIT rejouer la
    question en TCP. Si ce repli echoue, la resolution est morte la - et la
    cause est presque toujours un pare-feu qui autorise UDP/53 en oubliant
    TCP/53.

    Le quatrieme element dit si la connexion s'est ETABLIE. Sans lui, des SYN
    restes sans reponse passaient pour un repli reussi.
    """
    ordered = sorted(msgs, key=lambda m: m.ts)
    resolutions: list[DnsResolution] = []
    ouvertes: dict[tuple, DnsResolution] = {}

    for m in ordered:
        k = _cle(m)
        if k is None:
            # Question illisible (tronquee des le nom) : on ne peut la
            # rattacher a rien sans risquer de melanger deux resolutions.
            continue
        res = ouvertes.get(k)
        if res is not None and (res.response is not None
                                or m.ts - res.t_last_attempt > NEW_RESOLUTION_GAP_S):
            res = None
        if m.is_response:
            if res is None:
                # Reponse sans question observee (capture demarree trop tard) :
                # elle ne prouve aucune latence, on ne fabrique pas de
                # resolution autour d'elle.
                continue
            res.response = m
            if m.src not in res.resolvers:
                res.resolvers.append(m.src)
            continue
        if res is None:
            res = DnsResolution(client=k[0], qname=m.qname or "", qtype=m.qtype)
            ouvertes[k] = res
            resolutions.append(res)
        res.attempts.append(m)
        if m.dst not in res.resolvers:
            res.resolvers.append(m.dst)

    tcp53 = list(tcp53 or [])
    for res in resolutions:
        if res.response is None:
            res.capture_ends_first = capture_end is not None
        if res.response is not None and res.response.dns_truncated:
            # Le repli doit suivre la reponse tronquee, pas la preceder.
            candidats = [t for t in tcp53
                         if t[0] >= res.response.ts - 1.0 and t[1] == res.client
                         and t[2] in res.resolvers]
            res.tcp_retry_seen = bool(candidats)
            # Une connexion TCP etablie prouve que le repli a pu commencer ;
            # une REPONSE DNS lue sur ce TCP prouve qu'il a abouti. La seconde
            # preuve est meilleure et prime quand elle existe : une session
            # etablie peut tres bien se faire couper avant la reponse.
            reponse_tcp = any(
                autre.response is not None and autre.response.over_tcp
                and autre.qname.lower() == res.qname.lower()
                and autre.response.ts >= res.response.ts
                for autre in resolutions if autre is not res)
            res.tcp_retry_ok = reponse_tcp or any(
                len(t) > 3 and t[3] for t in candidats)
    return resolutions


@dataclass
class DnsSignals:
    """Contrat entre l'etage DNS et les regles. Meme discipline que
    FlowSignals : ces noms sont des IDENTIFIANTS, ils apparaissent dans les
    fichiers `--rules` des utilisateurs."""

    qname: str = ""
    qtype: str = ""
    client: str = ""
    resolver: str = ""
    resolvers_tried: int = 0
    attempts: int = 0
    answered: bool = False
    latency_ms: Optional[float] = None
    t_first: float = 0.0
    # Duree observee : jusqu'a la reponse, ou jusqu'a la fin de la capture.
    observed_ms: float = 0.0
    # Vrai quand la capture s'arrete avant toute reponse : observed_ms est
    # alors un minimum, et aucune regle ne doit le presenter autrement.
    capture_ends_first: bool = False
    rcode: Optional[int] = None
    rcode_name: str = ""
    dns_truncated: bool = False
    tcp_retry_seen: bool = False
    tcp_retry_ok: bool = False
    capture_truncated: bool = False
    # mDNS : meme format, mais une question multicast sans reponse y est
    # normale. Les regles qui accusent s'en servent pour s'abstenir.
    is_mdns: bool = False
    answers_readable: bool = False
    answers_count: int = 0
    answers_str: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def compute_dns_signals(res: DnsResolution,
                        capture_end: Optional[float] = None) -> DnsSignals:
    rep = res.response
    latence = None
    if rep is not None and res.attempts:
        # Mesuree depuis la PREMIERE tentative : c'est le temps que
        # l'application a reellement attendu. Le mesurer depuis la derniere
        # reemission afficherait 40 ms la ou l'utilisateur en a subi 2400.
        latence = (rep.ts - res.t_first) * 1000.0
    if rep is not None:
        observe = latence or 0.0
    elif capture_end is not None:
        observe = max(0.0, (capture_end - res.t_first) * 1000.0)
    else:
        observe = max(0.0, (res.t_last_attempt - res.t_first) * 1000.0)
    tronque = any(m.capture_truncated for m in res.attempts) or (
        rep is not None and rep.capture_truncated)
    return DnsSignals(
        qname=res.qname,
        qtype=qtype_name(res.qtype),
        client=res.client,
        resolver=res.resolvers[0] if res.resolvers else "",
        resolvers_tried=len(res.resolvers),
        attempts=len(res.attempts),
        answered=rep is not None,
        latency_ms=latence,
        t_first=res.t_first,
        observed_ms=observe,
        capture_ends_first=res.capture_ends_first,
        rcode=rep.rcode if rep is not None else None,
        rcode_name=rcode_name(rep.rcode) if rep is not None else "",
        dns_truncated=bool(rep is not None and rep.dns_truncated),
        tcp_retry_seen=res.tcp_retry_seen,
        tcp_retry_ok=res.tcp_retry_ok,
        capture_truncated=tronque,
        is_mdns=any(m.sport == MDNS_PORT or m.dport == MDNS_PORT
                    for m in res.attempts) or bool(
            rep is not None and (rep.sport == MDNS_PORT
                                 or rep.dport == MDNS_PORT)),
        answers_readable=bool(rep is not None and rep.answers_readable),
        answers_count=len(rep.answers) if rep is not None else 0,
        answers_str=", ".join(rep.answers) if rep is not None else "",
    )


@dataclass
class FlowDnsLink:
    """Ce qu'une resolution apprend a propos d'un flux TCP."""

    qname: str
    answered_at: float
    latency_ms: Optional[float]
    lag_s: float
    # Vrai quand la resolution precede IMMEDIATEMENT la connexion : son delai
    # fait alors partie du temps que l'utilisateur a subi. Faux quand le nom
    # ne sert qu'a nommer l'hote (resolution plus ancienne, cache) - auquel
    # cas afficher « precede de 240 s » suggererait un lien de cause qui
    # n'existe pas.
    explains_delay: bool


# Delai maximal entre la reponse DNS et le premier paquet du flux pour que le
# temps de resolution compte dans le temps percu. Un connect() suit
# getaddrinfo() de quelques millisecondes ; deux secondes laissent la place a
# du travail applicatif entre les deux sans jamais rattacher une resolution
# qui n'a servi qu'a remplir un cache.
DELAY_ATTRIBUTION_WINDOW_S = 2.0

# Au-dela, on ne nomme meme plus : un enregistrement A expire (TTL usuel de
# 300 s) a pu changer d'adresse, et coller l'ancien nom a une IP recyclee
# serait une affirmation fausse presentee comme une aide a la lecture.
NAMING_WINDOW_S = 300.0


def link_flows(resolutions: Iterable[DnsResolution],
               flows: Iterable[tuple[int, str, float]],
               ) -> dict[int, FlowDnsLink]:
    """Rattache chaque flux TCP au nom qui l'a produit.

    `flows` : (index du flux, adresse du serveur, horodatage du 1er paquet).
    Volontairement des primitifs et non des FlowSignals : ce module est lu par
    pcap.py, et l'importer creerait un cycle."""
    par_adresse = resolved_addresses(resolutions)
    detail = {(r.response.ts, r.qname): r for r in resolutions
              if r.response is not None}
    out: dict[int, FlowDnsLink] = {}
    for index, serveur, t_first in flows:
        candidats = [(ts, nom) for ts, nom in par_adresse.get(serveur, [])
                     if ts <= t_first and t_first - ts <= NAMING_WINDOW_S]
        if not candidats:
            continue
        # La plus RECENTE anterieure au flux : si le nom a ete resolu deux
        # fois, c'est la derniere reponse qui a fourni l'adresse utilisee.
        ts, nom = max(candidats, key=lambda c: c[0])
        res = detail.get((ts, nom))
        lat = None
        if res is not None and res.attempts:
            lat = (res.response.ts - res.t_first) * 1000.0
        lag = t_first - ts
        out[index] = FlowDnsLink(
            qname=nom, answered_at=ts, latency_ms=lat, lag_s=lag,
            explains_delay=lag <= DELAY_ATTRIBUTION_WINDOW_S)
    return out


def resolved_addresses(resolutions: Iterable[DnsResolution]) -> dict[str, list[tuple[float, str]]]:
    """adresse -> [(ts de la reponse, nom)], pour nommer les flux TCP.

    Une adresse peut porter plusieurs noms (hebergement mutualise, VIP) et un
    nom changer d'adresse pendant la capture : on garde TOUT, horodate, et
    c'est l'appelant qui choisit l'entree anterieure au flux."""
    out: dict[str, list[tuple[float, str]]] = {}
    for res in resolutions:
        rep = res.response
        if rep is None or not rep.answers_readable:
            continue
        for adresse in rep.answers:
            out.setdefault(adresse, []).append((rep.ts, res.qname))
    return out
