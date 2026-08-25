"""Les six defauts du backlog 0.8.1, chacun reproduit ici AVANT d'etre corrige.

Origine : revues croisees pre-tag 0.8.0 (Codex + Claude, 16/08/2026). La 0.8.0
a ete publiee en connaissance de ces defauts ; ce fichier les transforme en
contrats. Chaque test decrit le SYMPTOME observable, pas l'implementation :

1. Deux requetes DNS concurrentes (deux sockets, deux txid, quelques
   millisecondes d'ecart) etaient fusionnees en une « reemission » — fausse
   preuve, et la reponse de l'une servait de latence a l'autre.
2. Un horodatage aberrant (paquet isole date des annees plus loin) etirait
   la fin de capture : le rapport AVERTISSAIT, mais l'etage DNS calculait
   quand meme « aucune reponse en 31536000000 ms » contre la valeur folle.
3. Un ICMP recu au MILIEU d'une longue conversation UDP etait rattache a la
   conversation suivante du meme quadruplet (distance mesuree au premier
   paquet, pas a l'intervalle) — l'erreur changeait le verdict de la
   mauvaise minute, voire d'une session future.
4. ICMPv4 type 12 (parameter problem) : dpkt n'a pas de classe pour lui,
   son paquet fautif restait en octets bruts et l'evenement n'etait jamais
   rattache — compte dans l'en-tete, absent de tous les verdicts.
5. La couverture DNS -> UDP ne portait que le port source de la PREMIERE
   tentative : une reemission depuis un second socket laissait l'etage UDP
   sortir un panneau AMBIGU redondant sur la meme resolution.
6. --explain recevait un rapport SANS le compte d'orphelins : la synthese
   narrative expliquait une capture differente de celle affichee.
"""

from __future__ import annotations

import json
import socket

import dpkt
import pytest

from netverdict.dns import build_resolutions, compute_dns_signals, parse_dns_datagram
from netverdict.pcap import read_capture
from netverdict.udp import build_udp_conversations, compute_udp_signals

CLIENT = "10.0.0.42"
RESOLVER = "10.0.0.53"
SERVEUR = "10.0.0.9"


# ------------------------------------------------------------ helpers DNS

def dns_bytes(txid, qname="api.corp.local", response=False, answers=()):
    d = dpkt.dns.DNS(id=txid, rd=1)
    if response:
        d.qr = dpkt.dns.DNS_R
        d.ra = 1
    d.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    d.an = [dpkt.dns.DNS.RR(name=qname, type=dpkt.dns.DNS_A,
                            cls=dpkt.dns.DNS_IN, ttl=300,
                            ip=socket.inet_aton(a)) for a in answers]
    return bytes(d)


def q(ts, sport, txid, qname="api.corp.local"):
    raw = dns_bytes(txid, qname)
    return parse_dns_datagram(ts, CLIENT, RESOLVER, sport, 53, raw, len(raw))


def r(ts, dport, txid, qname="api.corp.local", answers=("192.0.2.7",)):
    raw = dns_bytes(txid, qname, response=True, answers=answers)
    return parse_dns_datagram(ts, RESOLVER, CLIENT, 53, dport, raw, len(raw))


# ----------------------------------------------------------- helpers pcap

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


def udp_trame(ts, src, dst, sport, dport, payload=b"\x01" * 20, ident=1):
    u = dpkt.udp.UDP(sport=sport, dport=dport)
    u.data = payload
    u.ulen = 8 + len(payload)
    return (ts, _eth(_ip(src, dst, dpkt.ip.IP_PROTO_UDP, u, ident)))


def capture(tmp_path, trames, nom="t.pcap"):
    chemin = tmp_path / nom
    with open(chemin, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in trames:
            w.writepkt(buf, ts=ts)
    return chemin


# ------------------------------------------- 1. requetes DNS concurrentes

def test_deux_requetes_concurrentes_ne_sont_pas_une_reemission():
    """Deux process du meme hote demandent le meme nom a 30 ms d'ecart,
    chacun depuis son socket avec son txid. Aucun resolveur ne reemet aussi
    vite (glibc attend 5 s, musl 2,5 s, systemd-resolved ~0,8 s) : ce sont
    DEUX resolutions, et chaque reponse appartient a la sienne."""
    msgs = [
        q(1.00, 40001, 0x1111),
        q(1.03, 40002, 0x2222),
        r(1.06, 40002, 0x2222),   # reponse rapide au SECOND
        r(1.50, 40001, 0x1111),   # reponse lente au PREMIER
    ]
    res = build_resolutions(msgs)
    assert len(res) == 2
    par_txid = {x.attempts[0].txid: x for x in res}
    assert all(len(x.attempts) == 1 for x in res)   # pas de fausse reemission
    s1 = compute_dns_signals(par_txid[0x1111])
    s2 = compute_dns_signals(par_txid[0x2222])
    assert s1.answered and s2.answered
    assert s1.latency_ms == pytest.approx(500, abs=20)
    assert s2.latency_ms == pytest.approx(30, abs=20)


def test_chaque_reponse_rejoint_sa_question_par_txid_et_port():
    """Reponses arrivees dans l'ORDRE des questions : un simple repli « la
    resolution la plus recente » attribuerait la premiere reponse a la
    SECONDE question (ouverte en dernier). L'appariement par txid + port du
    socket est le seul qui ne se trompe jamais - et ces deux champs
    survivent a toutes les troncatures."""
    msgs = [
        q(1.00, 40001, 0xAAAA),
        q(1.03, 40002, 0xBBBB),
        r(1.20, 40001, 0xAAAA),   # reponse au PREMIER, arrivee en premier
        r(1.40, 40002, 0xBBBB),
    ]
    res = build_resolutions(msgs)
    assert len(res) == 2
    par_txid = {x.attempts[0].txid: x for x in res}
    s1 = compute_dns_signals(par_txid[0xAAAA])
    s2 = compute_dns_signals(par_txid[0xBBBB])
    assert s1.answered and s2.answered
    assert s1.latency_ms == pytest.approx(200, abs=20)
    assert s2.latency_ms == pytest.approx(370, abs=20)


def test_une_reponse_dupliquee_ne_contamine_pas_une_resolution_concurrente():
    """Port-miroir ou dup de capture : la meme reponse arrive deux fois. La
    premiere ferme sa resolution ; la seconde ne doit PAS etre offerte a la
    resolution concurrente encore ouverte du meme nom - elle est orpheline,
    comme toute reponse dont la question n'est plus a servir."""
    msgs = [
        q(1.00, 40001, 0xAAAA),
        q(1.03, 40002, 0xBBBB),
        r(1.20, 40001, 0xAAAA),
        r(1.21, 40001, 0xAAAA),   # le doublon
        r(1.40, 40002, 0xBBBB),
    ]
    orphelines = []
    res = build_resolutions(msgs, orphelines=orphelines)
    assert len(res) == 2
    par_txid = {x.attempts[0].txid: x for x in res}
    assert compute_dns_signals(par_txid[0xBBBB]).latency_ms == pytest.approx(370, abs=20)
    assert len(orphelines) == 1        # le doublon, et rien d'autre


def test_une_reemission_meme_socket_reste_une_seule_resolution():
    """Le comportement glibc (meme txid, meme socket, 5 s d'ecart) reste une
    reemission — c'etait juste avant, ca doit le rester apres."""
    res = build_resolutions([q(1.0, 40001, 0x1111), q(6.0, 40001, 0x1111)])
    assert len(res) == 1
    assert len(res[0].attempts) == 2


def test_une_reemission_nouveau_socket_apres_timeout_reste_une_resolution():
    """L'autre famille de resolveurs : nouveau socket ET nouveau txid a
    chaque essai, mais APRES un timeout (ici 1,2 s). C'est une reemission,
    pas une resolution concurrente."""
    res = build_resolutions([q(1.0, 40001, 0x1111), q(2.2, 40002, 0x2222)])
    assert len(res) == 1
    assert len(res[0].attempts) == 2


# --------------------------------------------- 2. horodatage aberrant

def test_un_horodatage_aberrant_ne_fausse_plus_les_durees_dns(tmp_path):
    """Une question sans reponse a t=1, la capture vit jusqu'a t=5, et un
    paquet isole date 30 ans plus loin (capture concatenee, horloge folle).
    Le rapport avertissait deja ; l'etage DNS, lui, calculait quand meme
    « sans reponse apres un milliard de ms » contre le paquet fou."""
    chemin = capture(tmp_path, [
        udp_trame(1.0, CLIENT, RESOLVER, 40001, 53, dns_bytes(0x1111)),
        udp_trame(5.0, CLIENT, SERVEUR, 40000, 514),          # vie normale
        udp_trame(1.0e9, CLIENT, SERVEUR, 40000, 514),        # l'aberrant
    ])
    cap = read_capture(chemin)
    assert cap.t_fin_fiable == pytest.approx(5.0)             # borne saine
    res = build_resolutions(list(cap.dns_msgs), cap.t_fin_fiable)
    sig = compute_dns_signals(res[0], cap.t_fin_fiable)
    assert sig.observed_ms < 10_000                           # pas des annees


def test_sans_aberrant_la_fin_fiable_est_la_vraie_fin(tmp_path):
    chemin = capture(tmp_path, [
        udp_trame(1.0, CLIENT, SERVEUR, 40000, 514),
        udp_trame(5.0, CLIENT, SERVEUR, 40000, 514),
    ])
    assert read_capture(chemin).t_fin_fiable == pytest.approx(5.0)


def test_le_cli_borne_les_durees_dns_a_la_fin_fiable(tmp_path, capsys):
    """Le meme defaut par le chemin complet : analyze --json ne doit plus
    publier une duree d'attente calculee contre l'horodatage fou."""
    from netverdict.cli import main
    chemin = capture(tmp_path, [
        udp_trame(1.0, CLIENT, RESOLVER, 40001, 53, dns_bytes(0x1111)),
        udp_trame(5.0, CLIENT, SERVEUR, 40000, 514),
        udp_trame(1.0e9, CLIENT, SERVEUR, 40000, 514),
    ])
    main(["analyze", str(chemin), "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["dns"], "l'etage DNS doit voir la question"
    assert data["dns"][0]["signals"]["observed_ms"] < 10_000


# ------------------------------- 3. ICMP au milieu d'une longue conversation

def icmp_unreachable(ts, sport, dport, ident=99):
    """Port-unreachable emis par le serveur, embarquant le datagramme fautif
    CLIENT -> SERVEUR (le cas nominal du rattachement)."""
    orig_u = dpkt.udp.UDP(sport=sport, dport=dport)
    orig_u.data = b"\x01" * 20
    orig_u.ulen = 28
    orig_ip = _ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_UDP, orig_u, ident)
    ic = dpkt.icmp.ICMP(type=3, code=3)
    ic.data = dpkt.icmp.ICMP.Unreach(data=orig_ip)
    return (ts, _eth(_ip(SERVEUR, CLIENT, dpkt.ip.IP_PROTO_ICMP, ic, ident + 1)))


def test_l_icmp_du_milieu_d_une_conversation_ne_saute_pas_sur_le_quadruplet_recycle(tmp_path):
    """Conversation RADIUS de presque cinq minutes, erreur ICMP a t=289 —
    en plein dedans — puis le quadruplet est recycle a t=460. La distance
    au PREMIER paquet designait la session future (171 s) plutot que celle
    en cours (289 s depuis son debut) : l'erreur changeait le verdict de la
    mauvaise session."""
    trames = [udp_trame(t, CLIENT, SERVEUR, 40000, 1812, ident=i + 1)
              for i, t in enumerate([0.0, 60.0, 120.0, 180.0, 240.0, 290.0])]
    trames.append(icmp_unreachable(289.0, 40000, 1812))
    trames.append(udp_trame(460.0, CLIENT, SERVEUR, 40000, 1812, ident=50))
    cap = read_capture(capture(tmp_path, trames))
    convs = build_udp_conversations(cap)
    assert len(convs) == 2
    premiere = min(convs, key=lambda c: c.pkts[0][0])
    seconde = max(convs, key=lambda c: c.pkts[0][0])
    assert len(premiere.icmp) == 1, "l'erreur est DANS la premiere conversation"
    assert not seconde.icmp, "la session future n'a rien recu"


# ----------------------------------------------- 4. ICMPv4 type 12

def test_icmp_type_12_est_rattache_comme_les_autres_erreurs(tmp_path):
    """dpkt n'a pas de classe pour le type 12 (parameter problem) : son
    payload reste en octets bruts (4 octets pointer/unused + paquet fautif).
    L'evenement etait compte dans l'en-tete puis oublie — « 1 ICMP » en
    haut, « aucune erreur ICMP » deux lignes plus bas."""
    orig_u = dpkt.udp.UDP(sport=40000, dport=1812)
    orig_u.data = b"\x01" * 20
    orig_u.ulen = 28
    orig_ip = _ip(CLIENT, SERVEUR, dpkt.ip.IP_PROTO_UDP, orig_u, 7)
    ic = dpkt.icmp.ICMP(type=12, code=0)
    ic.data = b"\x00\x00\x00\x00" + bytes(orig_ip)     # pointer + unused + IP
    trames = [udp_trame(1.0, CLIENT, SERVEUR, 40000, 1812),
              (1.5, _eth(_ip(SERVEUR, CLIENT, dpkt.ip.IP_PROTO_ICMP, ic, 8)))]
    cap = read_capture(capture(tmp_path, trames))
    assert len(cap.icmp_events) == 1
    ev = cap.icmp_events[0]
    assert ev.type == 12
    assert (ev.orig_src, ev.orig_sport) == (CLIENT, 40000)
    assert (ev.orig_dst, ev.orig_dport) == (SERVEUR, 1812)
    convs = build_udp_conversations(cap)
    assert convs and convs[0].icmp, "l'evenement doit rejoindre sa conversation"
    sig = compute_udp_signals(convs[0])
    assert sig.icmp_other and "12" in sig.icmp_other_label


# ------------------------------- 5. couverture DNS et second socket

def test_la_couverture_dns_suit_tous_les_sockets_d_une_resolution(tmp_path, capsys):
    """Reemission depuis un second socket (1,2 s apres la premiere question,
    aucune reponse) : l'etage DNS porte deja le verdict. La conversation UDP
    du SECOND socket doit etre couverte comme celle du premier — sinon un
    panneau AMBIGU redondant sort sur la meme panne."""
    from netverdict.cli import main
    chemin = capture(tmp_path, [
        udp_trame(1.0, CLIENT, RESOLVER, 40001, 53, dns_bytes(0x1111)),
        udp_trame(2.2, CLIENT, RESOLVER, 40002, 53, dns_bytes(0x2222)),
    ])
    main(["analyze", str(chemin), "--json"])
    data = json.loads(capsys.readouterr().out)
    convs = {c["conversation"]: c for c in data.get("udp", [])}
    assert len(convs) == 2
    for cle, c in convs.items():
        assert c["signals"]["dns_handled"] is True, f"{cle} doit etre couverte"


# -------------------------------------------------- 6. --explain

def test_explain_recoit_le_meme_rapport_orphelins_compris(tmp_path, monkeypatch):
    """La synthese narrative doit relire LE rapport rendu a l'utilisateur.
    L'appel --explain omettait le compte d'orphelins : le narratif recevait
    « dns_orphelins: 0 » pendant que la console avertissait du contraire."""
    import netverdict.explain as explain_mod
    from netverdict.cli import main
    recu = {}

    def faux_explain(report_json, lang="en"):
        recu["json"] = report_json
        return "ok"

    monkeypatch.setattr(explain_mod, "explain", faux_explain)
    # Une reponse DNS sans question observee = une orpheline.
    chemin = capture(tmp_path, [
        udp_trame(1.0, RESOLVER, CLIENT, 53, 40001,
                  dns_bytes(0x1111, response=True, answers=("192.0.2.7",))),
    ])
    main(["analyze", str(chemin), "--explain"])
    assert "json" in recu, "explain doit avoir ete appele"
    assert json.loads(recu["json"])["stats"]["dns_orphelins"] == 1
