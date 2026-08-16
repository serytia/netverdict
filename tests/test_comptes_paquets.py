"""La comptabilite de lecture doit BOUCLER, et ce qui n'est pas analyse
doit se dire.

Defaut d'origine (mesure du 15/08, netverdict 0.7.0) : le dispatch de
read_capture etait `if TCP / elif ICMP / elif ICMP6`, sans branche finale. Un
paquet UDP incrementait `total` et aucun sous-compteur. Sur une capture
contenant une resolution DNS de 2,4 s suivie d'un flux TCP irreprochable, le
rapport affichait :

    13 packets read - 10 TCP, 0 ICMP, 0 non-IP, 0 unreadable
    [CLEAN] 1 conversation(s) with healthy transport

Trois paquets disparus du compte, et un "tout va bien" rendu a un utilisateur
qui venait d'attendre deux secondes et demie. La ligne de comptes existe
precisement pour empecher ca ("un verdict rendu sur une capture illisible a
40 % ne vaut rien") : elle doit donc etre verifiable, pas decorative.
"""

from __future__ import annotations

import json
import socket

import dpkt
import pytest
from dpkt.tcp import TH_ACK, TH_SYN

from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.report import render_console, to_json
from netverdict.rules.engine import evaluate
from netverdict.signals import compute_signals

CLIENT = "10.0.0.42"
SERVER = "10.0.0.5"
RESOLVER = "10.0.0.53"


def _eth(ip) -> bytes:
    e = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                               type=dpkt.ethernet.ETH_TYPE_IP)
    e.data = ip
    return bytes(e)


def _ip(src, dst, proto, payload, offset=0, ip_id=1):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=proto, ttl=64, id=ip_id)
    ip.data = payload
    ip.len = 20 + len(bytes(payload))
    if offset:
        ip.offset = offset       # `ip.off` existe encore mais est deprecie
    return ip


def _udp(src, dst, sport, dport, payload=b"\x00" * 20):
    u = dpkt.udp.UDP(sport=sport, dport=dport)
    u.data = payload
    u.ulen = 8 + len(payload)
    return _eth(_ip(src, dst, dpkt.ip.IP_PROTO_UDP, u))


def _tcp(src, dst, sport, dport, flags, seq, ack):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq,
                       ack=ack, win=65535)
    seg.data = b""
    return _eth(_ip(src, dst, dpkt.ip.IP_PROTO_TCP, seg))


def _icmp_unreach():
    orig = dpkt.ip.IP(src=socket.inet_aton(CLIENT), dst=socket.inet_aton(SERVER),
                      p=dpkt.ip.IP_PROTO_TCP, ttl=63, id=9)
    orig.data = dpkt.tcp.TCP(sport=1234, dport=443, flags=TH_SYN, seq=1, win=1)
    orig.len = 40
    icmp = dpkt.icmp.ICMP(type=3, code=13)
    icmp.data = dpkt.icmp.ICMP.Unreach(data=orig)
    return _eth(_ip("10.0.0.1", CLIENT, dpkt.ip.IP_PROTO_ICMP, icmp))


def _gre():
    """Un protocole IP que l'outil ne traite pas : ni TCP, ni UDP, ni ICMP."""
    return _eth(_ip(CLIENT, SERVER, 47, b"\x00\x00\x08\x00" + b"\x11" * 16))


def _arp():
    e = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\xff" * 6,
                               type=dpkt.ethernet.ETH_TYPE_ARP)
    e.data = dpkt.arp.ARP(sha=b"\x02" * 6, spa=socket.inet_aton(CLIENT),
                          tha=b"\x00" * 6, tpa=socket.inet_aton(SERVER))
    return bytes(e)


def _fragment_non_premier():
    """Fragment IPv4 d'offset non nul : pas d'en-tete transport dedans."""
    return _eth(_ip(CLIENT, SERVER, dpkt.ip.IP_PROTO_TCP, b"\x41" * 24,
                    offset=185, ip_id=77))


@pytest.fixture(scope="module")
def capture_melangee(tmp_path_factory):
    """Un exemplaire de chaque famille que le lecteur peut rencontrer."""
    trames = [
        (0.0, _tcp(CLIENT, SERVER, 5000, 443, TH_SYN, 1, 0)),
        (0.1, _tcp(SERVER, CLIENT, 443, 5000, TH_SYN | TH_ACK, 100, 2)),
        (0.2, _tcp(CLIENT, SERVER, 5000, 443, TH_ACK, 2, 101)),
        (0.3, _udp(CLIENT, RESOLVER, 54321, 53)),          # DNS query
        (0.4, _udp(RESOLVER, CLIENT, 53, 54321)),          # DNS reponse
        (0.5, _udp(CLIENT, "10.0.0.9", 40000, 123)),       # NTP : UDP non-DNS
        (0.6, _icmp_unreach()),
        (0.7, _gre()),
        (0.8, _arp()),
        (0.9, _fragment_non_premier()),
    ]
    path = tmp_path_factory.mktemp("comptes") / "melange.pcap"
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in trames:
            w.writepkt(buf, ts=ts)
    return path


def test_le_compte_de_paquets_boucle(capture_melangee):
    """L'invariant qui protege durablement : chaque paquet lu tombe dans
    exactement une colonne. Ajouter une branche de dispatch sans compteur
    fait tomber ce test - c'est tout son interet."""
    st = read_capture(capture_melangee).stats
    somme = (st.tcp + st.udp + st.icmp + st.other_ip + st.non_ip
             + st.fragments_skipped + st.parse_errors)
    assert st.total == somme, (
        f"{st.total} paquets lus mais {somme} classes : "
        f"{st.total - somme} disparus en silence"
    )


def test_chaque_famille_est_comptee_dans_sa_colonne(capture_melangee):
    st = read_capture(capture_melangee).stats
    assert st.total == 10
    assert st.tcp == 3
    assert st.udp == 3           # 2 DNS + 1 NTP
    assert st.udp_dns == 2       # les deux sens du port 53
    assert st.icmp == 1
    assert st.other_ip == 1      # GRE
    assert st.non_ip == 1        # ARP
    assert st.fragments_skipped == 1
    assert st.parse_errors == 0


def test_le_dns_non_analyse_est_annonce_dans_le_rapport(capture_melangee, rules):
    """Compter en silence ne vaudrait pas mieux que ne pas compter : le
    rapport doit dire que ces paquets sortent du champ des verdicts."""
    cap = read_capture(capture_melangee)
    verdicts = evaluate([compute_signals(f) for f in build_flows(cap)], rules)
    from rich.console import Console
    con = Console(file=__import__("io").StringIO(), width=200, no_color=True)
    render_console(cap, verdicts, console=con, lang="en")
    sortie = con.file.getvalue()
    assert "3 UDP" in sortie, "la ligne de comptes tait l'UDP"
    assert "DNS" in sortie and "NOT analyzed" in sortie, (
        "le rapport ne previent pas que le DNS sort du champ des verdicts"
    )


def test_le_json_expose_les_nouveaux_comptes(capture_melangee, rules):
    cap = read_capture(capture_melangee)
    verdicts = evaluate([compute_signals(f) for f in build_flows(cap)], rules)
    stats = json.loads(to_json(cap, verdicts))["stats"]
    assert stats["udp"] == 3
    assert stats["udp_dns"] == 2
    assert stats["other_ip"] == 1
    assert stats["fragments_skipped"] == 1
    assert stats["packets"] == (stats["tcp"] + stats["udp"] + stats["icmp"]
                                + stats["other_ip"] + stats["non_ip"]
                                + stats["fragments_skipped"]
                                + stats["parse_errors"])


def test_les_erreurs_icmp_autres_que_type_3_sont_rattachables(tmp_path):
    """Seuls les type 3 (v4) et type 1 (v6) etaient decodes : un TTL exceeded
    etait compte dans l'en-tete puis oublie, si bien qu'une regle affirmait
    « aucune erreur ICMP » deux lignes plus bas (revue du 16/08/2026)."""
    from netverdict.pcap import read_capture

    orig = dpkt.udp.UDP(sport=40000, dport=123)
    orig.data = b"\x1b" + b"\x00" * 47
    orig.ulen = 56
    oip = _ip(CLIENT, SERVER, dpkt.ip.IP_PROTO_UDP, orig, ip_id=9)
    ic = dpkt.icmp.ICMP(type=11, code=0)               # TTL exceeded
    ic.data = dpkt.icmp.ICMP.TimeExceed(data=oip)
    trames = [(0.0, _udp(CLIENT, SERVER, 40000, 123)),
              (0.5, _eth(_ip("10.0.0.1", CLIENT, dpkt.ip.IP_PROTO_ICMP, ic, ip_id=10)))]
    chemin = tmp_path / "ttl.pcap"
    with open(chemin, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in trames:
            w.writepkt(buf, ts=ts)
    cap = read_capture(chemin)
    assert cap.stats.icmp == 1
    assert len(cap.icmp_events) == 1, "le TTL exceeded n'est pas rattachable"
    assert cap.icmp_events[0].label == "ICMP type 11 code 0"
    assert cap.icmp_events[0].is_unreachable is False
