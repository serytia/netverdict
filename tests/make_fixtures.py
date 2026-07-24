"""Fabrique les pcaps synthetiques de test avec dpkt.

Chaque fonction construit UN scenario de panne canonique et retourne la liste
(ts, trame ethernet). Ces fixtures valident la MECANIQUE du moteur ;
la limite est connue : le meme dpkt ecrit et lit (auto-validation partielle).
La contre-preuve independante viendra des pcaps generes par un vrai kernel
dans la VM lab (lab/scenarios/) — generes par tcpdump, pas par nous.
"""

from __future__ import annotations

import itertools
import socket
from pathlib import Path

import dpkt
from dpkt.tcp import TH_ACK, TH_FIN, TH_PUSH, TH_RST, TH_SYN

CLIENT = "10.0.0.42"
SERVER = "10.0.0.5"
ROUTER = "10.0.0.1"

_ip_id = itertools.count(1)


def _tcp(ts, src, dst, sport, dport, flags, seq=0, ack=0, win=65535, payload=b"",
         ip_id=None):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags,
                       seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF, win=win)
    seg.data = payload
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, ttl=64,
                    id=(ip_id if ip_id is not None else next(_ip_id)) & 0xFFFF)
    ip.data = seg
    ip.len = 20 + 20 + len(payload)
    eth = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return (ts, bytes(eth))


def _icmp_unreach(ts, icmp_src, code, orig_src, orig_dst, orig_sport, orig_dport):
    """ICMP type 3 emis par un equipement, embarquant le paquet fautif."""
    orig_tcp = dpkt.tcp.TCP(sport=orig_sport, dport=orig_dport,
                            flags=TH_SYN, seq=1, ack=0, win=65535)
    orig_ip = dpkt.ip.IP(src=socket.inet_aton(orig_src),
                         dst=socket.inet_aton(orig_dst),
                         p=dpkt.ip.IP_PROTO_TCP, ttl=63, id=next(_ip_id) & 0xFFFF)
    orig_ip.data = orig_tcp
    orig_ip.len = 40
    icmp = dpkt.icmp.ICMP(type=3, code=code)
    icmp.data = dpkt.icmp.ICMP.Unreach(data=orig_ip)
    ip = dpkt.ip.IP(src=socket.inet_aton(icmp_src), dst=socket.inet_aton(orig_src),
                    p=dpkt.ip.IP_PROTO_ICMP, ttl=64, id=next(_ip_id) & 0xFFFF)
    ip.data = icmp
    ip.len = 20 + len(bytes(icmp))
    eth = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                                 type=dpkt.ethernet.ETH_TYPE_IP)
    eth.data = ip
    return (ts, bytes(eth))


def _handshake(t0, cport, sport, cseq=1000, sseq=2000):
    return [
        _tcp(t0, CLIENT, SERVER, cport, sport, TH_SYN, seq=cseq),
        _tcp(t0 + 0.001, SERVER, CLIENT, sport, cport, TH_SYN | TH_ACK,
             seq=sseq, ack=cseq + 1),
        _tcp(t0 + 0.002, CLIENT, SERVER, cport, sport, TH_ACK,
             seq=cseq + 1, ack=sseq + 1),
    ]


# ------------------------------------------------------------------ scenarios

def syn_no_answer():
    """3 SYN dans le vide : DROP silencieux quelque part."""
    return [
        _tcp(0.0, CLIENT, SERVER, 51001, 443, TH_SYN, seq=1000),
        _tcp(1.0, CLIENT, SERVER, 51001, 443, TH_SYN, seq=1000),
        _tcp(3.0, CLIENT, SERVER, 51001, 443, TH_SYN, seq=1000),
    ]


def rst_to_syn():
    """RST immediat : rien n'ecoute sur le port."""
    return [
        _tcp(0.0, CLIENT, SERVER, 51002, 8443, TH_SYN, seq=1000),
        _tcp(0.002, SERVER, CLIENT, 8443, 51002, TH_RST | TH_ACK,
             seq=0, ack=1001),
    ]


def reject_icmp():
    """Le firewall repond admin-prohibited (code 13) : REJECT explicite."""
    return [
        _tcp(0.0, CLIENT, SERVER, 51003, 445, TH_SYN, seq=1000),
        _icmp_unreach(0.003, ROUTER, 13, CLIENT, SERVER, 51003, 445),
    ]


def retrans_heavy():
    """~17 % de retransmissions : perte franche sur le chemin."""
    pkts = _handshake(0.0, 51004, 80)
    t = 0.01
    seq = 1001
    sent = []  # (seq, payload) deja emis, pour les re-emettre
    for i in range(30):
        payload = bytes([i % 251]) * 1000
        pkts.append(_tcp(t, CLIENT, SERVER, 51004, 80, TH_PUSH | TH_ACK,
                         seq=seq, ack=2001, payload=payload))
        sent.append((seq, payload))
        # ACK du serveur (couvre ce segment)
        pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 80, 51004, TH_ACK,
                         seq=2001, ack=seq + 1000))
        seq += 1000
        t += 0.02
        # Toutes les 5 emissions, re-emettre un segment plus ancien (retrans),
        # 200 ms apres son original pour rester loin du seuil dup-capture.
        if i % 5 == 4:
            old_seq, old_payload = sent[i - 2]
            pkts.append(_tcp(t, CLIENT, SERVER, 51004, 80, TH_PUSH | TH_ACK,
                             seq=old_seq, ack=2001, payload=old_payload))
            t += 0.02
    return pkts


def zero_window_server():
    """Le serveur annonce win=0 : son application ne lit plus la socket."""
    pkts = _handshake(0.0, 51005, 8080)
    # Requete client
    pkts.append(_tcp(0.01, CLIENT, SERVER, 51005, 8080, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=b"Q" * 1000))
    # Le serveur ACK... avec une fenetre a zero, deux fois, 400 ms durant
    pkts.append(_tcp(0.04, SERVER, CLIENT, 8080, 51005, TH_ACK,
                     seq=2001, ack=2001, win=0))
    pkts.append(_tcp(0.2, SERVER, CLIENT, 8080, 51005, TH_ACK,
                     seq=2001, ack=2001, win=0))
    # Window update puis reponse
    pkts.append(_tcp(0.44, SERVER, CLIENT, 8080, 51005, TH_ACK,
                     seq=2001, ack=2001, win=65535))
    pkts.append(_tcp(0.45, SERVER, CLIENT, 8080, 51005, TH_PUSH | TH_ACK,
                     seq=2001, ack=2001, payload=b"R" * 500))
    pkts.append(_tcp(0.46, CLIENT, SERVER, 51005, 8080, TH_ACK,
                     seq=2001, ack=2501))
    pkts.append(_tcp(0.5, CLIENT, SERVER, 51005, 8080, TH_FIN | TH_ACK,
                     seq=2001, ack=2501))
    pkts.append(_tcp(0.51, SERVER, CLIENT, 8080, 51005, TH_FIN | TH_ACK,
                     seq=2501, ack=2002))
    pkts.append(_tcp(0.52, CLIENT, SERVER, 51005, 8080, TH_ACK,
                     seq=2002, ack=2502))
    return pkts


def slow_app():
    """ACK serveur en 5 ms, reponse en 800 ms : le delai est DANS l'app."""
    pkts = _handshake(0.0, 51006, 5432)
    cseq, sseq = 1001, 2001
    for t0 in (0.01, 1.0, 2.0):
        req = b"SELECT" + b"x" * 194
        pkts.append(_tcp(t0, CLIENT, SERVER, 51006, 5432, TH_PUSH | TH_ACK,
                         seq=cseq, ack=sseq, payload=req))
        # ACK pur immediat : la pile TCP serveur a RECU
        pkts.append(_tcp(t0 + 0.005, SERVER, CLIENT, 5432, 51006, TH_ACK,
                         seq=sseq, ack=cseq + len(req)))
        cseq += len(req)
        # ... mais l'application met 800 ms a repondre
        resp = b"ROWS" + b"y" * 396
        pkts.append(_tcp(t0 + 0.8, SERVER, CLIENT, 5432, 51006,
                         TH_PUSH | TH_ACK, seq=sseq, ack=cseq, payload=resp))
        sseq += len(resp)
        pkts.append(_tcp(t0 + 0.805, CLIENT, SERVER, 51006, 5432, TH_ACK,
                         seq=cseq, ack=sseq))
    pkts.append(_tcp(3.0, CLIENT, SERVER, 51006, 5432, TH_FIN | TH_ACK,
                     seq=cseq, ack=sseq))
    pkts.append(_tcp(3.001, SERVER, CLIENT, 5432, 51006, TH_FIN | TH_ACK,
                     seq=sseq, ack=cseq + 1))
    pkts.append(_tcp(3.002, CLIENT, SERVER, 51006, 5432, TH_ACK,
                     seq=cseq + 1, ack=sseq + 1))
    return pkts


def clean():
    """Transport parfaitement sain : TTFB 30 ms, zero perte, FIN propre."""
    pkts = _handshake(0.0, 51007, 443)
    cseq, sseq = 1001, 2001
    for t0 in (0.01, 0.5, 1.0):
        req = b"GET " + b"a" * 96
        pkts.append(_tcp(t0, CLIENT, SERVER, 51007, 443, TH_PUSH | TH_ACK,
                         seq=cseq, ack=sseq, payload=req))
        pkts.append(_tcp(t0 + 0.005, SERVER, CLIENT, 443, 51007, TH_ACK,
                         seq=sseq, ack=cseq + len(req)))
        cseq += len(req)
        resp = b"200 " + b"b" * 496
        pkts.append(_tcp(t0 + 0.03, SERVER, CLIENT, 443, 51007,
                         TH_PUSH | TH_ACK, seq=sseq, ack=cseq, payload=resp))
        sseq += len(resp)
        pkts.append(_tcp(t0 + 0.035, CLIENT, SERVER, 51007, 443, TH_ACK,
                         seq=cseq, ack=sseq))
    pkts.append(_tcp(1.5, CLIENT, SERVER, 51007, 443, TH_FIN | TH_ACK,
                     seq=cseq, ack=sseq))
    pkts.append(_tcp(1.501, SERVER, CLIENT, 443, 51007, TH_FIN | TH_ACK,
                     seq=sseq, ack=cseq + 1))
    pkts.append(_tcp(1.502, CLIENT, SERVER, 51007, 443, TH_ACK,
                     seq=cseq + 1, ack=sseq + 1))
    return pkts


def midstream_rst():
    """Session etablie qui travaillait, tuee net par un RST serveur."""
    pkts = _handshake(0.0, 51008, 1433)
    pkts.append(_tcp(0.01, CLIENT, SERVER, 51008, 1433, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=b"q" * 200))
    pkts.append(_tcp(0.02, SERVER, CLIENT, 1433, 51008, TH_PUSH | TH_ACK,
                     seq=2001, ack=1201, payload=b"r" * 300))
    pkts.append(_tcp(0.025, CLIENT, SERVER, 51008, 1433, TH_ACK,
                     seq=1201, ack=2301))
    # 30 s d'inactivite... puis RST sec du cote serveur (timeout firewall ?)
    pkts.append(_tcp(30.0, SERVER, CLIENT, 1433, 51008, TH_RST,
                     seq=2301, ack=0))
    return pkts


def mtu_blackhole():
    """Gros segments qui ne passent pas + ICMP fragmentation-needed."""
    pkts = _handshake(0.0, 51009, 443)
    big = b"P" * 1400
    pkts.append(_tcp(0.01, CLIENT, SERVER, 51009, 443, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=big))
    pkts.append(_icmp_unreach(0.013, ROUTER, 4, CLIENT, SERVER, 51009, 443))
    # retransmissions du meme gros segment
    pkts.append(_tcp(0.5, CLIENT, SERVER, 51009, 443, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=big))
    pkts.append(_tcp(1.5, CLIENT, SERVER, 51009, 443, TH_PUSH | TH_ACK,
                     seq=1001, ack=2001, payload=big))
    return pkts


SCENARIOS = {
    "syn_no_answer": syn_no_answer,
    "rst_to_syn": rst_to_syn,
    "reject_icmp": reject_icmp,
    "retrans_heavy": retrans_heavy,
    "zero_window_server": zero_window_server,
    "slow_app": slow_app,
    "clean": clean,
    "midstream_rst": midstream_rst,
    "mtu_blackhole": mtu_blackhole,
}


def write_pcap(path: Path, pkts) -> None:
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in pkts:
            w.writepkt(buf, ts=ts)


def build_all(outdir: Path) -> dict[str, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    out = {}
    for name, fn in SCENARIOS.items():
        p = outdir / f"{name}.pcap"
        write_pcap(p, fn())
        out[name] = p
    return out


if __name__ == "__main__":
    import sys
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "fixtures"
    for name, p in build_all(dest).items():
        print(f"  {p}")
