"""Calcule les signaux TCP par flux : des FAITS mesures, zero jugement.

C'est le coeur technique de l'outil : la reimplementation du sous-ensemble
d'analyse TCP dont le triage a besoin (ce que tshark appelle tcp.analysis.*).
Les seuils et les verdicts vivent dans les regles YAML, pas ici — meme
separation parse/judge que decoders/rules dans un pack Wazuh.

Chaque champ de FlowSignals est adressable par les regles : c'est une API,
les noms sont stables et courts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .flows import Flow

# --- Arithmetique de numeros de sequence (modulo 2^32) -----------------------
# Une capture qui traverse le wrap (toutes les ~4 Go transferes) casse les
# comparaisons naives ; l'arithmetique signee modulaire est la forme standard.

_MOD = 1 << 32
_HALF = 1 << 31


def seq_le(a: int, b: int) -> bool:
    """a <= b au sens TCP (fenetre de comparaison de 2 Go)."""
    return ((b - a) & (_MOD - 1)) < _HALF


def seq_add(a: int, n: int) -> int:
    return (a + n) & (_MOD - 1)


def _pctl(samples: list[float], q: float) -> Optional[float]:
    if not samples:
        return None
    s = sorted(samples)
    idx = min(len(s) - 1, max(0, round(q * (len(s) - 1))))
    return s[idx]


# Keepalive TCP : segment de 0 ou 1 octet emis a snd_nxt-1. Periodique par
# nature, il matcherait le detecteur de retransmission a chaque emission et
# fabriquerait de la fausse perte sur toute session longue et calme.
_KEEPALIVE_MAX_LEN = 1

# Un segment qui n'avance pas la fenetre mais arrive dans cette fenetre
# apres le dernier octet le plus haut est du REORDONNANCEMENT de capture,
# pas une retransmission (meme heuristique que Wireshark).
_OOO_WINDOW_S = 0.003


@dataclass
class FlowSignals:
    # Identite / contexte
    client: str = ""
    server: str = ""
    cport: int = 0
    sport: int = 0
    direction_confident: bool = True
    started_midstream: bool = False
    t_first: float = 0.0             # epoch du premier paquet du flux
    duration_s: float = 0.0
    pkts_total: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    data_pkts_c2s: int = 0
    data_pkts_s2c: int = 0

    # Handshake
    syn_count: int = 0
    synack_seen: bool = False
    handshake_complete: bool = False
    handshake_rtt_ms: Optional[float] = None
    syn_span_s: float = 0.0          # etalement des SYN retransmis
    rst_to_syn: bool = False         # RST en reponse directe au SYN
    rst_to_syn_ms: Optional[float] = None

    # Perte / retransmissions
    retrans_c2s: int = 0
    retrans_s2c: int = 0
    retrans_total: int = 0
    retrans_rate: float = 0.0        # retrans / (data pkts + retrans)
    dup_ack_bursts_from_client: int = 0   # le RECEPTEUR emet les dup acks
    dup_ack_bursts_from_server: int = 0

    # Latence
    rtt_ms_min: Optional[float] = None
    rtt_ms_p50: Optional[float] = None
    rtt_ms_p95: Optional[float] = None
    # Dispersion p95/min : mesure de gigue SANS baseline externe — la
    # reference est le meilleur RTT observe dans la capture elle-meme.
    rtt_ratio_p95_min: Optional[float] = None

    # Zero window (recepteur sature : l'app ne lit pas sa socket)
    zw_from_client: int = 0
    zw_from_server: int = 0
    zw_max_ms: float = 0.0
    zw_total_ms: float = 0.0

    # Comportement applicatif
    exchanges: int = 0
    ttfb_ms_p50: Optional[float] = None
    ttfb_ms_p95: Optional[float] = None
    ttfb_ms_max: Optional[float] = None
    # Delai entre la fin de la requete et l'ACK PUR du serveur : si l'ACK est
    # rapide mais la reponse lente, la pile TCP serveur a recu — c'est l'app
    # qui traine. Signal discriminant n°1 du verdict APPLICATIF.
    server_ack_delay_ms_p95: Optional[float] = None

    # Cloture
    closed_by: str = "none"          # fin | rst_client | rst_server | none
    rst_midstream: bool = False
    rst_emitter: str = ""            # IP de l'emetteur du RST (pour la preuve)

    # ICMP rattache
    icmp_admin_prohibited: bool = False
    icmp_admin_prohibited_from: Optional[str] = None
    icmp_frag_needed: bool = False
    icmp_unreach_count: int = 0

    # Divers
    dup_capture_skipped: int = 0

    def as_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


def compute_signals(fl: Flow) -> FlowSignals:
    sig = FlowSignals(client=fl.client, server=fl.server,
                      cport=fl.cport, sport=fl.sport,
                      direction_confident=fl.direction_confident,
                      dup_capture_skipped=fl.dup_capture_skipped)
    pkts = fl.pkts
    if not pkts:
        return sig

    sig.pkts_total = len(pkts)
    sig.t_first = pkts[0].pkt.ts
    sig.duration_s = pkts[-1].pkt.ts - pkts[0].pkt.ts
    first = pkts[0].pkt
    sig.started_midstream = not (first.syn)

    rtt_samples: list[float] = []
    ttfb_samples: list[float] = []
    ack_delay_samples: list[float] = []

    # Etat handshake
    syn_times: list[float] = []
    synack_times: list[float] = []

    # Etat retrans/rtt par sens. La detection de retransmission suit la
    # FENETRE (max_seq_end), pas l'identite (seq,len) des segments : avec
    # TSO/GSO l'original part en mega-segment et la retransmission revient
    # re-decoupee en segments MSS — une comparaison exacte ne revoit jamais
    # le meme couple et rate 100 % des pertes (constate sur capture kernel
    # au lab, 2026-07-24). Regle : un segment de donnees qui n'avance pas
    # max_seq_end transporte des octets deja emis -> retransmission, sauf
    # arrivee dans la fenetre de reordonnancement (_OOO_WINDOW_S).
    class _Dir:
        def __init__(self):
            self.pending: dict[int, float] = {}      # seq_end -> ts (RTT)
            self.max_seq_end: Optional[int] = None
            self.t_max_seq: float = 0.0              # ts du plus haut octet emis
            self.last_ack: Optional[int] = None
            self.last_win: Optional[int] = None
            self.dup_run = 0
            self.zw_open_ts: Optional[float] = None
            self.fin_ts: Optional[float] = None

    c2s, s2c = _Dir(), _Dir()

    # Machine a etats requete/reponse pour le TTFB applicatif.
    talk_state: Optional[str] = None   # None | "client" | "server"
    last_c2s_data_ts: Optional[float] = None
    last_c2s_seq_end: Optional[int] = None
    block_ack_measured = False

    data_bidir_seen_c2s = False
    data_bidir_seen_s2c = False
    rst_info: Optional[tuple[bool, float, bool]] = None  # (from_client, ts, data_before)

    for op in pkts:
        p = op.pkt
        me, other = (c2s, s2c) if op.from_client else (s2c, c2s)

        # ---- Handshake -------------------------------------------------------
        if p.syn and not p.ack_flag and op.from_client:
            syn_times.append(p.ts)
        if p.syn and p.ack_flag and not op.from_client:
            synack_times.append(p.ts)
            sig.synack_seen = True
            # RTT du handshake : dernier SYN emis avant ce SYN/ACK.
            prev_syns = [t for t in syn_times if t <= p.ts]
            if prev_syns and sig.handshake_rtt_ms is None:
                sig.handshake_rtt_ms = (p.ts - prev_syns[-1]) * 1000.0
                rtt_samples.append(sig.handshake_rtt_ms)
        if p.rst and not op.from_client and syn_times and not sig.synack_seen \
                and not data_bidir_seen_s2c:
            sig.rst_to_syn = True
            if sig.rst_to_syn_ms is None:
                sig.rst_to_syn_ms = (p.ts - syn_times[-1]) * 1000.0

        # ---- Zero window -----------------------------------------------------
        # win==0 annonce est un zero window quel que soit le window scale
        # (0 * 2^n = 0) ; on exclut RST/SYN ou la fenetre n'a pas de sens.
        if not p.rst and not p.syn:
            if p.win == 0:
                if op.from_client:
                    sig.zw_from_client += 1
                else:
                    sig.zw_from_server += 1
                if me.zw_open_ts is None:
                    me.zw_open_ts = p.ts
            elif me.zw_open_ts is not None:
                dur = (p.ts - me.zw_open_ts) * 1000.0
                sig.zw_total_ms += dur
                sig.zw_max_ms = max(sig.zw_max_ms, dur)
                me.zw_open_ts = None

        # ---- Donnees : retransmissions, RTT, volumes, TTFB -------------------
        if p.payload_len > 0:
            seq_end = seq_add(p.seq, p.payload_len)
            is_keepalive = (p.payload_len <= _KEEPALIVE_MAX_LEN
                            and me.max_seq_end is not None
                            and seq_end == me.max_seq_end)
            is_old_data = (me.max_seq_end is not None
                           and seq_le(seq_end, me.max_seq_end))
            if is_keepalive:
                pass
            elif is_old_data:
                if (p.ts - me.t_max_seq) >= _OOO_WINDOW_S:
                    if op.from_client:
                        sig.retrans_c2s += 1
                    else:
                        sig.retrans_s2c += 1
                    # Karn : tout echantillon RTT contenant des octets
                    # retransmis devient inutilisable (on ne saura pas quel
                    # exemplaire l'ACK acquitte).
                    first_retrans_byte = seq_add(p.seq, 1)
                    for se in [se for se in me.pending
                               if seq_le(first_retrans_byte, se)]:
                        me.pending.pop(se, None)
                # sinon : reordonnancement de capture, pas une perte
            else:
                if op.from_client:
                    sig.data_pkts_c2s += 1
                    sig.bytes_c2s += p.payload_len
                else:
                    sig.data_pkts_s2c += 1
                    sig.bytes_s2c += p.payload_len
                me.pending[seq_end] = p.ts
                me.max_seq_end = seq_end
                me.t_max_seq = p.ts

            if not is_keepalive:
                if op.from_client:
                    data_bidir_seen_c2s = True
                    if talk_state != "client":
                        talk_state = "client"
                        block_ack_measured = False
                    last_c2s_data_ts = p.ts
                    last_c2s_seq_end = seq_end
                else:
                    data_bidir_seen_s2c = True
                    if talk_state == "client" and last_c2s_data_ts is not None:
                        ttfb_samples.append((p.ts - last_c2s_data_ts) * 1000.0)
                    talk_state = "server"

        # ---- ACKs : echantillons RTT, dup acks, ack-delay serveur ------------
        if p.ack_flag and not p.syn and not p.rst:
            # RTT : cet ACK couvre-t-il des segments en attente du sens oppose ?
            covered = [se for se in other.pending if seq_le(se, p.ack)]
            for se in covered:
                rtt_samples.append((p.ts - other.pending.pop(se)) * 1000.0)

            if p.payload_len == 0 and not p.fin:
                # Dup ACK : meme ack ET meme fenetre que le precedent ACK pur
                # du meme sens. Une fenetre differente = window update, pas un
                # dup ack (l'erreur classique des detecteurs naifs).
                if me.last_ack is not None and p.ack == me.last_ack \
                        and p.win == me.last_win:
                    me.dup_run += 1
                    if me.dup_run == 3:
                        if op.from_client:
                            sig.dup_ack_bursts_from_client += 1
                        else:
                            sig.dup_ack_bursts_from_server += 1
                else:
                    me.dup_run = 0
                me.last_ack, me.last_win = p.ack, p.win

                # Ack-delay serveur : ACK pur qui couvre la fin de la requete,
                # AVANT que la reponse ne parte. Mesure une fois par bloc.
                if (not op.from_client and talk_state == "client"
                        and not block_ack_measured
                        and last_c2s_seq_end is not None
                        and last_c2s_data_ts is not None
                        and seq_le(last_c2s_seq_end, p.ack)):
                    ack_delay_samples.append((p.ts - last_c2s_data_ts) * 1000.0)
                    block_ack_measured = True

        # ---- Cloture ---------------------------------------------------------
        if p.fin:
            me.fin_ts = me.fin_ts or p.ts
        if p.rst and rst_info is None:
            data_before = data_bidir_seen_c2s and data_bidir_seen_s2c
            rst_info = (op.from_client, p.ts, data_before)

    # ---- Consolidation -------------------------------------------------------
    sig.syn_count = len(syn_times)
    if len(syn_times) >= 2:
        sig.syn_span_s = syn_times[-1] - syn_times[0]
    sig.handshake_complete = sig.synack_seen and (
        data_bidir_seen_c2s or data_bidir_seen_s2c
        or any(op.from_client and op.pkt.ack_flag and not op.pkt.syn
               for op in pkts))

    sig.retrans_total = sig.retrans_c2s + sig.retrans_s2c
    data_total = sig.data_pkts_c2s + sig.data_pkts_s2c
    if data_total + sig.retrans_total > 0:
        sig.retrans_rate = sig.retrans_total / (data_total + sig.retrans_total)

    sig.rtt_ms_min = min(rtt_samples) if rtt_samples else None
    sig.rtt_ms_p50 = _pctl(rtt_samples, 0.50)
    # p95 pollue par les delayed ACK (~40-200 ms ajoutes sur les ACK differes) :
    # c'est connu et assume, le p50 et le min restent des mesures propres.
    sig.rtt_ms_p95 = _pctl(rtt_samples, 0.95)
    if sig.rtt_ms_min and sig.rtt_ms_p95 and sig.rtt_ms_min > 0:
        sig.rtt_ratio_p95_min = sig.rtt_ms_p95 / sig.rtt_ms_min

    sig.exchanges = len(ttfb_samples)
    sig.ttfb_ms_p50 = _pctl(ttfb_samples, 0.50)
    sig.ttfb_ms_p95 = _pctl(ttfb_samples, 0.95)
    sig.ttfb_ms_max = max(ttfb_samples) if ttfb_samples else None
    sig.server_ack_delay_ms_p95 = _pctl(ack_delay_samples, 0.95)

    # Periode zero-window jamais refermee : compter jusqu'a la fin du flux.
    for d in (c2s, s2c):
        if d.zw_open_ts is not None:
            dur = (pkts[-1].pkt.ts - d.zw_open_ts) * 1000.0
            sig.zw_total_ms += dur
            sig.zw_max_ms = max(sig.zw_max_ms, dur)

    if rst_info is not None:
        from_client, rst_ts, data_before = rst_info
        fin_before = any(d.fin_ts is not None and d.fin_ts <= rst_ts
                         for d in (c2s, s2c))
        sig.closed_by = "rst_client" if from_client else "rst_server"
        sig.rst_emitter = fl.client if from_client else fl.server
        # Un RST apres FIN est une fermeture expeditive banale ; le signal
        # interessant est le RST qui interrompt une session qui travaillait.
        sig.rst_midstream = data_before and not fin_before
    elif c2s.fin_ts or s2c.fin_ts:
        sig.closed_by = "fin"

    for ev in fl.icmp:
        sig.icmp_unreach_count += 1
        if ev.is_admin_prohibited:
            sig.icmp_admin_prohibited = True
            sig.icmp_admin_prohibited_from = ev.icmp_src
        if ev.is_frag_needed:
            sig.icmp_frag_needed = True

    return sig
