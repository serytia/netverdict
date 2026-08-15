"""Validation terrain de l'etage DNS : pcaps produits par un VRAI kernel.

Ces captures viennent de lab/dns_scenario.sh, execute dans la VM netlab. Les
messages sont produits par de VRAIS serveurs (dnsmasq 2.91, BIND 9.20), les
pertes par iptables, les delais par netem, la capture par tcpdump. Aucune
etape ne passe par dpkt avant la lecture : c'est la contre-preuve independante
des fixtures de test_dns.py, qui sont ecrites ET lues par nous.

Ce que cette confrontation a rapporte le 15/08/2026 :

1. UN DEFAUT REEL DANS L'OUTIL. `tcp_retry_seen` comptait un repli TCP/53
   simplement TENTE comme un repli reussi. Au lab, dig a bien rejoue sa
   question apres un TC=1, le pare-feu simule a jete les SYN, et netverdict
   n'a rendu AUCUN verdict - il se taisait exactement dans le cas qu'il vise.
   Corrige en distinguant `tcp_retry_seen` et `tcp_retry_ok`, ce qui a rendu
   la preuve PLUS forte que la conception d'origine (le pare-feu est prouve,
   plus seulement suppose).

2. DEUX DEFAUTS DANS LE BANC D'ESSAI, pas dans l'outil - la moitie du benefice
   d'un lab. dnsmasq ne tronque jamais ses reponses locales (672 puis 683
   octets renvoyes avec TC=0, au-dela de la limite de 512 du RFC 1035), et
   named refuse de lire une configuration hors de /etc/bind sous AppArmor.
   Dans les deux cas netverdict lisait juste ; c'est le scenario qui ne testait
   pas ce qu'il croyait tester.

3. LA PRECISION DE LA MESURE : netem delay 1500 ms -> entre 1501 ms (VM au
   repos) et 1562 ms (VM qui vient de booter) mesurees, y compris sur la
   capture a snaplen 96 ou les adresses sont illisibles.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netverdict.dns import (build_resolutions, compute_dns_signals,
                            link_flows, parse_dns_over_tcp,
                            reassemble_stream)
from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.rules.engine import (evaluate, evaluate_dns, load_dns_rules,
                                     load_rules)
from netverdict.signals import compute_signals

LAB_DIR = Path(__file__).parent / "fixtures" / "lab"

pytestmark = pytest.mark.skipif(
    not (LAB_DIR / "dns_clean.pcap").is_file(),
    reason="pcaps DNS du lab absents (generer avec lab/dns_scenario.sh)",
)


def analyse(nom):
    """Rejoue la chaine complete du CLI sur une capture du lab."""
    cap = read_capture(LAB_DIR / f"{nom}.pcap")
    flows = build_flows(cap)
    signals = [compute_signals(f) for f in flows]
    verdicts = evaluate(signals, load_rules())
    tcp53 = [(s.t_first, s.client, s.server, s.established_seen)
             for s in signals if s.sport == 53]
    msgs = list(cap.dns_msgs)
    for fl in flows:
        if fl.sport != 53:
            continue
        for du_client in (True, False):
            segs = [(op.pkt.seq, op.pkt.payload) for op in fl.pkts
                    if op.from_client is du_client and op.pkt.payload]
            if not segs:
                continue
            flux, complet = reassemble_stream(segs)
            t0 = next(op.pkt.ts for op in fl.pkts
                      if op.from_client is du_client and op.pkt.payload)
            src, dst = ((fl.client, fl.server) if du_client
                        else (fl.server, fl.client))
            sp, dp = ((fl.cport, fl.sport) if du_client else (fl.sport, fl.cport))
            msgs.extend(parse_dns_over_tcp(t0, src, dst, sp, dp, flux, complet))
    res = build_resolutions(msgs, cap.t_last_seen, tcp53)
    dns = evaluate_dns([compute_dns_signals(r, cap.t_last_seen) for r in res],
                       load_dns_rules())
    liens = link_flows(res, [(i, s.server, s.t_first, s.client)
                             for i, s in enumerate(signals)])
    return cap, verdicts, dns, liens


# scenario -> regle attendue sur la resolution
ATTENDU = {
    "dns_clean":       "dns-clean",
    "dns_nxdomain":    "dns-nxdomain",
    "dns_refused":     "dns-refused",
    "dns_slow":        "dns-slow",
    "dns_no_answer":   "dns-no-answer",
    "dns_truncated":   "dns-truncated-tcp-retry-failed",
    "dns_slow_snap96": "dns-slow",
    "dns_then_flow":   "dns-slow",
}


@pytest.mark.parametrize("nom, regle", sorted(ATTENDU.items()))
def test_le_verdict_terrain_concorde(nom, regle):
    _, _, dns, _ = analyse(nom)
    obtenus = [d.primary.rule.id for d in dns if d.primary]
    assert regle in obtenus, f"{nom}: {obtenus} au lieu de {regle!r}"


def test_un_repli_tcp_qui_aboutit_ne_declenche_aucune_accusation():
    """Pendant terrain de dns_truncated : meme TC=1, mais TCP/53 autorise. La
    resolution aboutit, et le message de reponse est lu SUR TCP (prefixe de
    longueur, reassemblage des segments)."""
    _, _, dns, _ = analyse("dns_truncated_tcp_ok")
    accusations = [m.rule.id for d in dns for m in d.matches
                   if m.rule.id.startswith("dns-truncated")]
    assert accusations == [], f"accusation a tort : {accusations}"
    tronquee = [d for d in dns if d.signals.dns_truncated]
    assert tronquee, "la reponse TC=1 doit rester visible dans les signaux"
    assert tronquee[0].signals.tcp_retry_ok is True


# netem delay 1500 ms est un PLANCHER, pas une cible : il ne peut qu'ajouter
# du delai. L'ordonnancement de la VM en ajoute encore, et il varie avec sa
# charge - mesure entre 1501 ms (VM au repos) et 1562 ms (VM qui vient de
# booter, apt encore actif). Un encadrement asymetrique dit donc la verite
# physique du banc, la ou un `approx(1500, abs=25)` symetrique autorisait
# 1475 ms : une valeur SOUS le plancher aurait signale une mesure fausse, et
# le test l'aurait acceptee.
NETEM_MS = 1500
JITTER_VM_MS = 300


def _dans_la_fenetre_netem(latence_ms):
    return NETEM_MS <= latence_ms <= NETEM_MS + JITTER_VM_MS


def test_le_delai_netem_est_mesure_a_la_milliseconde():
    """netem delay 1500 ms sur la reponse -> la latence mesuree doit tomber
    dessus. C'est la seule verification qui prouve que la mesure est juste et
    pas seulement plausible : la mesurer depuis la derniere reemission, ou
    depuis la reponse, donnerait un ordre de grandeur different."""
    _, _, dns, _ = analyse("dns_slow")
    lat = dns[0].signals.latency_ms
    assert _dans_la_fenetre_netem(lat), f"{lat} ms hors fenetre netem"


def test_a_snaplen_96_la_latence_reste_juste_et_les_adresses_se_taisent():
    """La raison d'etre du parseur d'en-tete maison, confrontee au reel : le
    message est coupe (dpkt leverait), la latence reste exacte, et les
    adresses sont ANNONCEES illisibles au lieu d'etre devinees."""
    _, _, dns, liens = analyse("dns_slow_snap96")
    s = dns[0].signals
    assert s.capture_truncated is True
    assert s.answers_readable is False
    assert _dans_la_fenetre_netem(s.latency_ms)
    assert liens == {}          # rien a nommer, et rien d'invente


def test_le_repli_tcp_53_mort_est_bien_impute_au_pare_feu():
    """Le defaut n°1 ci-dessus, verrouille : TC=1 + SYN TCP/53 sans reponse."""
    _, _, dns, _ = analyse("dns_truncated")
    s = dns[0].signals
    assert s.dns_truncated is True
    assert s.tcp_retry_seen is True      # le client a bien rejoue
    assert s.tcp_retry_ok is False       # ...et ca n'a jamais abouti
    assert dns[0].verdict == "RESEAU"


def test_un_transport_sain_precede_d_une_resolution_lente_dit_les_deux():
    """LE cas qui a motive l'etage, sur un vrai kernel : dig + curl reels,
    netem sur la resolution seule. La connexion est irreprochable ET le temps
    perdu est attribue - il n'y a plus a choisir entre les deux."""
    _, verdicts, dns, liens = analyse("dns_then_flow")
    assert dns[0].verdict == "RESEAU"
    assert _dans_la_fenetre_netem(dns[0].signals.latency_ms)
    # Le flux vers l'adresse resolue existe, il est sain, et il porte le nom.
    flux = [i for i, fv in enumerate(verdicts) if fv.signals.sport == 8080]
    assert flux, "le flux HTTP du scenario est absent de la capture"
    i = flux[0]
    assert verdicts[i].verdict == "RAS"
    assert liens[i].qname == "srv.corp.local"
    assert liens[i].explains_delay is True
    assert _dans_la_fenetre_netem(liens[i].latency_ms)


def test_le_compte_de_paquets_boucle_sur_toutes_les_captures_terrain():
    for nom in sorted(ATTENDU):
        st = read_capture(LAB_DIR / f"{nom}.pcap").stats
        somme = (st.tcp + st.udp + st.icmp + st.other_ip + st.non_ip
                 + st.fragments_skipped + st.parse_errors)
        assert st.total == somme, f"{nom}: {st.total - somme} paquets perdus"
