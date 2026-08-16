"""Resolutions DNS : parsing tolerant a la troncature, regroupement, verdicts.

Le cas qui a motive l'etage entier est en fin de fichier
(test_le_temps_percu_ne_disparait_plus_quand_le_transport_est_sain) : une
resolution de 2,4 s devant un flux TCP irreprochable. netverdict 0.7.0 rendait
« transport sain », code retour 0.
"""

from __future__ import annotations

import socket

import dpkt
import pytest

from netverdict.dns import (DELAY_ATTRIBUTION_WINDOW_S, NEW_RESOLUTION_GAP_S,
                            build_resolutions, compute_dns_signals,
                            link_flows, parse_dns_datagram)
from netverdict.rules.engine import evaluate_dns, load_dns_rules, load_rules

CLIENT = "10.0.0.42"
RESOLVER = "10.0.0.53"


@pytest.fixture(scope="module")
def dns_rules():
    return load_dns_rules()


def dns_bytes(txid=0x1234, qname="api.corp.local", qtype=dpkt.dns.DNS_A,
              response=False, rcode=0, tc=False, answers=()):
    d = dpkt.dns.DNS(id=txid, rd=1)
    if response:
        d.qr = dpkt.dns.DNS_R
        d.ra = 1
    d.rcode = rcode
    if tc:
        d.tc = 1
    d.qd = [dpkt.dns.DNS.Q(name=qname, type=qtype, cls=dpkt.dns.DNS_IN)]
    d.an = [dpkt.dns.DNS.RR(name=qname, type=dpkt.dns.DNS_A,
                            cls=dpkt.dns.DNS_IN, ttl=300,
                            ip=socket.inet_aton(a)) for a in answers]
    return bytes(d)


def msg(ts, response=False, qname="api.corp.local", txid=0x1234, rcode=0,
        tc=False, answers=(), cut=None, qtype=dpkt.dns.DNS_A):
    raw = dns_bytes(txid=txid, qname=qname, qtype=qtype, response=response,
                    rcode=rcode, tc=tc, answers=answers)
    declared = len(raw)
    if cut is not None:
        raw = raw[:cut]
    src, dst = (RESOLVER, CLIENT) if response else (CLIENT, RESOLVER)
    sport, dport = (53, 54321) if response else (54321, 53)
    return parse_dns_datagram(ts, src, dst, sport, dport, raw, declared)


# --------------------------------------------------------------- parsing

def test_len_tete_reste_lisible_quand_le_snaplen_a_coupe():
    """La raison d'etre du parseur maison. `dpkt.dns` leve des que le message
    est coupe, MEME avec les douze octets d'en-tete intacts (mesure du
    15/08) : s'appuyer dessus perdrait tout le DNS d'une capture tronquee."""
    raw = dns_bytes(response=True, rcode=2, answers=())
    with pytest.raises(Exception):
        dpkt.dns.DNS(raw[:20])          # le constat qui justifie tout le reste
    m = parse_dns_datagram(1.0, RESOLVER, CLIENT, 53, 54321, raw[:20], len(raw))
    assert m is not None
    assert m.txid == 0x1234
    assert m.is_response is True
    assert m.rcode == 2                 # SERVFAIL toujours lisible
    assert m.capture_truncated is True


def test_sous_douze_octets_il_n_y_a_rien_a_lire():
    assert parse_dns_datagram(1.0, CLIENT, RESOLVER, 54321, 53, b"\x12\x34", 32) is None


def test_un_nom_coupe_ne_rend_pas_un_nom_partiel():
    """« api.corp » designerait un autre hote que « api.corp.local » : mieux
    vaut pas de nom du tout qu'un nom faux."""
    raw = dns_bytes(qname="api.corp.local")
    m = parse_dns_datagram(1.0, CLIENT, RESOLVER, 54321, 53, raw[:20], len(raw))
    assert m is not None
    assert m.qname is None
    assert m.qtype is None


def test_les_adresses_ne_sont_pas_inventees_quand_la_reponse_est_coupee():
    m = msg(1.0, response=True, answers=("10.0.0.5",), cut=40)
    assert m.answers == []
    assert m.answers_readable is False
    assert m.capture_truncated is True


def test_un_nom_hostile_est_neutralise():
    """Le nom vient d'un paquet brut : n'importe qui sur le chemin le fabrique.
    U+202E inverserait l'affichage du rapport sans laisser de trace visible.

    Ecrit en ECHAPPEMENT et non en litteral, pour la meme raison que dans
    timeline.py : un controle bidi colle dans le source est invisible a la
    relecture - le defaut se cacherait dans son propre test."""
    hostile = "ab" + chr(0x202E) + "cde.corp"
    m = msg(1.0, qname=hostile)
    assert chr(0x202E) not in m.qname
    assert "\x1b" not in m.qname


# ----------------------------------------------------------- regroupement

def test_deux_tentatives_et_une_reponse_font_une_resolution():
    msgs = [msg(0.0), msg(1.0), msg(2.4, response=True, answers=("10.0.0.5",))]
    res = build_resolutions(msgs, capture_end=2.5)
    assert len(res) == 1
    s = compute_dns_signals(res[0], 2.5)
    assert s.attempts == 2
    assert s.answered is True
    # Mesuree depuis la PREMIERE tentative : c'est le temps subi. Depuis la
    # derniere reemission, on afficherait 1400 ms au lieu de 2400.
    assert s.latency_ms == pytest.approx(2400.0)
    assert s.answers_str == "10.0.0.5"


def test_un_txid_neuf_a_chaque_essai_reste_une_seule_resolution():
    """Les resolveurs se partagent en deux familles ; grouper par txid n'en
    verrait qu'une, et compterait les essais de l'autre comme autant de
    resolutions rapides."""
    msgs = [msg(0.0, txid=0x1111), msg(1.0, txid=0x2222),
            msg(2.4, response=True, txid=0x2222, answers=("10.0.0.5",))]
    res = build_resolutions(msgs, capture_end=2.5)
    assert len(res) == 1
    assert compute_dns_signals(res[0], 2.5).attempts == 2


def test_une_question_bien_plus_tard_ouvre_une_nouvelle_resolution():
    msgs = [msg(0.0), msg(0.05, response=True, answers=("10.0.0.5",)),
            msg(NEW_RESOLUTION_GAP_S + 10.0)]
    res = build_resolutions(msgs, capture_end=NEW_RESOLUTION_GAP_S + 11.0)
    assert len(res) == 2


def test_une_reponse_orpheline_ne_fabrique_pas_de_latence():
    """Capture demarree apres la question : la reponse seule ne prouve aucun
    delai. En inventer un accuserait le resolveur sans preuve."""
    res = build_resolutions([msg(5.0, response=True, answers=("10.0.0.5",))],
                            capture_end=6.0)
    assert res == []


def test_sans_reponse_la_duree_est_bornee_par_la_fin_de_capture():
    res = build_resolutions([msg(0.0), msg(1.0)], capture_end=6.0)
    s = compute_dns_signals(res[0], 6.0)
    assert s.answered is False
    assert s.observed_ms == pytest.approx(6000.0)
    assert s.capture_ends_first is True


# ----------------------------------------------------------------- regles

def _verdict(msgs, dns_rules, capture_end=10.0, tcp53=None):
    res = build_resolutions(msgs, capture_end=capture_end, tcp53=tcp53)
    sigs = [compute_dns_signals(r, capture_end) for r in res]
    return evaluate_dns(sigs, dns_rules, lang="fr")


@pytest.mark.parametrize("msgs, attendu, regle", [
    ([msg(0.0), msg(5.0)], "RESEAU", "dns-no-answer"),
    ([msg(0.0), msg(1.5, response=True, rcode=2)], "APP", "dns-servfail"),
    ([msg(0.0), msg(0.1, response=True, rcode=3)], "APP", "dns-nxdomain"),
    ([msg(0.0), msg(0.1, response=True, rcode=5)], "RESEAU", "dns-refused"),
    ([msg(0.0), msg(0.1, response=True, tc=True)], "RESEAU",
     "dns-truncated-no-tcp-retry"),
    ([msg(0.0), msg(1.4, response=True, answers=("10.0.0.5",))], "RESEAU",
     "dns-slow"),
    # Sous la seconde, sinon dns-slow (priorite superieure) prend la main -
    # c'est justement ce que son `unless` garantit, voir le test dedie.
    ([msg(0.0), msg(0.5), msg(0.6, response=True, answers=("10.0.0.5",))],
     "RESEAU", "dns-answered-after-retry"),
    ([msg(0.0), msg(0.02, response=True, answers=("10.0.0.5",))], "RAS",
     "dns-clean"),
])
def test_chaque_regle_dns_se_declenche_sur_son_cas(msgs, attendu, regle,
                                                   dns_rules):
    vs = _verdict(msgs, dns_rules)
    assert len(vs) == 1
    assert vs[0].verdict == attendu
    assert vs[0].primary.rule.id == regle


def test_une_question_unique_sans_reponse_reste_ambigue(dns_rules):
    """Une seule question, aucune reponse, capture finie : rien ne distingue
    « le serveur se tait » de « la capture etait trop courte »."""
    vs = _verdict([msg(0.0)], dns_rules, capture_end=0.5)
    assert vs[0].verdict == "AMBIGU"
    assert vs[0].primary.rule.id == "dns-unanswered-capture-too-short"


def test_une_resolution_lente_ne_rend_pas_deux_verdicts(dns_rules):
    """Une resolution lente APRES reemission matche les deux regles ; le
    `unless` de dns-answered-after-retry evite d'ecrire deux fois le meme
    fait, ce qui diluerait le rapport."""
    vs = _verdict([msg(0.0), msg(0.9), msg(2.0, response=True,
                                           answers=("10.0.0.5",))], dns_rules)
    ids = [m.rule.id for m in vs[0].matches]
    assert ids == ["dns-slow"]


def test_un_repli_tcp_53_ABOUTI_disculpe_la_reponse_tronquee(dns_rules):
    msgs = [msg(0.0), msg(0.1, response=True, tc=True)]
    vs = _verdict(msgs, dns_rules, tcp53=[(0.2, CLIENT, RESOLVER, True)])
    ids = [m.rule.id for m in vs[0].matches]
    assert "dns-truncated-no-tcp-retry" not in ids
    assert "dns-truncated-tcp-retry-failed" not in ids


def test_un_repli_tcp_53_TENTE_mais_mort_accuse_le_pare_feu(dns_rules):
    """Defaut trouve au lab le 15/08 : dig avait bien rejoue sa question en
    TCP/53, le pare-feu simule avait jete les SYN, et l'outil ne rendait
    AUCUN verdict - « repli tente » comptait pour « repli reussi », et la
    regle se taisait dans le cas meme qu'elle vise."""
    msgs = [msg(0.0), msg(0.1, response=True, tc=True)]
    vs = _verdict(msgs, dns_rules, tcp53=[(0.2, CLIENT, RESOLVER, False)])
    assert vs[0].verdict == "RESEAU"
    assert vs[0].primary.rule.id == "dns-truncated-tcp-retry-failed"


def test_les_deux_jeux_de_regles_ne_se_melangent_pas(dns_rules):
    flow_rules = load_rules()
    assert flow_rules and dns_rules
    assert all(r.scope == "flow" for r in flow_rules)
    assert all(r.scope == "dns" for r in dns_rules)
    assert not ({r.id for r in flow_rules} & {r.id for r in dns_rules})


# ------------------------------------------------------ rattachement au flux

def test_le_flux_herite_du_nom_et_du_delai_qui_le_precede():
    res = build_resolutions([msg(0.0), msg(2.4, response=True,
                                           answers=("10.0.0.5",))],
                            capture_end=3.0)
    liens = link_flows(res, [(0, "10.0.0.5", 2.402)])
    assert liens[0].qname == "api.corp.local"
    assert liens[0].latency_ms == pytest.approx(2400.0)
    assert liens[0].explains_delay is True


def test_une_resolution_ancienne_nomme_sans_expliquer_le_delai():
    """Le nom vient du cache : afficher « precede de 240 s » suggererait un
    lien de cause qui n'existe pas."""
    res = build_resolutions([msg(0.0), msg(0.05, response=True,
                                           answers=("10.0.0.5",))],
                            capture_end=300.0)
    plus_tard = 0.05 + DELAY_ATTRIBUTION_WINDOW_S + 60.0
    liens = link_flows(res, [(0, "10.0.0.5", plus_tard)])
    assert liens[0].qname == "api.corp.local"
    assert liens[0].explains_delay is False


def test_aucun_rattachement_quand_les_adresses_sont_illisibles():
    """Snaplen serre : la latence reste juste, mais nommer un flux
    demanderait de deviner l'adresse resolue."""
    res = build_resolutions([msg(0.0), msg(0.05, response=True,
                                           answers=("10.0.0.5",), cut=40)],
                            capture_end=1.0)
    assert link_flows(res, [(0, "10.0.0.5", 0.1)]) == {}


# ------------------------------------------------------- DNS sur TCP/53

def _flux_tcp(nb_adresses=5, qname="big.corp.local", question=False):
    """Un message DNS complet precede de sa longueur sur 2 octets (RFC 1035
    §4.2.2), tel qu'il circule sur TCP/53."""
    import struct
    d = dpkt.dns.DNS(id=9, rd=1)
    if not question:
        d.qr = dpkt.dns.DNS_R
        d.ra = 1
    d.qd = [dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    if not question:
        d.an = [dpkt.dns.DNS.RR(name=qname, type=dpkt.dns.DNS_A,
                                cls=dpkt.dns.DNS_IN, ttl=60,
                                ip=socket.inet_aton(f"10.9.9.{i}"))
                for i in range(1, nb_adresses + 1)]
    corps = bytes(d)
    return struct.pack("!H", len(corps)) + corps


def test_le_flux_tcp_se_recolle_meme_dans_le_desordre():
    from netverdict.dns import reassemble_stream
    flux = _flux_tcp()
    a, b = flux[:40], flux[40:]
    for segments in ([(1000, a), (1040, b)],          # dans l'ordre
                     [(1040, b), (1000, a)],          # desordonne
                     [(1000, a), (1000, a), (1040, b)]):   # retransmission
        octets, complet = reassemble_stream(segments)
        assert complet is True
        assert octets == flux


def test_un_trou_arrete_le_reassemblage_au_lieu_de_recoller_n_importe_quoi():
    """Recoller des octets non contigus fabriquerait un message qui n'a jamais
    circule - et il serait parfaitement decodable, donc invisible."""
    from netverdict.dns import reassemble_stream
    flux = _flux_tcp()
    octets, complet = reassemble_stream([(1000, flux[:40]), (9999, flux[40:])])
    assert complet is False
    assert octets == flux[:40]


def test_un_message_dns_sur_tcp_est_decode_avec_ses_adresses():
    from netverdict.dns import parse_dns_over_tcp
    msgs = parse_dns_over_tcp(1.0, "10.0.0.53", "10.0.0.1", 53, 5000,
                              _flux_tcp(), complet=True)
    assert len(msgs) == 1
    assert msgs[0].over_tcp is True
    assert msgs[0].is_response is True
    assert len(msgs[0].answers) == 5
    assert msgs[0].answers_readable is True


def test_un_flux_tcp_incomplet_ne_publie_aucune_adresse():
    from netverdict.dns import parse_dns_over_tcp
    flux = _flux_tcp()
    msgs = parse_dns_over_tcp(1.0, "10.0.0.53", "10.0.0.1", 53, 5000,
                              flux[:40], complet=False)
    assert msgs and msgs[0].capture_truncated is True
    assert msgs[0].answers == []
    assert msgs[0].answers_readable is False


def test_un_repli_tcp_qui_REPOND_disculpe_la_troncature(dns_rules):
    """Meilleure preuve qu'une simple connexion etablie : une session TCP peut
    etre coupee avant la reponse. Ici la reponse existe, donc la resolution a
    bel et bien abouti."""
    from netverdict.dns import parse_dns_over_tcp
    msgs = [msg(0.0, qname="big.corp.local"),
            msg(0.1, response=True, tc=True, qname="big.corp.local")]
    # Le repli complet tel qu'il circule : la question rejouee sur TCP, puis
    # la reponse. C'est le couple qui prouve l'aboutissement.
    msgs += parse_dns_over_tcp(0.28, CLIENT, RESOLVER, 5000, 53,
                               _flux_tcp(question=True), complet=True)
    msgs += parse_dns_over_tcp(0.3, RESOLVER, CLIENT, 53, 5000,
                               _flux_tcp(), complet=True)
    # Le repli TCP existe mais la connexion n'est PAS marquee etablie : seule
    # la reponse lue dessus peut disculper.
    vs = _verdict(msgs, dns_rules, tcp53=[(0.25, CLIENT, RESOLVER, False)])
    accusations = [m.rule.id for v in vs for m in v.matches
                   if m.rule.id.startswith("dns-truncated")]
    assert accusations == []


# ---------------------------------------------------------- bout en bout

def _ecrire_pcap(path, trames):
    with open(path, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in trames:
            w.writepkt(buf, ts=ts)
    return path


def _eth_ip(src, dst, proto, payload):
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=proto, ttl=64, id=1)
    ip.data = payload
    ip.len = 20 + len(bytes(payload))
    e = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                               type=dpkt.ethernet.ETH_TYPE_IP)
    e.data = ip
    return bytes(e)


def _udp53(ts, response, **kw):
    raw = dns_bytes(response=response, **kw)
    u = dpkt.udp.UDP(sport=53 if response else 54321,
                     dport=54321 if response else 53)
    u.data = raw
    u.ulen = 8 + len(raw)
    src, dst = (RESOLVER, CLIENT) if response else (CLIENT, RESOLVER)
    return (ts, _eth_ip(src, dst, dpkt.ip.IP_PROTO_UDP, u))


def _tcp(ts, src, dst, sport, dport, flags, seq, ack, payload=b""):
    seg = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=seq,
                       ack=ack, win=65535)
    seg.data = payload
    return (ts, _eth_ip(src, dst, dpkt.ip.IP_PROTO_TCP, seg))


def test_le_temps_percu_ne_disparait_plus_quand_le_transport_est_sain(
        tmp_path, capsys):
    """LE cas qui a motive cet etage.

    2,4 s de resolution, puis une conversation TCP irreprochable de 20 ms.
    netverdict 0.7.0 affichait « transport sain » et rendait 0 : la
    supervision branchee sur ce code lisait « rien d'anormal » pendant que
    l'utilisateur attendait deux secondes et demie."""
    from dpkt.tcp import TH_ACK, TH_FIN, TH_PUSH, TH_SYN
    S = "10.0.0.5"
    trames = [
        _udp53(0.0, False),
        _udp53(1.0, False),
        _udp53(2.4, True, answers=("10.0.0.5",)),
        _tcp(2.402, CLIENT, S, 54322, 443, TH_SYN, 1000, 0),
        _tcp(2.404, S, CLIENT, 443, 54322, TH_SYN | TH_ACK, 5000, 1001),
        _tcp(2.404, CLIENT, S, 54322, 443, TH_ACK, 1001, 5001),
        _tcp(2.405, CLIENT, S, 54322, 443, TH_PUSH | TH_ACK, 1001, 5001, b"G" * 200),
        _tcp(2.407, S, CLIENT, 443, 54322, TH_ACK, 5001, 1201),
        _tcp(2.421, S, CLIENT, 443, 54322, TH_PUSH | TH_ACK, 5001, 1201, b"H" * 800),
        _tcp(2.422, CLIENT, S, 54322, 443, TH_ACK, 1201, 5801),
        _tcp(2.423, CLIENT, S, 54322, 443, TH_FIN | TH_ACK, 1201, 5801),
        _tcp(2.424, S, CLIENT, 443, 54322, TH_FIN | TH_ACK, 5801, 1202),
        _tcp(2.425, CLIENT, S, 54322, 443, TH_ACK, 1202, 5802),
    ]
    pcap = _ecrire_pcap(tmp_path / "dns-lent.pcap", trames)

    import json as _json
    from netverdict.cli import main
    rc = main(["analyze", str(pcap), "--json"])
    out = _json.loads(capsys.readouterr().out)

    # 1. Le code retour ne ment plus : il y a bien quelque chose a signaler.
    assert rc == 1
    # 2. Le flux TCP reste juge sain - le verdict TCP n'a jamais ete faux.
    assert out["flows"][0]["verdict"] == "RAS"
    # 3. ...et le temps perdu est enfin quelque part.
    dns = out["dns"][0]
    assert dns["verdict"] == "RESEAU"
    assert dns["signals"]["latency_ms"] == pytest.approx(2400.0)
    # 4. Le lien entre les deux est explicite, pas laisse au lecteur.
    assert out["flows"][0]["dns"]["qname"] == "api.corp.local"
    assert out["flows"][0]["dns"]["explains_delay"] is True
    # 5. Le compte de paquets boucle toujours.
    st = out["stats"]
    assert st["packets"] == (st["tcp"] + st["udp"] + st["icmp"] + st["other_ip"]
                             + st["non_ip"] + st["fragments_skipped"]
                             + st["parse_errors"])


def test_une_capture_sans_dns_ne_gagne_aucune_section(capsys):
    """Pas de bruit ajoute : l'etage DNS doit etre invisible quand il n'y a
    pas de DNS."""
    import json as _json
    from pathlib import Path
    from netverdict.cli import main
    fixture = Path(__file__).parent / "fixtures" / "slow_app.pcap"
    main(["analyze", str(fixture), "--json"])
    out = _json.loads(capsys.readouterr().out)
    assert out["dns"] == []
    assert out["stats"]["udp"] == 0


# ---------------------------------------------- verrous poses par la revue

def test_le_resolveur_accuse_est_celui_qui_a_repondu(dns_rules):
    """Un client a deux nameservers. Quand le premier se tait et que le second
    repond une erreur, la version d'origine accusait le PREMIER - c'est-a-dire
    la machine qui n'avait rien dit (revue du 15/08/2026)."""
    ns1, ns2 = "10.0.0.53", "10.0.0.54"
    q_bytes = dns_bytes()
    e_bytes = dns_bytes(response=True, rcode=2)
    msgs = [parse_dns_datagram(0.0, CLIENT, ns1, 5000, 53, q_bytes, len(q_bytes)),
            parse_dns_datagram(5.0, CLIENT, ns2, 5000, 53, q_bytes, len(q_bytes)),
            parse_dns_datagram(5.1, ns2, CLIENT, 53, 5000, e_bytes, len(e_bytes))]
    res = build_resolutions(msgs, capture_end=10.0)
    s = compute_dns_signals(res[0], 10.0)
    assert s.resolver == ns2, "le rapport accuserait le resolveur muet"
    vs = evaluate_dns([s], dns_rules, lang="fr")
    assert ns2 in vs[0].primary.evidence[0]


def test_un_repli_tcp_reussi_AILLEURS_n_efface_pas_l_echec_ici(dns_rules):
    """Le test `reponse_tcp` ne filtrait ni le client ni le resolveur : une
    reussite TCP/53 n'importe ou dans la capture effacait l'echec constate
    ici, et le verdict phare du module disparaissait."""
    from netverdict.dns import parse_dns_over_tcp
    ns1, ns2 = "10.0.0.53", "10.0.0.54"
    # NS1 tronque et son repli TCP est mort.
    q_bytes = dns_bytes()
    tc_bytes = dns_bytes(response=True, tc=True)
    msgs = [parse_dns_datagram(0.0, CLIENT, ns1, 5000, 53, q_bytes, len(q_bytes)),
            parse_dns_datagram(0.1, ns1, CLIENT, 53, 5000, tc_bytes,
                               len(tc_bytes))]
    # Le client rejoue le MEME nom sur NS2, et la ca marche.
    msgs += parse_dns_over_tcp(1.0, CLIENT, ns2, 5001, 53,
                               _flux_tcp(question=True), complet=True)
    msgs += parse_dns_over_tcp(1.1, ns2, CLIENT, 53, 5001,
                               _flux_tcp(), complet=True)
    vs = _verdict(msgs, dns_rules,
                  tcp53=[(0.2, CLIENT, ns1, False), (1.0, CLIENT, ns2, True)])
    accusations = [m.rule.id for v in vs for m in v.matches
                   if m.rule.id.startswith("dns-truncated")]
    assert "dns-truncated-tcp-retry-failed" in accusations, (
        "la reussite sur NS2 a efface l'echec de NS1")


def test_une_resolution_lente_EN_ERREUR_n_affirme_pas_avoir_resolu(dns_rules):
    """dns-slow ne regardait pas le rcode : un SERVFAIL lent produisait
    « {qname} resolu en 1500 ms » et « adresses obtenues : » (vide), en
    contradiction avec le verdict d'erreur rendu juste a cote."""
    vs = _verdict([msg(0.0), msg(1.5, response=True, rcode=2)], dns_rules)
    ids = [m.rule.id for m in vs[0].matches]
    assert "dns-servfail" in ids
    assert "dns-slow" not in ids


def test_le_delai_d_un_hote_n_est_pas_impute_au_flux_d_un_autre():
    """Sur une capture multi-hotes - port-miroir, capture cote serveur - la
    resolution lente d'une machine etait attachee au flux TCP d'une AUTRE,
    en affirmant « ce delai s'ajoute a ce que l'utilisateur a subi »."""
    a, b = "10.0.0.5", "10.0.0.77"
    q_bytes = dns_bytes()
    r_bytes = dns_bytes(response=True, answers=("10.0.0.30",))
    msgs = [parse_dns_datagram(0.0, a, RESOLVER, 5000, 53, q_bytes, len(q_bytes)),
            parse_dns_datagram(2.4, RESOLVER, a, 53, 5000, r_bytes, len(r_bytes))]
    res = build_resolutions(msgs, capture_end=20.0)
    # Le flux appartient a B, qui n'a emis AUCUN paquet DNS.
    liens = link_flows(res, [(0, "10.0.0.30", 2.9, b)])
    assert liens == {}, "le delai de A a ete impute au flux de B"
    # Et pour A, le rattachement reste bien fait.
    liens = link_flows(res, [(0, "10.0.0.30", 2.9, a)])
    assert liens[0].explains_delay is True


@pytest.mark.parametrize("regle_evitee, msgs", [
    ("dns-no-answer", [0.0, 5.0]),
    ("dns-slow", None),
])
def test_le_mdns_ne_declenche_aucune_accusation(dns_rules, regle_evitee, msgs):
    """La clause `is_mdns == false` protege quatre regles, et aucun test ne
    l'exercait (revue du 15/08). Une question multicast sans reponse est le
    fonctionnement NORMAL du protocole : accuser ferait un faux positif sur
    n'importe quelle capture de LAN."""
    from netverdict.dns import MDNS_PORT

    def m_mdns(ts, response=False, qname="printer.local"):
        raw = dns_bytes(qname=qname, response=response,
                        answers=("10.0.0.7",) if response else ())
        src, dst = (("224.0.0.251", CLIENT) if response
                    else (CLIENT, "224.0.0.251"))
        return parse_dns_datagram(ts, src, dst, MDNS_PORT, MDNS_PORT, raw,
                                  len(raw))

    if msgs is None:                    # resolution mDNS LENTE
        paquets = [m_mdns(0.0), m_mdns(2.0, response=True)]
    else:                               # questions mDNS sans reponse
        paquets = [m_mdns(t) for t in msgs]
    vs = _verdict(paquets, dns_rules)
    assert vs and vs[0].signals.is_mdns is True
    ids = [m.rule.id for m in vs[0].matches]
    assert regle_evitee not in ids, f"{regle_evitee} accuse du mDNS"


# ------------------------ verrous de seuil (les constantes, pas leur echo)

def test_les_seuils_sont_pinces_a_leur_valeur_et_non_a_eux_memes():
    """Les tests ecrivaient leurs entrees en fonction des constantes
    (`NEW_RESOLUTION_GAP_S + 10`), si bien que changer la constante deplacait
    l'entree d'autant : elargir un seuil ne cassait rien. Porter
    DELAY_ATTRIBUTION_WINDOW_S de 2 s a 60 s aurait fait affirmer qu'une
    resolution « explique le delai » d'une connexion partie une minute plus
    tard (revue du 15/08/2026)."""
    from netverdict import dns as m
    from netverdict import udp as mu

    assert m.NEW_RESOLUTION_GAP_S == 30.0
    assert m.NAMING_WINDOW_S == 300.0
    assert m.DELAY_ATTRIBUTION_WINDOW_S == 2.0
    assert m.CAPTURE_TAIL_S == 5.0
    assert mu.SESSION_GAP_S == 120.0
    # Et les ordres de grandeur qui donnent leur sens aux seuils : la fenetre
    # d'attribution doit rester tres inferieure a la fenetre de nommage, elle
    # meme inferieure au recyclage d'une conversation UDP.
    assert m.DELAY_ATTRIBUTION_WINDOW_S < m.NEW_RESOLUTION_GAP_S < m.NAMING_WINDOW_S
    assert m.CAPTURE_TAIL_S < m.NEW_RESOLUTION_GAP_S


def test_une_capture_longue_ne_dit_plus_qu_elle_s_arrete_trop_tot():
    """`capture_ends_first` etait arme des qu'une fin de capture etait connue -
    toujours, depuis la CLI. Une question muette au debut d'une capture de cinq
    minutes sortait « la capture s'arrete trop tot », avec la preuve « capture
    terminee 300010 ms plus tard » juste en dessous."""
    q_bytes = dns_bytes()
    une = [parse_dns_datagram(0.0, CLIENT, RESOLVER, 5000, 53, q_bytes,
                              len(q_bytes))]
    courte = compute_dns_signals(build_resolutions(une, capture_end=0.5)[0], 0.5)
    longue = compute_dns_signals(build_resolutions(une, capture_end=300.0)[0],
                                 300.0)
    assert courte.capture_ends_first is True
    assert longue.capture_ends_first is False


def test_une_question_muette_sur_une_longue_capture_est_signalee(dns_rules):
    """Le pendant du test precedent : en resserrant `capture_ends_first`, il
    ne faut pas creer un silence a la place. Une question sans reponse pendant
    cinq minutes reste une information."""
    q_bytes = dns_bytes()
    une = [parse_dns_datagram(0.0, CLIENT, RESOLVER, 5000, 53, q_bytes,
                              len(q_bytes))]
    vs = _verdict(une, dns_rules, capture_end=300.0)
    assert vs[0].primary is not None, "le silence du resolveur est passe sous"
    assert vs[0].primary.rule.id == "dns-no-answer"


def test_le_rattachement_choisit_la_resolution_ANTERIEURE_au_flux():
    """Les tests de link_flows n'exercaient jamais plus d'une resolution : ni
    la garde d'anteriorite, ni le choix de la plus recente n'etaient couverts."""
    def rep(ts, adresse):
        r = dns_bytes(response=True, answers=(adresse,))
        return parse_dns_datagram(ts, RESOLVER, CLIENT, 53, 5000, r, len(r))

    def dem(ts):
        q = dns_bytes()
        return parse_dns_datagram(ts, CLIENT, RESOLVER, 5000, 53, q, len(q))

    # Deux resolutions du meme nom : 10.0.0.5 a t=1, puis 10.0.0.6 a t=100.
    msgs = [dem(0.0), rep(1.0, "10.0.0.5"),
            dem(99.0), rep(100.0, "10.0.0.6")]
    res = build_resolutions(msgs, capture_end=200.0)
    assert len(res) == 2
    # Un flux vers .5 parti a t=50 : seule la PREMIERE resolution le precede.
    liens = link_flows(res, [(0, "10.0.0.5", 50.0, CLIENT)])
    assert liens[0].qname == "api.corp.local"
    assert liens[0].explains_delay is False        # 49 s d'ecart
    # Un flux vers .6 parti a t=100.5 : la seconde, et elle explique le delai.
    liens = link_flows(res, [(0, "10.0.0.6", 100.5, CLIENT)])
    assert liens[0].explains_delay is True
    # Un flux vers .6 parti AVANT sa resolution : aucun rattachement possible.
    assert link_flows(res, [(0, "10.0.0.6", 50.0, CLIENT)]) == {}


def test_les_octets_tcp_53_sont_bien_conserves_par_le_lecteur(tmp_path):
    """Seul pont entre un vrai pcap et parse_dns_over_tcp : pcap.py ne garde
    le payload applicatif QUE pour le port 53. Aucun test ne l'exercait -
    remplacer cette expression par b"" laissait la suite verte, alors que
    toutes les resolutions portees par TCP/53 disparaissaient du rapport en
    silence (revue du 15/08/2026)."""
    import struct
    from dpkt.tcp import TH_ACK, TH_PUSH
    from netverdict.pcap import read_capture
    from netverdict.dns import parse_dns_over_tcp, reassemble_stream

    corps = dns_bytes(response=True, answers=("10.9.9.1",))
    flux = struct.pack("!H", len(corps)) + corps

    def seg(ts, sport, dport, seq, charge):
        t = dpkt.tcp.TCP(sport=sport, dport=dport, flags=TH_PUSH | TH_ACK,
                         seq=seq, ack=1, win=65535)
        t.data = charge
        ip = dpkt.ip.IP(src=socket.inet_aton(RESOLVER),
                        dst=socket.inet_aton(CLIENT), p=dpkt.ip.IP_PROTO_TCP,
                        ttl=64, id=1)
        ip.data = t
        ip.len = 20 + len(bytes(t))
        e = dpkt.ethernet.Ethernet(src=b"\x02" * 6, dst=b"\x04" * 6,
                                   type=dpkt.ethernet.ETH_TYPE_IP)
        e.data = ip
        return (ts, bytes(e))

    chemin = tmp_path / "dns-tcp.pcap"
    with open(chemin, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, buf in [seg(0.0, 53, 5000, 1000, flux),
                        # Un segment sur un AUTRE port : son payload ne doit
                        # PAS etre conserve (c'est tout l'interet de la garde).
                        seg(0.1, 443, 5000, 2000, b"X" * 40)]:
            w.writepkt(buf, ts=ts)

    cap = read_capture(chemin)
    par_port = {p.sport: p for p in cap.tcp_packets}
    assert par_port[53].payload == flux, "les octets TCP/53 ont ete perdus"
    assert par_port[443].payload == b"", "un port hors 53 a ete conserve"

    # Et ces octets suffisent bien a reconstituer le message.
    octets, complet = reassemble_stream([(par_port[53].seq,
                                          par_port[53].payload)])
    msgs = parse_dns_over_tcp(0.0, RESOLVER, CLIENT, 53, 5000, octets, complet)
    assert len(msgs) == 1 and msgs[0].over_tcp is True
    assert msgs[0].answers == ["10.9.9.1"]


def test_une_reponse_PARSABLE_mais_tronquee_ne_publie_pas_ses_adresses():
    """Verrou de la garde `if coupe` de parse_dns_datagram.

    Les tests de troncature existants coupent la ou dpkt echoue de toute
    facon : `_read_answers` rend alors ([], False) tout seul, et retirer la
    garde ne cassait rien (revue du 15/08/2026). Le cas dangereux est
    l'inverse - un message que dpkt parse SANS BRONCHER alors qu'il manque des
    octets, ce qui arrive des qu'une section additionnelle (l'OPT record
    d'EDNS0, par exemple) est coupee par le snaplen. Sans la garde, netverdict
    publierait des adresses tirees d'un message incomplet comme si elles
    etaient completes.
    """
    corps = dns_bytes(response=True, answers=("10.0.0.5",))
    # dpkt lit ces octets parfaitement...
    lisible, ok = __import__("netverdict.dns", fromlist=["_read_answers"])._read_answers(corps)
    assert ok is True and lisible == ["10.0.0.5"]
    # ...mais le datagramme d'origine en annoncait davantage.
    m = parse_dns_datagram(1.0, RESOLVER, CLIENT, 53, 5000, corps,
                           declared_len=len(corps) + 40)
    assert m.capture_truncated is True
    assert m.answers == [], "des adresses d'un message incomplet ont ete publiees"
    assert m.answers_readable is False
    # Et la latence, elle, reste juste : c'est tout l'interet du parseur maison.
    assert m.rcode == 0 and m.is_response is True
