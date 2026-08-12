"""Durcissement 2 du 08/08/2026 : les verdicts de LATENCE et de PERTE.

Le durcissement 1 a traite l'etablissement de connexion (rien n'ecoute,
connexion refusee, port recycle, MTU). Restaient les deux familles ou l'outil
chiffre : un percentile, un taux. Ce sont les verdicts les plus credibles du
rapport — un pourcentage se recopie tel quel dans un ticket operateur — et donc
les plus chers quand ils sont faux.

Trois defauts, tous trouves en fabriquant la capture qui piege, puis retrouves
sur les captures kernel du lab :

  1. delayed-ack  — « Latence instable : gigue forte (congestion probable) »,
     RESEAU, sur un flux dont TOUTES les mesures hautes sont des ACK purs, donc
     le timer d'acquittement differe du recepteur. Reproduit tel quel sur
     tests/fixtures/lab/zero_window.pcap, la capture de validation de l'outil :
     une ligne RESEAU s'imprime sous un verdict HOTE, sur un veth sans netem.
  2. rafale       — « Perte de paquets significative sur le chemin », RESEAU,
     confiance haute, taux annonce a la decimale, a partir d'UN SEUL evenement
     de perte. Le plancher de 5 retransmissions comptait des SEGMENTS la ou son
     commentaire dit vouloir compter des EVENEMENTS.
  3. deja-acquitte — la remediation fait lire le SENS des retransmissions comme
     l'endroit de la perte, alors que la capture montre que le recepteur avait
     deja acquitte ces octets : le sens aller a livre, c'est demontre.

Plus une preuve qui ne tient pas l'arithmetique : « 7 retransmissions sur 93
paquets (14,9 %) ». 7/93 = 7,5 %.

Les pcaps sont FABRIQUES ici avec les briques de make_fixtures.py, puis lus par
la vraie chaine read_capture -> build_flows -> compute_signals -> evaluate.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from dpkt.tcp import TH_ACK, TH_FIN, TH_PUSH, TH_SYN
from make_fixtures import CLIENT, SERVER, _handshake, _tcp, write_pcap

from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.rules.engine import evaluate, load_rules
from netverdict.signals import compute_signals

LAB = Path(__file__).parent / "fixtures" / "lab"


@pytest.fixture(scope="module")
def regles():
    return load_rules()


def _analyse(regles, path: Path):
    """(signaux, verdict, ids de TOUS les matches, texte de toutes les preuves).

    TOUS les matches : report.py imprime les suivants en signaux secondaires et
    --json les exporte tous. Une accusation fausse reléguee au second rang reste
    sous les yeux de l'admin — c'est la doctrine posee au durcissement 1.
    """
    flows = build_flows(read_capture(path))
    assert len(flows) == 1, f"{len(flows)} flux, 1 attendu"
    sig = compute_signals(flows[0])
    # lang="fr" explicite : ce fichier verifie le texte francais precis des
    # preuves, pas le defaut de langue de l'outil (DEFAULT_LANG = "en" depuis
    # 0.7.0).
    fv = evaluate([sig], regles, lang="fr")[0]
    ids = [m.rule.id for m in fv.matches]
    preuves = " | ".join(p for m in fv.matches for p in m.evidence)
    return sig, fv, ids, preuves


def _ecrire(path: Path, pkts) -> Path:
    write_pcap(path, pkts)
    return path


# --------------------------------------------------------------------------
# CAS 1 — le timer d'acquittement differe du recepteur, vendu comme congestion
# --------------------------------------------------------------------------

def _abonnement_avec_delayed_ack(cport: int = 53101, sport: int = 8883,
                                 differe_ms: float = 40.0,
                                 queue: int = 0, queue_ms: float = 400.0):
    """Connexion d'ABONNEMENT sur un LAN sain : MQTT subscribe, tail de logs,
    flux de cotations, notifications d'une base. Le client demande une fois,
    puis le serveur pousse un petit enregistrement toutes les 200 ms. Le client
    n'a rien a repondre : chacun de ses acquittements part donc sur le timer de
    delayed ACK de sa pile (40 ms sous Linux, jusqu'a 200 ms sous Windows).

    Le RTT reel du chemin est celui du handshake : 0,4 ms. Rien d'autre dans
    cette capture ne mesure le chemin.

    `differe_ms=0.5` rejoue le meme abonnement avec un client qui acquitte
    immediatement (TCP_QUICKACK) : meme flux, sans le timer.

    `queue=N` ajoute N enregistrements acquittes bien plus tard (`queue_ms`) :
    la queue de latence devient alors REELLE, toujours portee par des ACK purs.
    """
    pkts = _handshake(0.0, cport, sport, cseq=1000, sseq=2000)
    # _handshake pose 1 ms de RTT ; on veut 0,4 ms pour que le contraste avec
    # les 40 ms soit celui du terrain (LAN commute contre timer de pile).
    pkts[1] = _tcp(0.0004, SERVER, CLIENT, sport, cport, TH_SYN | TH_ACK,
                   seq=2000, ack=1001)
    pkts[2] = _tcp(0.0008, CLIENT, SERVER, cport, sport, TH_ACK,
                   seq=1001, ack=2001)
    c, s = 1001, 2001
    sub = b"SUBSCRIBE topic/#"
    pkts.append(_tcp(0.010, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                     seq=c, ack=s, payload=sub))
    c += len(sub)
    # Le serveur accuse ET repond dans le meme segment (piggyback) : mesure
    # propre du chemin cote serveur, 5 ms, tres en dessous du seuil de 20 ms.
    ack = b"SUBACK"
    pkts.append(_tcp(0.015, SERVER, CLIENT, sport, cport, TH_PUSH | TH_ACK,
                     seq=s, ack=c, payload=ack))
    s += len(ack)
    pkts.append(_tcp(0.015 + differe_ms / 1000.0, CLIENT, SERVER, cport, sport,
                     TH_ACK, seq=c, ack=s))
    t = 0.3
    rec = b"{\"t\":1754680000,\"v\":42}"
    for i in range(12 + queue):
        differe = differe_ms if i < 12 else queue_ms
        pkts.append(_tcp(t, SERVER, CLIENT, sport, cport, TH_PUSH | TH_ACK,
                         seq=s, ack=c, payload=rec))
        s += len(rec)
        pkts.append(_tcp(t + differe / 1000.0, CLIENT, SERVER, cport, sport,
                         TH_ACK, seq=c, ack=s))
        t += 0.2 if i < 12 else 0.6
    return pkts


class TestCongestionAnnonceeSurDesAcquittementsDifferes:
    """PREJUDICE : « Latence instable : gigue forte (congestion probable) »,
    RESEAU, priorite 70, sur un LAN dont la capture mesure 0,4 ms de RTT. La
    remediation envoie « croiser l'horaire des pics avec les graphes
    d'utilisation des liens » — c'est-a-dire ouvrir un dossier de congestion
    aupres de l'equipe reseau pour un timer d'acquittement de la pile cliente.

    Le fait mesure n'est meme pas un fait sur le chemin : les seules valeurs qui
    depassent 20 ms sont portees par des ACK PURS, sans une seule donnee. La
    remediation de latency-tail-unexplained NOMME deja cette confusion et
    demande a l'admin d'aller regarder dans la capture « si les RTT longs sont
    portes par des ACK PURS » — une verification que l'outil a toutes les
    donnees pour faire lui-meme, et qu'il ne fait pas.

    Le commentaire de signals.py affirme par ailleurs que seul le p95 est pollue
    par les delayed ACK et que « le p50 et le min restent des mesures propres ».
    Sur ce flux la mediane EST le timer.
    """

    def test_un_timer_de_delayed_ack_ne_prouve_aucune_congestion(
            self, regles, tmp_path):
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "abonnement.pcap",
                            _abonnement_avec_delayed_ack()))

        assert sig.rtt_ms_min is not None and sig.rtt_ms_min < 1.0, (
            "le chemin est mesure a moins d'une milliseconde par le handshake")
        assert sig.rtt_ms_p50 is not None and sig.rtt_ms_p50 >= 20, (
            "le piege est arme : la mediane est le timer du recepteur")
        assert sig.rtt_haut_porte_par_ack_purs, (
            "toutes les mesures au-dessus de 20 ms sont des ACK purs : "
            "la capture ne porte aucune preuve de gigue du chemin")
        assert "rtt-degraded" not in ids, (
            "affirmer RESEAU sur des acquittements differes envoie l'admin "
            "chercher une congestion qui n'existe pas, meme en signal "
            "secondaire")
        assert "congestion" not in preuves.lower()

    def test_le_flux_ressort_pour_ce_qu_il_est_un_transport_sain(
            self, regles, tmp_path):
        """Ne pas mentir ne suffit pas : ce flux doit conclure, sinon l'admin
        retombe sur « tableau incomplet ». La queue est plate (p95 ~ p50), donc
        la bonne reponse est celle que l'outil rend deja pour un WAN stable a
        80 ms : le transport est sain, chercher ailleurs."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "abonnement.pcap",
                            _abonnement_avec_delayed_ack()))
        assert fv.primary.rule.id == "clean"
        assert fv.verdict == "RAS"

    def test_la_meme_conversation_sans_le_timer_est_deja_saine(
            self, regles, tmp_path):
        """La borne qui prouve que c'est bien le timer, et rien d'autre, qui
        fabriquait le verdict : meme flux, client en QUICKACK."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "abonnement_quickack.pcap",
                            _abonnement_avec_delayed_ack(cport=53102,
                                                          differe_ms=0.5)))
        assert not sig.rtt_haut_porte_par_ack_purs
        assert fv.primary.rule.id == "clean"

    def test_une_vraie_gigue_reste_detectee_sur_la_capture_du_lab(self, regles):
        """LE garde-fou. jitter.pcap sort d'un vrai kernel sous netem : c'est la
        seule preuve independante que rtt-degraded fonctionne, et le correctif
        ne doit pas y toucher d'un iota. Il tient parce que la gigue du chemin
        frappe AUSSI les segments de donnees : dans chacun de ces flux, au moins
        une mesure haute est portee par un paquet qui transporte des octets."""
        pcap = LAB / "jitter.pcap"
        if not pcap.exists():
            pytest.skip("pcaps du lab absents")
        sigs = [compute_signals(f) for f in build_flows(read_capture(pcap))]
        ids = [[m.rule.id for m in fv.matches] for fv in evaluate(sigs, regles)]
        assert any("rtt-degraded" in i for i in ids)
        degrades = [s for s in sigs
                    if s.rtt_ms_p50 is not None and s.rtt_ms_p50 >= 20]
        assert degrades, "les flux netem doivent rester au-dessus du seuil"
        assert not any(s.rtt_haut_porte_par_ack_purs for s in degrades), (
            "une gigue reelle retarde aussi les paquets de donnees ; "
            "l'inhibition ne doit jamais s'armer sur ces flux")

    def test_le_reseau_n_est_plus_accuse_sous_un_verdict_HOTE(self, regles):
        """Le defaut se voit aussi sans rien fabriquer, sur la capture de
        validation de l'outil. zero_window.pcap est un veth SANS netem ou le
        serveur n'ouvre jamais sa socket : le verdict juste est HOTE. L'outil
        imprimait dessous une ligne « RESEAU — gigue forte (congestion
        probable) » construite sur cinq ACK purs a 44 ms. Deux verdicts opposes
        sur la meme conversation : l'admin ne peut pas savoir lequel croire, et
        la ligne RESEAU est celle qui declenche un ticket."""
        pcap = LAB / "zero_window.pcap"
        if not pcap.exists():
            pytest.skip("pcaps du lab absents")
        sigs = [compute_signals(f) for f in build_flows(read_capture(pcap))]
        fv = evaluate(sigs, regles)[0]
        ids = [m.rule.id for m in fv.matches]
        assert ids[0] == "zero-window-server"
        assert "rtt-degraded" not in ids
        assert all(m.rule.verdict != "RESEAU" for m in fv.matches)

    def test_une_queue_sur_ack_purs_reste_dite_sans_accuser_le_chemin(
            self, regles, tmp_path):
        """Le trou a ne pas ouvrir. Inhiber rtt-degraded sans rien mettre a la
        place ferait disparaitre du rapport tout flux a mediane haute ET queue
        reelle : `clean` ne le rattrape pas (il exige une queue plate) et
        latency-tail-unexplained non plus (il exige une mediane saine). Ici la
        moitie des acquittements part sur le timer et l'autre sur un timer bien
        plus long : il y a une vraie queue, et la capture ne sait toujours pas
        dire de quoi."""
        # Trois enregistrements de plus, acquittes 400 ms plus tard : la queue
        # devient reelle (p95 largement au-dessus du double de la mediane).
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "abonnement_queue.pcap",
                            _abonnement_avec_delayed_ack(cport=53103, queue=3)))

        assert sig.rtt_ratio_p95_p50 is not None and sig.rtt_ratio_p95_p50 >= 2
        assert "rtt-degraded" not in ids
        assert "clean" not in ids, "une queue de latence n'est pas un flux sain"
        assert fv.primary.rule.id == "latence-mesuree-sur-ack-purs"
        assert fv.verdict == "AMBIGU"
        assert fv.primary.rule.confidence == "faible"
        assert "delayed ACK" in fv.primary.remediation

    def test_la_preuve_de_latence_dit_sur_combien_de_mesures_elle_repose(
            self, regles, tmp_path):
        """« sur 25 paquets » laissait croire a 25 mesures. Un flux de 25
        paquets peut ne porter que 4 echantillons de RTT — c'est le cas de tous
        les flux du lab. Le nombre de mesures est ce qui dit a l'admin combien
        vaut le percentile qu'on lui montre."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "abonnement_mesures.pcap",
                            _abonnement_avec_delayed_ack(cport=53104, queue=3)))
        assert sig.pkts_total == 36
        assert sig.rtt_samples == 18, (
            "36 paquets, 18 mesures : la preuve doit citer les mesures, pas "
            "les paquets")
        assert f"{sig.rtt_samples} mesures" in preuves

    def test_un_rapport_de_latence_ne_se_calcule_pas_contre_une_microseconde(
            self, regles):
        """« x46398 » : cinq chiffres significatifs obtenus en divisant par un
        minimum de 0,00095 ms. Le meme defaut avait deja ete corrige sur
        rtt_ratio_p95_p50 (plancher de 1 ms) ; les deux autres rapports
        l'avaient garde, et c'est l'un d'eux que la preuve imprime."""
        pcap = LAB / "zero_window.pcap"
        if not pcap.exists():
            pytest.skip("pcaps du lab absents")
        s = [compute_signals(f) for f in build_flows(read_capture(pcap))][0]
        assert s.rtt_ms_min is not None and s.rtt_ms_min < 0.01
        assert s.rtt_ratio_p95_min is not None and s.rtt_ratio_p95_min < 100, (
            f"x{s.rtt_ratio_p95_min:.0f} : rapport fabrique sur un minimum de "
            f"{s.rtt_ms_min:.5f} ms")
        assert s.rtt_ratio_p50_min is not None and s.rtt_ratio_p50_min < 100


# --------------------------------------------------------------------------
# CAS 2 — un seul evenement de perte, annonce comme un taux
# --------------------------------------------------------------------------

def _rafale_unique(cport: int = 53201, n_perdus: int = 7):
    """Televersement sain de 40 segments a travers un lien qui hoquette UNE
    fois : une file qui deborde, un basculement de trunk, un roaming Wi-Fi. La
    fenetre en vol — 7 segments — n'est pas acquittee et repart d'un bloc au
    RTO. Ensuite tout reprend et la session se ferme par FIN.

    UN evenement de perte. Pas 7.
    """
    pkts = _handshake(0.0, cport, 443)
    c, s, t = 1001, 2001, 0.01
    emis: list[int] = []

    def seg(ts, seq):
        return _tcp(ts, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                    seq=seq, ack=s, payload=b"u" * 1000)

    for i in range(40):
        pkts.append(seg(t, c))
        emis.append(c)
        c += 1000
        if not (20 <= i < 20 + n_perdus):
            pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 443, cport, TH_ACK,
                             seq=s, ack=c))
        t += 0.01
        if i == 20 + n_perdus - 1:
            for k, sq in enumerate(emis[20:20 + n_perdus]):
                pkts.append(seg(t + k * 0.0005, sq))
            t += 0.02
            pkts.append(_tcp(t, SERVER, CLIENT, 443, cport, TH_ACK,
                             seq=s, ack=c))
    pkts.append(_tcp(t + 0.01, CLIENT, SERVER, cport, 443, TH_FIN | TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.011, SERVER, CLIENT, 443, cport, TH_FIN | TH_ACK,
                     seq=s, ack=c + 1))
    pkts.append(_tcp(t + 0.012, CLIENT, SERVER, cport, 443, TH_ACK,
                     seq=c + 1, ack=s + 1))
    return pkts


class TestUnSeulEvenementDePerteVenduCommeUnTaux:
    """PREJUDICE : « Perte de paquets significative sur le chemin », RESEAU,
    confiance haute, « 14,9 % ». La remediation prescrit, dans l'ordre : relever
    l'utilisation des interfaces, lire les compteurs CRC des switchs du chemin,
    chercher un duplex mismatch, changer un cable ou un SFP, suspecter le Wi-Fi,
    regarder le CPU du firewall. Une demi-journee de travail, et un chiffre —
    « 14,9 % de perte » — qui se recopie tel quel dans un ticket operateur.

    Ce que la capture montre : UN hoquet. Sept segments en vol au meme instant
    n'ont pas ete acquittes, ils sont repartis ensemble au RTO, et le
    televersement s'est termine normalement. Sept segments perdus d'un coup,
    c'est UNE mesure du chemin, pas sept. Un taux tire d'un seul evenement n'a
    pas d'intervalle de confiance : il n'est pas faux, il n'a pas de sens.

    Le commentaire de la regle dit d'ailleurs exactement ce qu'il fallait
    faire : « le plancher de 5 retrans evite de flagger 1 perte isolee sur un
    petit flux ». Il compte des SEGMENTS ; une perte isolee en emporte autant
    qu'il y en avait en vol.
    """

    def test_sept_segments_perdus_au_meme_instant_font_un_evenement(
            self, regles, tmp_path):
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "rafale.pcap", _rafale_unique()))

        assert sig.retrans_total == 7
        assert sig.retrans_events == 1, (
            "une salve de renvois sans la moindre donnee neuve entre eux est "
            "UN episode de perte")
        assert sig.perte_evenement_unique

    def test_le_reseau_n_est_pas_accuse_avec_confiance_sur_un_hoquet(
            self, regles, tmp_path):
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "rafale.pcap", _rafale_unique()))

        assert "retrans-heavy" not in ids, (
            "un taux de perte annonce a la decimale sur un seul evenement "
            "envoie changer des cables et ouvrir un ticket operateur")
        assert "CRC" not in preuves and "SFP" not in preuves

    def test_le_hoquet_reste_dit_sans_extrapoler_un_taux(self, regles, tmp_path):
        """Se taire serait l'autre faute : sept segments ont bel et bien ete
        perdus, a un instant date, et si l'utilisateur s'est plaint a cette
        seconde-la c'est la piste. Ce qui doit disparaitre, c'est le taux et la
        confiance haute."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "rafale.pcap", _rafale_unique()))

        assert fv.primary.rule.id == "perte-rafale-unique"
        assert fv.verdict == "AMBIGU"
        assert fv.primary.rule.confidence == "faible"
        assert "7" in preuves
        assert "capture plus longue" in fv.primary.remediation

    def test_une_perte_repetee_reste_un_verdict_reseau_confiant(
            self, regles, tmp_path):
        """LE garde-fou : la meme capture, mais le lien hoquette CINQ fois. La
        difference entre les deux n'est pas le nombre de segments — c'est le
        nombre de fois ou le chemin a fait defaut. La, un taux a un sens."""
        pkts = _handshake(0.0, 53202, 443)
        c, s, t = 1001, 2001, 0.01
        emis: list[int] = []
        for i in range(40):
            pkts.append(_tcp(t, CLIENT, SERVER, 53202, 443, TH_PUSH | TH_ACK,
                             seq=c, ack=s, payload=b"u" * 1000))
            emis.append(c)
            c += 1000
            pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 443, 53202, TH_ACK,
                             seq=s, ack=c))
            t += 0.01
            if i % 7 == 6 and i < 36:      # cinq hoquets independants
                for k in range(2):
                    pkts.append(_tcp(t + k * 0.0005, CLIENT, SERVER, 53202, 443,
                                     TH_PUSH | TH_ACK, seq=emis[i - 1 - k],
                                     ack=s, payload=b"u" * 1000))
                t += 0.02
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "cinq_hoquets.pcap", pkts))

        assert sig.retrans_events == 5
        assert not sig.perte_evenement_unique
        assert fv.primary.rule.id == "retrans-heavy"
        assert fv.primary.rule.confidence == "haute"

    def test_la_capture_kernel_du_lab_reste_un_verdict_reseau(self, regles):
        """L'autre garde-fou, et le seul qui ne vienne pas de nous : loss.pcap
        est un televersement de 2 Mo a travers 8 % de perte netem reelle. Le
        correctif ne doit rien y changer."""
        pcap = LAB / "loss.pcap"
        if not pcap.exists():
            pytest.skip("pcaps du lab absents")
        sigs = [compute_signals(f) for f in build_flows(read_capture(pcap))]
        s = max(sigs, key=lambda x: x.retrans_total)
        assert s.retrans_events > 20, (
            "8 % de perte aleatoire produisent des dizaines d'episodes")
        assert not s.perte_evenement_unique
        ids = [m.rule.id for fv in evaluate(sigs, regles) for m in fv.matches]
        assert "retrans-heavy" in ids


# --------------------------------------------------------------------------
# CAS 3 — le sens des retransmissions lu comme l'endroit de la perte
# --------------------------------------------------------------------------

def _renvois_deja_acquittes(cport: int = 53301):
    """Le serveur ACQUITTE chaque segment — la capture le montre — et le client
    les renvoie quand meme. Cas de terrain : les acquittements se perdent sur le
    chemin de RETOUR (routage asymetrique, brin de collecte different), ou le
    RTO de l'emetteur est trop court apres un pic de latence (timeout spurieux,
    RFC 3522). Dans les deux cas, le sens client -> serveur a LIVRE, et la
    capture le prouve segment par segment.
    """
    pkts = _handshake(0.0, cport, 443)
    c, s, t = 1001, 2001, 0.01
    emis: list[int] = []
    for i in range(30):
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=b"v" * 1000))
        emis.append(c)
        c += 1000
        pkts.append(_tcp(t + 0.003, SERVER, CLIENT, 443, cport, TH_ACK,
                         seq=s, ack=c))
        t += 0.02
        if i % 4 == 3:
            pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                             seq=emis[i - 1], ack=s, payload=b"v" * 1000))
            t += 0.02
    return pkts


class TestSensDeLaPerteAffirmeContreLaCapture:
    """PREJUDICE : la remediation de retrans-heavy dit « Le sens des
    retransmissions dit ou chercher (c2s = perte vers le serveur, s2c = perte
    vers le client) », puis liste les compteurs a relever. Sur cette capture
    elle affiche « c2s : 7 » et envoie donc chercher la perte sur le chemin
    ALLER — celui dont la capture montre, sept fois, que le serveur a acquitte
    les octets. S'il y a une perte, elle est sur le chemin de RETOUR, ou il n'y
    en a pas du tout (RTO trop court).

    Ce n'est pas un detail de redaction : c'est la seule phrase du rapport qui
    dise a l'admin de quel cote du reseau regarder, et elle designe le mauvais.

    La regle elle-meme reste juste — des renvois repetes sont anormaux — et
    aucun verdict n'est retire ici. Ce qui est corrige, c'est une affirmation
    que la capture contredit. C'est aussi le cas de la fixture historique
    retrans_heavy.pcap, dont les six retransmissions portent toutes des octets
    deja acquittes : l'outil livrait « perte vers le serveur » sur sa propre
    capture de reference.
    """

    def test_la_capture_prouve_que_le_sens_aller_a_livre(self, regles, tmp_path):
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "deja_acquittes.pcap",
                            _renvois_deja_acquittes()))

        assert sig.retrans_total == 7
        assert sig.retrans_deja_acquittees == 7, (
            "le serveur avait acquitte ces octets AVANT chaque renvoi : "
            "la capture prouve que le sens aller a livre")

    def test_le_rapport_ne_designe_plus_le_mauvais_cote_du_reseau(
            self, regles, tmp_path):
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "deja_acquittes.pcap",
                            _renvois_deja_acquittes()))

        m = next(m for m in fv.matches if m.rule.id == "retrans-heavy")
        assert "7" in " ".join(m.evidence) and "acquitt" in " ".join(m.evidence)
        assert "deja acquittes" in m.remediation, (
            "la remediation doit porter la contradiction, sinon l'admin lit "
            "« c2s » et part sur le chemin aller")

    def test_une_perte_reelle_garde_sa_lecture_de_sens(self, regles, tmp_path):
        """Le garde-fou : quand le recepteur n'avait PAS acquitte, le sens des
        retransmissions reste ce qu'il a toujours ete — l'indication la plus
        utile du rapport. Elle ne doit pas etre noyee sous une reserve."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "cinq_hoquets_2.pcap",
                            _perte_reelle_repetee()))
        assert sig.retrans_deja_acquittees == 0
        assert fv.primary.rule.id == "retrans-heavy"

    def test_la_preuve_de_perte_tient_l_arithmetique(self, regles, tmp_path):
        """« 7 retransmissions sur 93 paquets (14,9 %) » : 7/93 = 7,5 %. Le taux
        se calcule sur les segments de DONNEES, le denominateur affiche comptait
        tous les paquets, acquittements compris. Un admin qui verifie le calcul
        — et c'est le premier reflexe devant un chiffre qu'on va recopier dans
        un ticket — trouve deux nombres qui ne se repondent pas et perd
        confiance dans tout le rapport."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "cinq_hoquets_3.pcap",
                            _perte_reelle_repetee(cport=53303)))
        m = next(m for m in fv.matches if m.rule.id == "retrans-heavy")
        ligne = m.evidence[0]

        assert sig.retrans_base == (sig.data_pkts_c2s + sig.data_pkts_s2c
                                    + sig.retrans_total)
        assert str(sig.retrans_base) in ligne
        assert str(sig.pkts_total) not in ligne, (
            "le denominateur affiche doit etre celui du taux affiche")
        taux = sig.retrans_total / sig.retrans_base
        assert f"{taux:.1%}".replace(".", ",") in ligne.replace(".", ",")


def _perte_reelle_repetee(cport: int = 53302):
    """Cinq hoquets independants, et le recepteur n'a jamais acquitte les
    segments perdus : la lecture par sens est legitime."""
    pkts = _handshake(0.0, cport, 443)
    c, s, t = 1001, 2001, 0.01
    emis: list[int] = []
    for i in range(40):
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=b"w" * 1000))
        emis.append(c)
        c += 1000
        # Le serveur n'acquitte QUE jusqu'au segment precedent : les deux
        # derniers restent non acquittes au moment du renvoi.
        pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 443, cport, TH_ACK,
                         seq=s, ack=max(2001, emis[max(0, i - 2)])))
        t += 0.01
        if i % 7 == 6 and i < 36:
            for k in range(2):
                pkts.append(_tcp(t + k * 0.0005, CLIENT, SERVER, cport, 443,
                                 TH_PUSH | TH_ACK, seq=emis[i - 1 - k],
                                 ack=s, payload=b"w" * 1000))
            t += 0.02
    pkts.append(_tcp(t + 0.01, SERVER, CLIENT, 443, cport, TH_ACK, seq=s, ack=c))
    return pkts
