"""Non-regression des VERDICTS et PREUVES FAUX trouves en revue le 25/07/2026.

Ces cinq defauts partagent une propriete : ils ne plantent pas, ils MENTENT.
L'outil rendait un verdict confiant et faux, ou une preuve contredite par le
pcap qu'il venait de lire. C'est la pire panne possible pour un outil dont la
promesse est « avec les preuves ».

Les signaux sont construits A LA MAIN et passes au VRAI moteur de regles
(load_rules + evaluate) : on teste les regles livrees, pas une imitation.
Chaque test doit ECHOUER si l'on retablit l'ancien comportement — verifie par
mutation lors de l'ecriture.
"""

from __future__ import annotations

import pytest
from dpkt.tcp import TH_ACK, TH_PUSH
from make_fixtures import CLIENT, SERVER, _handshake, _tcp, write_pcap

from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.rules.engine import evaluate, load_rules
from netverdict.signals import FlowSignals, compute_signals


@pytest.fixture(scope="module")
def regles():
    return load_rules()


def _verdict(regles, **champs):
    """(id primaire, tous les ids, tout le texte de preuve) pour ces signaux.

    On regarde TOUS les matches, pas seulement le primaire : report.py:209
    affiche les suivants en lignes secondaires et la sortie JSON les exporte
    tous avec leurs preuves. Une accusation fausse reléguée en secondaire
    reste sous les yeux de l'admin — donc reste un defaut.
    """
    sig = FlowSignals(client="10.0.0.42", server="10.0.0.5", cport=51001,
                      sport=443, **champs)
    fv = evaluate([sig], regles)[0]
    ids = [m.rule.id for m in fv.matches]
    preuves = " | ".join(p for m in fv.matches for p in m.evidence)
    return (ids[0] if ids else None), ids, preuves


class TestVerdictReseauFabrique:
    """rtt-degraded concluait « congestion » a partir d'un p95 pollue par les
    delayed ACK — un verdict RESEAU sur un probleme purement applicatif."""

    def test_des_delayed_ack_ne_produisent_plus_un_verdict_reseau(self, regles):
        # Signature d'un flux applicatif lent sur un reseau SAIN : le vrai RTT
        # est sub-milliseconde, seuls quelques ACK differes gonflent le p95.
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=0.4, rtt_ms_p50=0.5, rtt_ms_p95=180.0,
            rtt_ratio_p95_min=450.0, rtt_ratio_p50_min=1.25,
        )
        assert rid != "rtt-degraded", (
            "un p95 pollue par les delayed ACK ne doit plus faire conclure au reseau")

    def test_un_LAN_sain_ne_matche_pas_malgre_un_ratio_enorme(self, regles):
        # Mesure reelle sur tests/fixtures/lab/clean.pcap : ratio 62, et
        # pourtant tout est sain — le minimum sub-milliseconde fait exploser
        # n'importe quel rapport. C'est pour ca que le ratio SEUL ne suffit pas.
        rid, ids, preuves = _verdict(
            regles, pkts_total=120, handshake_complete=True,
            rtt_ms_min=0.014, rtt_ms_p50=0.9, rtt_ms_p95=0.9,
            rtt_ratio_p50_min=62.8, rtt_ratio_p95_min=64.5,
        )
        assert rid != "rtt-degraded"

    def test_une_vraie_gigue_est_TOUJOURS_detectee(self, regles):
        # Valeurs mesurees sur tests/fixtures/lab/jitter.pcap (netem, vrai
        # kernel) : mediane a 31.9 ms et AUCUNE perte. Un correctif qui
        # exigerait une corroboration par retransmission raterait ce cas —
        # essaye et abandonne le 25/07, mesure en main.
        rid, ids, preuves = _verdict(
            regles, pkts_total=90, handshake_complete=True,
            rtt_ms_min=0.058, rtt_ms_p50=31.9, rtt_ms_p95=32.2,
            rtt_ratio_p50_min=549.8, rtt_ratio_p95_min=555.6,
            retrans_total=0, dup_ack_bursts_from_client=0,
        )
        assert rid == "rtt-degraded"


class TestFauxToutVaBien:
    """Trouve le 25/07/2026 EN VERIFIANT le correctif de rtt-degraded, pas en
    revue : la regle `clean` ne regardait aucune mesure de latence, donc un flux
    a mediane 15 ms et p95 400 ms sortait « Transport sain ». Un faux « tout va
    bien » est la panne la plus couteuse d'un outil de diagnostic — elle envoie
    l'admin chercher ailleurs et rien ne l'invite a revenir.

    Le correctif de la mediane avait d'ailleurs cree la moitie du defaut :
    il a ferme un faux positif et ouvert ce faux negatif, silencieux."""

    def test_une_queue_de_latence_n_est_jamais_declaree_saine(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=0.5, rtt_ms_p50=15.0, rtt_ms_p95=400.0,
            rtt_ratio_p50_min=30.0, rtt_ratio_p95_min=800.0,
            rtt_ratio_p95_p50=26.7,
        )
        assert "clean" not in ids, "x27 entre la mediane et le p95 n'est pas sain"
        assert rid == "latency-tail-unexplained"
        assert "400" in preuves and "15" in preuves

    def test_le_verdict_reste_AMBIGU_car_la_capture_ne_tranche_pas(self, regles):
        """Ni RESEAU ni APP : une mediane saine avec un p95 eleve est produite
        AUSSI BIEN par la gigue du chemin que par le delayed ACK du recepteur,
        et rien dans le pcap ne les separe. Affirmer « reseau » serait juste une
        fois sur deux — c'est exactement le faux verdict corrige plus haut."""
        sig = FlowSignals(client="10.0.0.42", server="10.0.0.5", cport=51001,
                          sport=443, pkts_total=200, handshake_complete=True,
                          rtt_ms_min=0.4, rtt_ms_p50=0.5, rtt_ms_p95=180.0,
                          rtt_ratio_p50_min=1.25, rtt_ratio_p95_min=450.0,
                          rtt_ratio_p95_p50=180.0)
        m = evaluate([sig], regles)[0].primary
        assert m.verdict == "AMBIGU"
        assert m.rule.confidence == "faible"
        # La remediation doit NOMMER les deux causes et donner de quoi trancher,
        # sinon « ambigu » n'est qu'un aveu d'impuissance.
        assert "delayed ACK" in m.rule.remediation
        assert "ping" in m.rule.remediation

    def test_un_WAN_stable_a_80ms_reste_sain(self, regles):
        """Le garde-fou du correctif : une latence uniformement elevee n'est pas
        une panne. netverdict ne connait aucune baseline attendue, donc juger
        le p95 en absolu SANS la forme de la queue condamnerait tout WAN."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=78.0, rtt_ms_p50=80.0, rtt_ms_p95=82.0,
            rtt_ratio_p50_min=1.03, rtt_ratio_p95_min=1.05,
            rtt_ratio_p95_p50=1.03,
        )
        assert rid == "clean"

    def test_un_LAN_sain_reste_sain_malgre_un_rapport_eleve(self, regles):
        """L'autre garde-fou : sous la milliseconde, un rapport ne veut rien
        dire. clean.pcap atteint x64 en etant parfaitement sain."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=0.014, rtt_ms_p50=0.88, rtt_ms_p95=0.91,
            rtt_ratio_p50_min=62.8, rtt_ratio_p95_min=64.5,
            rtt_ratio_p95_p50=0.91,
        )
        assert rid == "clean"

    def test_un_hoquet_sous_le_seuil_absolu_reste_sain(self, regles):
        """Mediane 2 ms, pointe a 19 ms : x9,5 mais sous les 20 ms que le lab
        designe comme frontiere des deux familles. Ce flux DOIT rester sain —
        sans la branche en p95 absolu il tomberait en AMBIGU, ce qui rendrait
        l'outil bavard sur des LAN parfaitement utilisables."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=1.8, rtt_ms_p50=2.0, rtt_ms_p95=19.0,
            rtt_ratio_p50_min=1.1, rtt_ratio_p95_min=10.5,
            rtt_ratio_p95_p50=9.5,
        )
        assert rid == "clean"

    def test_un_plateau_juste_au_dessus_du_seuil_reste_sain(self, regles):
        """Mediane 19,9 ms et p95 20 ms : le seuil ABSOLU est franchi, mais il
        n'y a aucun pic — c'est un lien lent et regulier. Voila ce que la garde
        de forme protege reellement (et non le WAN a 80 ms, deja exclu par la
        condition sur la mediane : rationnel corrige par la mesure)."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=19.5, rtt_ms_p50=19.9, rtt_ms_p95=20.0,
            rtt_ratio_p50_min=1.02, rtt_ratio_p95_min=1.03,
            rtt_ratio_p95_p50=1.01,
        )
        assert rid == "clean"

    def test_une_queue_de_60ms_sur_une_mediane_de_15ms_n_est_pas_saine(self, regles):
        """Le seuil de forme etait a 5 : ce flux sortait x4, donc « sain ».
        Mesure du 25/07 — un p95 quadruple de la mediane ET quatre fois le seuil
        absolu est une queue, pas du bruit. Seuil ramene a 2."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            rtt_ms_min=13.0, rtt_ms_p50=15.0, rtt_ms_p95=60.0,
            rtt_ratio_p50_min=1.15, rtt_ratio_p95_min=4.6,
            rtt_ratio_p95_p50=4.0,
        )
        assert "clean" not in ids
        assert rid == "latency-tail-unexplained"

    def test_le_signal_de_forme_ne_fabrique_pas_de_precision(self):
        """Les tests ci-dessus passent rtt_ratio_p95_p50 A LA MAIN : ils
        valident les regles, pas le CALCUL. Ici on le calcule sur le vrai pcap
        netem. Sans le plancher a 1 ms, le flux a mediane 0,11 ms afficherait
        « x475 » — un chiffre a trois chiffres significatifs tire d'un rapport
        entre deux mesures dont l'une est sous la resolution utile."""
        from pathlib import Path

        pcap = Path(__file__).parent / "fixtures" / "lab" / "jitter.pcap"
        sigs = [compute_signals(f) for f in build_flows(read_capture(pcap))]
        cible = [s for s in sigs
                 if s.rtt_ms_p50 is not None and s.rtt_ms_p50 < 1.0
                 and s.rtt_ms_p95 is not None and s.rtt_ms_p95 > 20.0]
        assert cible, "le flux a mediane sub-ms et p95 de 52 ms doit exister"
        s = cible[0]
        # Le rapport se lit contre 1 ms, pas contre la mediane brute.
        assert s.rtt_ratio_p95_p50 == pytest.approx(s.rtt_ms_p95, rel=1e-6)
        assert s.rtt_ratio_p95_p50 < 100, (
            f"x{s.rtt_ratio_p95_p50:.0f} : rapport fabrique sur une mediane "
            f"de {s.rtt_ms_p50:.2f} ms")

    def test_le_rapport_n_affiche_pas_sain_sous_un_verdict_de_panne(self, regles):
        """`clean` peut legitimement matcher en secondaire (les pathologies
        qu'il teste sont bien absentes), mais son titre affirme « le probleme
        n'est pas dans cette conversation reseau ». Imprime sous un verdict
        RESEAU, l'admin ne peut pas savoir quelle ligne croire."""
        import io
        from pathlib import Path

        from rich.console import Console

        from netverdict.report import render_console

        # Sur le VRAI pcap netem, pas sur des signaux fabriques : c'est la que
        # le cas a ete observe, et cela teste la chaine de rendu complete.
        pcap = Path(__file__).parent / "fixtures" / "lab" / "jitter.pcap"
        cap = read_capture(pcap)
        verdicts = evaluate([compute_signals(f) for f in build_flows(cap)], regles)
        assert any([m.rule.id for m in fv.matches] == ["rtt-degraded", "clean"]
                   for fv in verdicts), "les deux regles matchent vraiment ici"
        assert all(fv.verdict != "RAS" for fv in verdicts), (
            "aucun flux de cette capture n'est sain : 'clean' ne doit pas "
            "apparaitre du tout dans le rapport")

        con = Console(file=io.StringIO(), width=200, no_color=True)
        render_console(cap, verdicts, top=99, console=con)
        sortie = con.file.getvalue()
        assert "gigue forte" in sortie, "le vrai diagnostic doit rester affiche"
        # Le panneau n'imprime les identifiants de regle QUE dans la ligne des
        # signaux secondaires : y trouver « clean » signifie exactement que la
        # ligne fautive est revenue.
        assert "clean" not in sortie, (
            "'clean' ne doit jamais s'imprimer sous un verdict de panne : son "
            "titre affirme le contraire du verdict")


class TestTrouDuSlowApp:
    """Un ACK a 60 ms face a une reponse a 900 ms ne matchait AUCUNE regle :
    le flux ressortait « anodin, trop peu de trafic pour juger »."""

    def test_ack_60ms_et_reponse_900ms_est_bien_un_probleme_applicatif(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=40, handshake_complete=True, exchanges=6,
            ttfb_ms_p50=880.0, ttfb_ms_p95=900.0,
            server_ack_delay_ms_p95=60.0, ttfb_over_ack_ratio=15.0,
            retrans_rate=0.0,
        )
        assert rid == "slow-app-proven", (
            "15x plus lent que l'acquittement prouve que le delai est dans le serveur")
        assert "900" in preuves and "60" in preuves

    def test_le_cas_historique_ack_rapide_reste_couvert(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=40, handshake_complete=True, exchanges=3,
            ttfb_ms_p50=800.0, ttfb_ms_p95=820.0,
            server_ack_delay_ms_p95=5.0, ttfb_over_ack_ratio=164.0,
            retrans_rate=0.0,
        )
        assert rid == "slow-app-proven"

    def test_un_serveur_aussi_lent_a_ACQUITTER_n_est_pas_ce_cas(self, regles):
        """Si l'ACK est aussi lent que la reponse, la preuve « le reseau a
        livre puis on a attendu l'app » ne tient plus : ce n'est pas ce
        diagnostic, et la regle doit se taire plutot que d'affirmer."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=40, handshake_complete=True, exchanges=3,
            ttfb_ms_p50=600.0, ttfb_ms_p95=620.0,
            server_ack_delay_ms_p95=400.0, ttfb_over_ack_ratio=1.55,
            retrans_rate=0.0,
        )
        assert rid != "slow-app-proven"


class TestPreuveContredteParLePcap:
    """syn-no-answer imprimait « aucun ICMP » alors que des ICMP unreachable
    etaient rattaches au flux : le rapport contredisait sa propre mesure."""

    def test_avec_ICMP_unreachable_la_preuve_ne_dit_plus_aucun_ICMP(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=6, syn_count=3, syn_span_s=7.1,
            synack_seen=False, rst_to_syn=False, icmp_unreach_count=2,
        )
        assert rid == "syn-no-answer-icmp-unreach"
        assert "2 ICMP unreachable" in preuves
        # Sur TOUT le rapport, pas seulement la ligne principale : reléguer
        # « aucun ICMP » en match secondaire ne le rend pas moins faux, et
        # report.py comme la sortie JSON l'affichent quand meme.
        assert "aucun ICMP" not in preuves
        assert "syn-no-answer" not in ids, (
            "la regle qui affirme « aucun ICMP » ne doit meme pas matcher ici")

    def test_sans_ICMP_le_diagnostic_de_silence_est_inchange(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=6, syn_count=3, syn_span_s=7.1,
            synack_seen=False, rst_to_syn=False, icmp_unreach_count=0,
        )
        assert rid == "syn-no-answer"
        assert "aucun ICMP" in preuves

    def test_un_REJECT_explicite_reste_prioritaire(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=6, syn_count=3, synack_seen=False,
            rst_to_syn=False, icmp_unreach_count=2,
            icmp_admin_prohibited=True,
            icmp_admin_prohibited_from="192.168.1.1",
        )
        assert rid == "reject-icmp"


class TestMauvaisHoteAccuse:
    """zw_max_ms etait global aux deux sens : quand client ET serveur
    annoncaient du zero-window, zero-window-server s'attribuait la duree du
    CLIENT et accusait le mauvais hote avec une preuve fausse."""

    def test_le_serveur_n_est_pas_accuse_pour_la_fenetre_du_client(self, regles):
        # Le client sature 800 ms ; le serveur n'a qu'une annonce fugace.
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            zw_from_client=5, zw_from_server=1,
            zw_max_ms=800.0, zw_total_ms=900.0,          # agregats
            zw_max_ms_from_client=800.0, zw_total_ms_from_client=880.0,
            zw_max_ms_from_server=20.0, zw_total_ms_from_server=20.0,
        )
        assert "zero-window-server" not in ids, (
            "20 ms cote serveur ne justifient pas de l'accuser")
        assert rid == "zero-window-client"
        assert "800" in preuves, "la duree affichee doit etre celle du client"

    def test_le_client_n_est_pas_accuse_pour_la_fenetre_du_serveur(self, regles):
        """Le symetrique. Il ne se voit PAS dans le verdict principal (la regle
        serveur a la priorite la plus haute et gagne de toute facon) : la
        fausse accusation sort en ligne secondaire. C'est pour ca que le test
        regarde tous les matches."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            zw_from_client=1, zw_from_server=5,
            zw_max_ms=800.0, zw_total_ms=900.0,
            zw_max_ms_from_client=20.0, zw_total_ms_from_client=20.0,
            zw_max_ms_from_server=800.0, zw_total_ms_from_server=880.0,
        )
        assert rid == "zero-window-server"
        assert "zero-window-client" not in ids

    # Les deux sens, parce que l'asymetrie est ce qui rend le bug visible :
    # quand les valeurs coincident, l'agregat et le cote sont indiscernables
    # et un test « qui passe » ne prouve rien.
    @pytest.mark.parametrize("cli_ms,srv_ms", [(950.0, 300.0), (300.0, 950.0)])
    def test_quand_les_DEUX_calent_chaque_ligne_porte_sa_propre_duree(
            self, regles, cli_ms, srv_ms):
        """Les deux hotes calent reellement : les deux regles DOIVENT matcher,
        c'est correct. Ce qui doit rester vrai, c'est le CHIFFRE de chaque
        ligne. Le gabarit interpolait l'agregat, donc la ligne du serveur
        pouvait annoncer la duree du client : une preuve fausse sous un verdict
        juste — le pire cas, parce que rien n'invite a la relire."""
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            zw_from_client=3, zw_from_server=2,
            zw_max_ms=max(cli_ms, srv_ms), zw_total_ms=1250.0,   # agregats
            zw_max_ms_from_client=cli_ms, zw_total_ms_from_client=cli_ms,
            zw_max_ms_from_server=srv_ms, zw_total_ms_from_server=srv_ms,
        )
        assert ids[:2] == ["zero-window-server", "zero-window-client"]
        lignes = preuves.split(" | ")
        ligne_srv = next(l for l in lignes if "10.0.0.5," in l)
        ligne_cli = next(l for l in lignes if "10.0.0.42," in l)

        assert f"{srv_ms:.0f}" in ligne_srv
        assert f"{cli_ms:.0f}" not in ligne_srv, (
            "la ligne du serveur affiche la duree du client")
        assert "1250" not in ligne_srv, (
            "le cumul de la ligne serveur doit etre celui du serveur seul")

        assert f"{cli_ms:.0f}" in ligne_cli
        assert f"{srv_ms:.0f}" not in ligne_cli, (
            "la ligne du client affiche la duree du serveur")

    def test_un_serveur_reellement_sature_est_bien_accuse(self, regles):
        rid, ids, preuves = _verdict(
            regles, pkts_total=200, handshake_complete=True,
            zw_from_client=0, zw_from_server=4,
            zw_max_ms=650.0, zw_total_ms=700.0,
            zw_max_ms_from_server=650.0, zw_total_ms_from_server=700.0,
        )
        assert rid == "zero-window-server"
        assert "650" in preuves and "700" in preuves


class TestRetransmissionsPerdues:
    """Un fast retransmit arrivant en moins de 3 ms etait classe
    « reordonnancement de capture » et jamais compte : sur un LAN en emission
    continue, le flux perdait TOUTES ses retransmissions."""

    def test_un_renvoi_rapide_apres_dup_ack_est_compte_comme_retransmission(
            self, tmp_path):
        # Fast retransmit du manuel : un trou dans la sequence, les segments
        # suivants arrivent quand meme, le recepteur re-acquitte le bord du
        # trou, l'emetteur renvoie sans attendre le RTO.
        pkts = list(_handshake(0.0, 51001, 443))
        sseq, cseq = 2001, 1001       # etat laisse par _handshake
        srv = lambda t, seq: _tcp(t, SERVER, CLIENT, 443, 51001,
                                  TH_ACK | TH_PUSH, seq=seq, ack=cseq,
                                  payload=b"x" * 100)
        # Fenetre annoncee CONSTANTE : un dup-ACK se distingue d'un window
        # update par la fenetre inchangee, c'est ce que le detecteur exige.
        cli = lambda t, ack: _tcp(t, CLIENT, SERVER, 51001, 443, TH_ACK,
                                  seq=cseq, ack=ack, win=65535)

        pkts += [srv(0.020, sseq),            # 2001..2101 recu
                 cli(0.021, sseq + 100)]      # ACK d'origine (pas un duplicata)
        # 2101..2201 est PERDU ; les trois suivants arrivent et provoquent
        # chacun une repetition du meme ACK.
        t = 0.0215
        for seq in (sseq + 200, sseq + 300, sseq + 400):
            pkts.append(srv(t, seq))
            pkts.append(cli(t + 0.0005, sseq + 100))
            t += 0.001
        # Renvoi du segment manquant 1 ms apres le dernier paquet du serveur :
        # DANS la fenetre de reordonnancement de capture, donc jete avant le
        # correctif — alors que le client venait de le reclamer trois fois.
        pkts.append(srv(t, sseq + 100))

        p = tmp_path / "fastretrans.pcap"
        write_pcap(p, pkts)
        sig = [compute_signals(f) for f in build_flows(read_capture(p))][0]

        assert sig.dup_ack_bursts_from_client >= 1, "les dup-ACK doivent etre vus"
        assert sig.retrans_total >= 1, (
            "un renvoi reclame par dup-ACK est une retransmission, pas un "
            "reordonnancement de capture, meme a 0,5 ms")
