"""Les trois AVEUGLEMENTS corriges le 08/08/2026, et la preuve qu'ils le sont.

Le commit « correction de l aveuglement » a change signals.py et builtin.yaml
sans qu'aucun test ne le voie : les 365 tests qui passaient avant passaient
encore apres, a l'identique. Un code que rien ne met en defaut peut etre juste,
faux, ou sans effet — et rien ne permettait de trancher. Ce fichier tranche.

Chaque cas est une capture FABRIQUEE avec les briques de make_fixtures.py, puis
lue par la vraie chaine read_capture -> build_flows -> compute_signals ->
evaluate. Chaque cas porte l'accusation ET son garde-fou : le scenario inverse,
celui ou l'ancien comportement etait JUSTE et doit le rester. Une correction qui
ne se contente pas d'echanger un faux positif contre un faux negatif se prouve
la, et nulle part ailleurs.

  1. HOQUET CLIENT contre SERVEUR LENT. `unless: zw_max_ms_from_client >= 100`
     retirait le verdict APP a partir d'une DUREE, sans jamais regarder QUAND la
     fenetre etait fermee. Un hoquet de 150 ms referme avant meme que la requete
     ne parte effacait un serveur qui repond en 900 ms : le rapport basculait
     sur HOTE et sa remediation « Le reseau et le serveur sont hors de cause »,
     et 300 ms de hoquet suffisaient a effacer un serveur a 10 s.
     Garde-fou : une fenetre fermee 800 ms qui RECOUVRE l'attente rend HOTE.

  2. TELECHARGEMENT CONGESTIONNE. `unless: rtt_haut_porte_par_ack_purs == true`
     etait vrai de TOUT transfert unidirectionnel : le recepteur n'a rien a
     piggybacker, donc 100 % de ses acquittements sont purs PAR CONSTRUCTION.
     Un bufferbloat a 450 ms ressortait « Transport sain », RAS, confiance
     haute.
     Garde-fou : un vrai delayed ACK reste ignore.

  3. CHEMIN MORT. `perte_evenement_unique` comptait UN episode, et un episode
     qui ne se referme jamais en est un : des renvois en backoff RTO jusqu'a la
     fin de la capture sortaient « une seule rafale, la session s'en est
     remise ». Meme aveuglement sur la MTU : reduire ses segments n'est pas les
     faire passer, et un trou noir total sortait « MTU absorbee par la
     decouverte automatique — RIEN A CORRIGER SUR CE FLUX ».
     Garde-fou : une vraie rafale unique dont le flux s'est remis garde son
     traitement.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from dpkt.tcp import TH_ACK, TH_FIN, TH_PUSH, TH_SYN
from make_fixtures import (CLIENT, ROUTER, SERVER, _handshake, _icmp_unreach,
                           _tcp, write_pcap)

from netverdict.flows import build_flows
from netverdict.pcap import read_capture
from netverdict.rules.engine import evaluate, load_rules
from netverdict.signals import compute_signals


@pytest.fixture(scope="module")
def regles():
    return load_rules()


def _analyse(regles, path: Path):
    """(signaux, verdict, ids de TOUS les matches, preuves, remediations).

    TOUS les matches : report.py imprime les suivants en signaux secondaires et
    --json les exporte tous. Une phrase fausse releguee au second rang reste
    sous les yeux de l'admin — c'est la doctrine posee au durcissement 1.
    """
    flows = build_flows(read_capture(path))
    assert len(flows) == 1, f"{len(flows)} flux, 1 attendu"
    sig = compute_signals(flows[0])
    # lang="fr" explicite : ce fichier verifie le texte francais precis des
    # regles (remediations/preuves citees mot pour mot dans les assertions
    # ci-dessous), pas le defaut de langue de l'outil — DEFAULT_LANG est
    # passe a "en" depuis 0.7.0, il ne doit pas faire deriver ces tests.
    fv = evaluate([sig], regles, lang="fr")[0]
    ids = [m.rule.id for m in fv.matches]
    preuves = " | ".join(e for m in fv.matches for e in m.evidence)
    remedes = "\n".join(m.remediation for m in fv.matches)
    return sig, fv, ids, preuves, remedes


def _ecrire(path: Path, pkts) -> Path:
    write_pcap(path, pkts)
    return path


# --------------------------------------------------------------------------
# CAS 1 — un hoquet du poste client efface un serveur lent
# --------------------------------------------------------------------------

def _hoquet_client_puis_serveur_lent(cport: int, hoquet_ms: float,
                                     reponse_ms: float):
    """Le poste client fige un instant — un tableur qui recalcule, un antivirus
    qui scanne — et sa pile annonce une fenetre a zero pendant `hoquet_ms`. La
    fenetre EST DEJA ROUVERTE quand la premiere requete part.

    Ensuite, trois echanges avec un serveur qui accuse reception en 5 ms et met
    `reponse_ms` a repondre : la pile TCP du serveur a recu, c'est son
    application qui traine. Il n'y a strictement AUCUN rapport de cause a effet
    entre le hoquet et l'attente — ils ne se recouvrent meme pas dans le temps.
    """
    pkts = _handshake(0.0, cport, 5432)
    c, s = 1001, 2001
    t = 0.05
    # LE HOQUET, et sa fin : la fenetre se referme puis se ROUVRE, avant que la
    # moindre requete n'ait ete emise.
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_ACK, seq=c, ack=s,
                     win=0))
    t += hoquet_ms / 1000.0
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_ACK, seq=c, ack=s))
    t += 0.05
    for _ in range(3):
        req = b"SELECT" + b"x" * 194
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=req))
        c += len(req)
        # ACK PUR immediat : la pile TCP du serveur a recu la requete.
        pkts.append(_tcp(t + 0.005, SERVER, CLIENT, 5432, cport, TH_ACK,
                         seq=s, ack=c))
        # ... et l'application met `reponse_ms` a produire le premier octet.
        r = reponse_ms / 1000.0
        resp = b"ROWS" + b"y" * 396
        pkts.append(_tcp(t + r, SERVER, CLIENT, 5432, cport, TH_PUSH | TH_ACK,
                         seq=s, ack=c, payload=resp))
        s += len(resp)
        pkts.append(_tcp(t + r + 0.005, CLIENT, SERVER, cport, 5432, TH_ACK,
                         seq=c, ack=s))
        t += r + 0.5
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_FIN | TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.001, SERVER, CLIENT, 5432, cport, TH_FIN | TH_ACK,
                     seq=s, ack=c + 1))
    pkts.append(_tcp(t + 0.002, CLIENT, SERVER, cport, 5432, TH_ACK,
                     seq=c + 1, ack=s + 1))
    return pkts


def _fenetre_client_fermee_pendant_l_attente(cport: int):
    """Le scenario INVERSE, celui ou l'inhibition a toujours eu raison : la
    fenetre du client se ferme pendant que le serveur a sa reponse prete, et
    reste fermee 800 des 820 ms d'attente. Le controle de flux TCP interdit au
    serveur d'emettre : le TTFB ne mesure plus le temps de l'application, et le
    coupable est le poste client.
    """
    pkts = _handshake(0.0, cport, 5432)
    c, s = 1001, 2001
    t = 0.05
    for _ in range(3):
        req = b"SELECT" + b"x" * 194
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=req))
        c += len(req)
        pkts.append(_tcp(t + 0.005, SERVER, CLIENT, 5432, cport, TH_ACK,
                         seq=s, ack=c))
        # La fenetre se ferme APRES la requete et se rouvre JUSTE avant la
        # reponse : 800 ms sur les 820 ms d'attente.
        pkts.append(_tcp(t + 0.010, CLIENT, SERVER, cport, 5432, TH_ACK,
                         seq=c, ack=s, win=0))
        pkts.append(_tcp(t + 0.810, CLIENT, SERVER, cport, 5432, TH_ACK,
                         seq=c, ack=s))
        resp = b"ROWS" + b"y" * 396
        pkts.append(_tcp(t + 0.820, SERVER, CLIENT, 5432, cport,
                         TH_PUSH | TH_ACK, seq=s, ack=c, payload=resp))
        s += len(resp)
        pkts.append(_tcp(t + 0.825, CLIENT, SERVER, cport, 5432, TH_ACK,
                         seq=c, ack=s))
        t += 1.3
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 5432, TH_FIN | TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.001, SERVER, CLIENT, 5432, cport, TH_FIN | TH_ACK,
                     seq=s, ack=c + 1))
    pkts.append(_tcp(t + 0.002, CLIENT, SERVER, cport, 5432, TH_ACK,
                     seq=c + 1, ack=s + 1))
    return pkts


class TestUnHoquetClientNExpliquePasUnServeurLent:
    """PREJUDICE : le rapport bascule de « Reponse applicative lente, reception
    prouvee par ACK rapide » (APP, confiance haute, priorite 84) a « Le client
    ne lit plus sa socket » (HOTE, priorite 83), dont la remediation ecrit noir
    sur blanc « Le reseau et le serveur sont hors de cause » et envoie verifier
    la charge du POSTE. Le serveur qui met 900 ms a repondre disparait alors du
    rapport — il n'est plus cite nulle part, pas meme en signal secondaire, et
    les 900 ms avec lui.

    Le fait sur lequel reposait la bascule est un MAXIMUM DE DUREES. Il ne dit
    pas quand la fenetre etait fermee, donc il ne peut rien expliquer : ici
    elle s'est refermee avant que la requete ne parte. La bascule suivait le
    seuil au lieu de suivre les faits.
    """

    def test_un_hoquet_referme_avant_la_requete_ne_recouvre_aucune_attente(
            self, regles, tmp_path):
        """La mesure qui manquait : la POSITION de la fenetre fermee, rapportee
        a ce qu'elle est censee expliquer."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "hoquet_150.pcap",
                            _hoquet_client_puis_serveur_lent(54101, 150.0,
                                                             900.0)))

        assert sig.zw_max_ms_from_client >= 100, (
            "le piege est arme : l'ancienne condition, une duree nue, est "
            "vraie — 150 ms de fenetre fermee")
        assert sig.attente_totale_ms > 2000, (
            "trois attentes de 900 ms : c'est cela qu'il faudrait expliquer")
        assert sig.zw_client_attente_ms == 0.0, (
            "la fenetre fermee ne recouvre AUCUNE de ces attentes : elle "
            "s'est rouverte avant la premiere requete")
        assert sig.zw_client_part_attente == 0.0

    def test_le_verdict_reste_APP_et_ne_bascule_jamais_sur_HOTE(
            self, regles, tmp_path):
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "hoquet_150.pcap",
                            _hoquet_client_puis_serveur_lent(54101, 150.0,
                                                             900.0)))

        assert fv.verdict == "APP"
        assert fv.verdict != "HOTE"
        assert fv.primary.rule.id == "slow-app-proven"
        assert "COTE APPLICATIF" in fv.primary.remediation
        assert "Le reseau et le serveur sont hors de cause" not in \
            fv.primary.remediation, (
            "cette phrase, en tete de rapport, arrete l'enquete sur le serveur")

    def test_le_rapport_cite_les_900_ms_du_serveur(self, regles, tmp_path):
        """Ne pas se tromper de verdict ne suffit pas : le CHIFFRE qui envoie
        l'admin lire les logs applicatifs du serveur au bon horodatage doit
        etre imprime."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "hoquet_150.pcap",
                            _hoquet_client_puis_serveur_lent(54101, 150.0,
                                                             900.0)))

        assert "900 ms" in preuves, (
            "les 900 ms de l'application sont le fait a rapporter")
        assert "ACK serveur en 5 ms" in preuves, (
            "et le contraste avec l'ACK a 5 ms est ce qui le PROUVE")

    def test_trois_cents_ms_de_hoquet_n_effacent_pas_un_serveur_a_dix_secondes(
            self, regles, tmp_path):
        """Le meme defaut, a l'echelle qui le rend absurde : 300 ms de hoquet
        contre un serveur qui met DIX SECONDES. Un seuil qui laisse 0,3 s
        effacer 10 s ne mesure plus rien."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "hoquet_300.pcap",
                            _hoquet_client_puis_serveur_lent(54102, 300.0,
                                                             10000.0)))

        assert sig.zw_max_ms_from_client >= 300, "le piege est arme"
        assert fv.verdict == "APP"
        assert fv.primary.rule.id == "slow-app-proven"
        assert "10000 ms" in preuves
        assert sig.zw_client_part_attente == 0.0

    def test_une_fenetre_qui_recouvre_l_attente_rend_toujours_HOTE(
            self, regles, tmp_path):
        """LE GARDE-FOU, et la raison d'etre de l'inhibition : quand la fenetre
        fermee recouvre VRAIMENT l'attente et en explique l'essentiel, accuser
        l'application serait accuser un serveur a qui TCP interdisait d'emettre.
        Ce cas doit rendre HOTE exactement comme avant la correction — une
        correction qui echange un faux positif contre un faux negatif ne
        corrige rien."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "fenetre_recouvrante.pcap",
                            _fenetre_client_fermee_pendant_l_attente(54103)))

        assert fv.verdict == "HOTE"
        assert fv.primary.rule.id == "zero-window-client"
        assert "slow-app-proven" not in ids, (
            "le serveur ne doit pas etre accuse, meme en signal secondaire")

    def test_la_part_de_l_attente_sous_fenetre_fermee_est_mesuree(
            self, regles, tmp_path):
        """Et la mesure qui le justifie, sur le meme flux : ce n'est plus la
        duree de la fermeture qui inhibe, c'est la part de l'attente qu'elle
        recouvre. 800 ms sur 820, soit 97 % — le serveur n'est responsable de
        rien."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "fenetre_recouvrante.pcap",
                            _fenetre_client_fermee_pendant_l_attente(54103)))

        assert sig.zw_client_attente_ms >= 100
        assert sig.zw_client_part_attente >= 0.5, (
            "800 des 820 ms d'attente sont sous fenetre fermee")


# --------------------------------------------------------------------------
# CAS 2 — un telechargement congestionne vendu comme un transport sain
# --------------------------------------------------------------------------

def _telechargement_congestionne(cport: int, rtt_ms: float = 450.0,
                                 tours: int = 14):
    """TELECHARGEMENT : une requete de 36 octets, puis le serveur pousse. Le
    client n'a plus RIEN a dire — tous ses acquittements sont donc purs par
    construction, et non parce qu'un timer les retarde.

    Le chemin est engorge : la file d'attente du goulot est pleine et le RTT
    s'etablit sur un plateau de 450 ms (bufferbloat). Au demarrage, file vide,
    le premier aller-retour ne coute que 15 ms — c'est cette montee qui signe
    la congestion, et c'est elle que l'outil doit voir.

    Deux segments pleins voyagent ensemble et sont acquittes ENSEMBLE : la
    RFC 1122 impose au recepteur d'acquitter immediatement des qu'il a deux
    segments pleins non acquittes. Aucun timer de delayed ACK ne peut donc
    expliquer ces 450 ms.
    """
    pkts = _handshake(0.0, cport, 443)
    c, s = 1001, 2001
    req = b"GET /image.iso HTTP/1.1\r\nHost: x\r\n\r\n"
    pkts.append(_tcp(0.010, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                     seq=c, ack=s, payload=req))
    c += len(req)
    # Premier octet apres 15 ms : la file du goulot est encore vide.
    t = 0.025
    r = rtt_ms / 1000.0
    for _ in range(tours):
        pkts.append(_tcp(t, SERVER, CLIENT, 443, cport, TH_ACK,
                         seq=s, ack=c, payload=b"D" * 1448))
        s += 1448
        pkts.append(_tcp(t + 0.0002, SERVER, CLIENT, 443, cport, TH_ACK,
                         seq=s, ack=c, payload=b"D" * 1448))
        s += 1448
        pkts.append(_tcp(t + r, CLIENT, SERVER, cport, 443, TH_ACK,
                         seq=c, ack=s))
        t += 0.020
    return pkts


def _abonnement_avec_delayed_ack(cport: int, differe_ms: float = 40.0):
    """Le VRAI delayed ACK, celui que l'outil doit continuer d'ignorer : un
    abonnement (MQTT, tail de logs, flux de cotations) sur un LAN a 0,4 ms. Le
    serveur pousse UN petit enregistrement toutes les 200 ms ; le client n'a
    rien a repondre et sa pile arme son timer — 40 ms sous Linux.

    Un seul segment en vol a chaque fois : le recepteur POUVAIT attendre son
    timer, et 40 ms en ont exactement la grandeur.
    """
    pkts = _handshake(0.0, cport, 8883)
    # Le handshake de reference pose 1 ms ; on veut le LAN commute a 0,4 ms
    # pour que le contraste avec les 40 ms soit celui du terrain.
    pkts[1] = _tcp(0.0004, SERVER, CLIENT, 8883, cport, TH_SYN | TH_ACK,
                   seq=2000, ack=1001)
    pkts[2] = _tcp(0.0008, CLIENT, SERVER, cport, 8883, TH_ACK,
                   seq=1001, ack=2001)
    c, s = 1001, 2001
    sub = b"SUBSCRIBE topic/#"
    pkts.append(_tcp(0.010, CLIENT, SERVER, cport, 8883, TH_PUSH | TH_ACK,
                     seq=c, ack=s, payload=sub))
    c += len(sub)
    # Piggyback : mesure franche du chemin cote serveur, 5 ms.
    suback = b"SUBACK"
    pkts.append(_tcp(0.015, SERVER, CLIENT, 8883, cport, TH_PUSH | TH_ACK,
                     seq=s, ack=c, payload=suback))
    s += len(suback)
    pkts.append(_tcp(0.015 + differe_ms / 1000.0, CLIENT, SERVER, cport, 8883,
                     TH_ACK, seq=c, ack=s))
    t = 0.3
    rec = b'{"t":1754680000,"v":42}'
    for _ in range(12):
        pkts.append(_tcp(t, SERVER, CLIENT, 8883, cport, TH_PUSH | TH_ACK,
                         seq=s, ack=c, payload=rec))
        s += len(rec)
        pkts.append(_tcp(t + differe_ms / 1000.0, CLIENT, SERVER, cport, 8883,
                         TH_ACK, seq=c, ack=s))
        t += 0.2
    return pkts


class TestUnTelechargementCongestionneNEstPasUnTransportSain:
    """PREJUDICE : « Transport sain : le probleme n'est pas dans cette
    conversation reseau », RAS, confiance HAUTE, sur un telechargement dont le
    RTT tient un plateau de 450 ms. C'est le faux « tout va bien » — la panne
    la plus couteuse pour un outil de diagnostic, parce qu'elle ne se contente
    pas de se taire : elle envoie l'admin chercher ailleurs, avec la plus haute
    confiance affichable, pendant qu'un lien sature est sous ses yeux.

    L'inhibition s'armait sur « toutes les mesures hautes sont portees par des
    ACK purs ». Dans un telechargement, une sauvegarde ou un upload, le
    recepteur n'a jamais rien a piggybacker : ses acquittements sont purs PAR
    CONSTRUCTION, pas par choix. La garde etait donc vraie de 100 % des
    transferts unidirectionnels — c'est-a-dire aveugle a toute congestion sur
    la famille de flux ou la congestion se voit le mieux.
    """

    def test_la_purete_des_acquittements_ne_prouve_rien_sur_un_telechargement(
            self, regles, tmp_path):
        """Les trois faits mesures, et ce que chacun dit : l'ancienne garde est
        armee, la nouvelle ne l'est pas, et ce n'est PAS la grandeur qui les
        separe (450 ms restent sous le plafond de 500 ms)."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "telechargement.pcap",
                            _telechargement_congestionne(54201)))

        assert sig.rtt_ms_p50 is not None and sig.rtt_ms_p50 >= 400, (
            "le plateau de bufferbloat est bien la, sur la MEDIANE")
        assert sig.rtt_haut_porte_par_ack_purs, (
            "le piege est arme : l'ancienne garde, seule, est vraie — un "
            "recepteur qui ne fait que recevoir n'a rien a piggybacker")
        assert not sig.rtt_haut_sur_segment_isole, (
            "chaque acquittement en couvre DEUX : la RFC 1122 interdit au "
            "recepteur d'attendre un timer, l'explication par le delayed ACK "
            "ne tient pas")
        assert sig.rtt_haut_max_ms is not None and sig.rtt_haut_max_ms <= 500, (
            "et ce n'est pas la grandeur qui sauve ce cas : 450 ms passeraient "
            "le plafond du timer sans broncher")
        assert not sig.rtt_haut_sous_fenetre_saturee, (
            "le client annonce sa fenetre pleine du debut a la fin : il n'est "
            "pas sature, il attend")

    def test_la_congestion_ne_ressort_plus_transport_sain_confiance_haute(
            self, regles, tmp_path):
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "telechargement.pcap",
                            _telechargement_congestionne(54201)))

        # Liees a des locales : sans cela, l'echec imprime le repr complet de
        # la regle et de tout le FlowVerdict, et le message se perd dedans.
        tete = fv.primary.rule.id
        confiance = fv.primary.rule.confidence
        assert tete != "clean", (
            "un plateau de 450 ms en tete de rapport ne peut pas s'appeler "
            "« transport sain »")
        assert fv.verdict != "RAS"
        assert not (fv.verdict == "RAS" and confiance == "haute"), (
            "un faux « tout va bien » avec la plus haute confiance affichable "
            "est le pire produit possible de cet outil")
        assert tete == "rtt-degraded"
        assert fv.verdict == "RESEAU"
        assert "450" in preuves, "le plateau mesure doit etre cite"

    def test_un_vrai_delayed_ack_reste_ignore(self, regles, tmp_path):
        """LE GARDE-FOU. Le durcissement 2 avait supprime « congestion
        probable » sur un abonnement LAN dont la mediane EST le timer du
        recepteur ; rendre l'outil sensible aux telechargements ne doit pas
        ramener ce faux verdict RESEAU. Ici un seul segment est en vol a chaque
        fois, et 40 ms sont exactement la grandeur d'un timer : les deux faits
        que la correction exige en plus sont reunis, l'inhibition tient."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "abonnement.pcap",
                            _abonnement_avec_delayed_ack(54202)))

        assert sig.rtt_ms_min is not None and sig.rtt_ms_min < 1.0, (
            "le chemin est mesure a moins d'une milliseconde par le handshake")
        assert sig.rtt_ms_p50 is not None and sig.rtt_ms_p50 >= 20, (
            "le piege est arme : la mediane est le timer du recepteur")
        assert sig.rtt_haut_porte_par_ack_purs
        assert "rtt-degraded" not in ids, (
            "accuser le chemin sur des acquittements differes envoie l'admin "
            "chercher une congestion qui n'existe pas, meme en signal "
            "secondaire")
        assert "congestion" not in preuves.lower()
        assert fv.primary.rule.id == "clean"
        assert fv.verdict == "RAS"


# --------------------------------------------------------------------------
# CAS 3 — un chemin mort requalifie en rafale dont la session s'est remise
# --------------------------------------------------------------------------

def _chemin_qui_meurt(cport: int, avant: int = 20, renvois: int = 5):
    """Un televersement qui travaille normalement — 20 segments emis, 20
    acquittes — puis le chemin MEURT. Le segment suivant part et n'est jamais
    acquitte ; l'emetteur le renvoie en doublant son delai a chaque fois
    (backoff RTO : 0,5 s, 1 s, 2 s, 4 s, 8 s) et n'obtient plus rien. La
    capture s'arrete sans cloture : ni FIN, ni RST.

    Cas de terrain : un firewall qui a perdu l'etat de la session apres un
    basculement, un trou noir de MTU dont l'ICMP est filtre en amont, un pair
    qui a redemarre.
    """
    pkts = _handshake(0.0, cport, 443)
    c, s, t = 1001, 2001, 0.01
    for _ in range(avant):
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=b"u" * 1000))
        c += 1000
        pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 443, cport, TH_ACK,
                         seq=s, ack=c))
        t += 0.02
    mort = c
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                     seq=mort, ack=s, payload=b"u" * 1000))
    d = 0.5
    for _ in range(renvois):
        t += d
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                         seq=mort, ack=s, payload=b"u" * 1000))
        d *= 2
    return pkts


def _trou_noir_mtu_total(cport: int, renvois: int = 5):
    """Le trou noir de MTU dans sa forme complete : les PETITS echanges
    passent — requete de 200 octets, reponse, tout est acquitte — et tout gele
    des qu'un gros transfert demarre. L'ICMP 'fragmentation needed' remonte,
    l'emetteur REDUIT ses segments de 1460 a 1400 octets... mais le lien du
    chemin est a 1300 : rien ne passe davantage, et le pair n'acquitte plus un
    seul octet.

    Reduire n'est pas livrer. C'est toute la difference entre une decouverte de
    MTU qui a fonctionne et un trou noir ou l'emetteur a poliment obei sans que
    cela change quoi que ce soit.
    """
    pkts = _handshake(0.0, cport, 443)
    c, s, t = 1001, 2001, 0.01
    petit = b"HEAD / HTTP/1.1\r\n\r\n" + b"h" * 181
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                     seq=c, ack=s, payload=petit))
    c += len(petit)
    pkts.append(_tcp(t + 0.004, SERVER, CLIENT, 443, cport, TH_ACK,
                     seq=s, ack=c))
    rep = b"200 OK" + b"r" * 294
    pkts.append(_tcp(t + 0.008, SERVER, CLIENT, 443, cport, TH_PUSH | TH_ACK,
                     seq=s, ack=c, payload=rep))
    s += len(rep)
    pkts.append(_tcp(t + 0.012, CLIENT, SERVER, cport, 443, TH_ACK,
                     seq=c, ack=s))
    # Le gros transfert demarre : 1460 octets, et l'equipement repond.
    t = 0.1
    gros = c
    pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                     seq=gros, ack=s, payload=b"P" * 1460))
    pkts.append(_icmp_unreach(t + 0.003, ROUTER, 4, CLIENT, SERVER, cport, 443))
    # L'emetteur obeit — 1400 octets — et se fait avaler pareil.
    d = 0.5
    for _ in range(renvois):
        t += d
        pkts.append(_tcp(t, CLIENT, SERVER, cport, 443, TH_PUSH | TH_ACK,
                         seq=gros, ack=s, payload=b"P" * 1400))
        d *= 2
    return pkts


def _rafale_unique_avec_reprise(cport: int, n_perdus: int = 7):
    """Le scenario que perte-rafale-unique decrit VRAIMENT : un televersement
    de 40 segments a travers un lien qui hoquette UNE fois. La fenetre en vol —
    7 segments — n'est pas acquittee et repart d'un bloc au RTO. Le pair
    acquitte alors les nouveaux octets, le transfert reprend, la session se
    ferme par FIN.

    Chaque segment n'est renvoye qu'UNE fois, et le pair a acquitte apres : ce
    n'est pas un backoff, c'est un hoquet dont TCP est sorti.
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


class TestUnCheminMortNEstPasUneRafaleDontOnSeRemet:
    """PREJUDICE : « Une seule rafale de pertes, pas un taux de perte »,
    AMBIGU, confiance faible, et une remediation qui affirme « la session s'en
    est remise » sur une conversation ou plus rien ne passe. L'admin lit un
    incident clos, ne rouvre rien, et le transfert est mort.

    Le compteur qui produisait ce verdict comptait des EPISODES. Un episode se
    ferme quand l'emetteur reprend sa progression — donc un episode qui ne se
    referme JAMAIS reste « un » episode, et un chemin coupe se retrouvait
    decrit comme un hoquet passager. Emettre a nouveau ne prouve rien ; seul
    l'ACQUITTEMENT du pair prouve que quelque chose est passe.
    """

    def test_le_rapport_ne_dit_plus_que_la_session_s_en_est_remise(
            self, regles, tmp_path):
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "chemin_mort.pcap",
                            _chemin_qui_meurt(54301)))

        assert "s'en est remise" not in remedes.lower(), (
            "affirmer un retablissement que la capture ne montre pas est la "
            "phrase la plus couteuse du rapport : elle fait classer l'incident")
        assert fv.primary.rule.id == "perte-sans-reprise"
        assert fv.verdict == "RESEAU"
        assert "jamais acquitte" in preuves
        assert "Aucune reprise dans la capture" in preuves

    def test_le_backoff_RTO_est_mesure_et_non_suppose(self, regles, tmp_path):
        """Les faits qui separent un chemin mort d'un hoquet : le MEME segment,
        cinq fois, etale sur quinze secondes, jamais acquitte — et aucune
        reprise dans aucun sens."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "chemin_mort.pcap",
                            _chemin_qui_meurt(54301)))

        assert sig.retrans_meme_segment_max == 5
        assert sig.retrans_meme_segment_span_s >= 0.5, (
            "un fast retransmit renvoie les memes octets en quelques ms ; "
            "quinze secondes sont un backoff")
        assert sig.retrans_meme_segment_jamais_acquitte
        assert not sig.reprise_apres_perte
        assert sig.perte_evenement_unique, (
            "le piege est intact : c'est bien UN episode au sens du compteur, "
            "et c'est pour cela qu'il ne suffit pas a conclure")
        assert sig.closed_by == "none", "ni FIN ni RST : la capture s'arrete"

    def test_un_trou_noir_mtu_total_n_est_pas_une_decouverte_reussie(
            self, regles, tmp_path):
        """L'emetteur a REDUIT ses segments — 1460 puis 1400 — et l'outil en
        concluait « RIEN A CORRIGER SUR CE FLUX ... la session a poursuivi ».
        Elle n'a rien poursuivi du tout : le pair n'a jamais acquitte un octet
        de ce qui a suivi l'erreur."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "trou_noir_mtu.pcap",
                            _trou_noir_mtu_total(54302)))

        assert sig.seg_max_before_frag_needed == 1460
        assert sig.seg_max_after_frag_needed == 1400, (
            "le piege est arme : l'emetteur a bel et bien reduit, et c'etait "
            "la seule preuve exigee")
        assert "mtu-decouverte-reussie" not in ids
        assert "RIEN A CORRIGER" not in remedes
        assert "la session a poursuivi" not in preuves
        assert fv.primary.rule.id == "mtu-blackhole"
        assert fv.verdict == "RESEAU"
        assert "s'en est remise" not in remedes.lower(), (
            "un trou noir total ne s'annonce pas non plus comme une rafale "
            "dont on se remet")
        assert not sig.progres_apres_frag_needed, (
            "et la mesure qui le justifie : le pair n'a jamais acquitte ces "
            "octets-la — reduire n'est pas livrer")
        assert sig.frag_needed_ignored

    def test_une_vraie_rafale_dont_le_flux_s_est_remis_garde_son_traitement(
            self, regles, tmp_path):
        """LE GARDE-FOU. Le durcissement 2 avait retire le TAUX et la confiance
        haute a un hoquet unique ; la correction ne doit pas les lui rendre par
        la bande, ni requalifier en chemin mort une session qui a repris et
        s'est fermee proprement."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "rafale_reprise.pcap",
                            _rafale_unique_avec_reprise(54303)))

        assert sig.retrans_total == 7
        assert sig.retrans_events == 1
        assert sig.perte_evenement_unique
        assert "perte-sans-reprise" not in ids, (
            "chaque segment n'est renvoye qu'une fois et le pair a acquitte "
            "apres : ce n'est pas un backoff")
        assert "retrans-heavy" not in ids, (
            "le taux et la confiance haute restent retires (durcissement 2)")
        assert fv.primary.rule.id == "perte-rafale-unique"
        assert fv.verdict == "AMBIGU"
        assert fv.primary.rule.confidence == "faible"
        assert "capture plus longue" in fv.primary.remediation

    def test_le_retablissement_est_desormais_une_preuve_imprimee(
            self, regles, tmp_path):
        """La contrepartie de la phrase supprimee : quand la session S'EST
        remise, le rapport ne l'affirme plus, il le MONTRE — le pair a acquitte
        de nouveaux octets apres le dernier renvoi, et la ligne le dit."""
        sig, fv, ids, preuves, remedes = _analyse(
            regles, _ecrire(tmp_path / "rafale_reprise.pcap",
                            _rafale_unique_avec_reprise(54303)))

        assert "Reprise constatee" in preuves
        assert "acquittes par le pair : True" in preuves
        assert sig.reprise_apres_perte
