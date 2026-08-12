"""Durcissement du 08/08/2026 : deux verdicts CONFIANTS ET FAUX, trouves en
fabriquant des pcaps pieges plutot qu'en relisant les regles.

Les deux partagent la faute la plus chere d'un outil de diagnostic : ils
affirment, avec « confiance haute », le contraire de ce que la capture montre,
et ils envoient l'administrateur travailler sur une machine innocente.

  1. rst-to-syn  — « rien n'ecoute sur ce port » (APP, haute) alors que la
     capture contient DEUX acquittements du serveur portant sur 400 octets de
     donnees client : la socket existait, elle a recu, elle a acquitte.
  2. reject-icmp — « Connexion REFUSEE explicitement » (RESEAU, haute,
     priorite 92, la plus forte de tout le moteur) sur une session qui a fait
     son handshake, trois aller-retours applicatifs et une cloture FIN propre.

Les pcaps sont FABRIQUES ici avec les briques de make_fixtures.py, puis lus par
la vraie chaine read_capture -> build_flows -> compute_signals -> evaluate :
c'est le produit livre qui est juge, pas une imitation de signaux.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from dpkt.tcp import TH_ACK, TH_FIN, TH_PUSH, TH_RST, TH_SYN
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
    """(signaux, ids des matches, texte de toutes les preuves) du flux unique.

    TOUS les matches, pas seulement le primaire : report.py les imprime en
    signaux secondaires et --json les exporte tous. Une accusation fausse
    reléguée au second rang reste sous les yeux de l'admin.
    """
    flows = build_flows(read_capture(path))
    assert len(flows) == 1, f"{len(flows)} flux, 1 attendu"
    sig = compute_signals(flows[0])
    fv = evaluate([sig], regles)[0]
    ids = [m.rule.id for m in fv.matches]
    preuves = " | ".join(p for m in fv.matches for p in m.evidence)
    return sig, fv, ids, preuves


# --------------------------------------------------------------------------
# CAS 1 — le SYN/ACK manque a la capture, mais le serveur a ACQUITTE
# --------------------------------------------------------------------------

def _rst_sur_session_etablie(cport: int = 51101, sport: int = 5432):
    """Collecteur qui pousse (syslog/TCP, metriques, MQTT) vers un serveur qui
    ne repond RIEN — il se contente d'acquitter. Le SYN/ACK n'est pas dans la
    capture : chemin de retour asymetrique, tap sur un seul brin, ou capture
    demarree une fraction de seconde trop tard. 31 secondes plus tard, un RST
    tombe cote serveur (timeout d'un equipement a etats, ou crash du process).

    Ce que la capture PROUVE : la session a existe. Le serveur a acquitte
    400 octets de donnees applicatives — on n'acquitte pas sur un port ferme.
    """
    return [
        _tcp(0.0, CLIENT, SERVER, cport, sport, TH_SYN, seq=1000),
        # SYN/ACK absent — le seul paquet manquant de toute la session.
        _tcp(0.05, CLIENT, SERVER, cport, sport, TH_ACK, seq=1001, ack=2001),
        _tcp(0.06, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
             seq=1001, ack=2001, payload=b"m" * 200),
        _tcp(0.09, SERVER, CLIENT, sport, cport, TH_ACK, seq=2001, ack=1201),
        _tcp(1.06, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
             seq=1201, ack=2001, payload=b"m" * 200),
        _tcp(1.09, SERVER, CLIENT, sport, cport, TH_ACK, seq=2001, ack=1401),
        _tcp(31.0, SERVER, CLIENT, sport, cport, TH_RST, seq=2001, ack=0),
    ]


class TestRienNEcouteAlorsQueLeServeurAAcquitte:
    """PREJUDICE : l'outil dit « aucun service n'ecoute sur 10.0.0.5:5432,
    verifier si le service est demarre ». L'admin redemarre un service qui
    tourne, coupe la production, et ne trouve rien — pendant que la vraie cause
    (un equipement a etats qui tue les sessions inactives, ou un crash du
    process en face) n'est meme pas nommee. Le pcap qu'il vient de lire contient
    pourtant la refutation : deux ACK du serveur sur 400 octets de donnees.

    La preuve imprimee se contredisait elle-meme : « RST recu 31000.0 ms apres
    le SYN » sous un titre qui parle d'un refus immediat de connexion.
    """

    def test_un_serveur_qui_a_acquitte_des_donnees_ecoutait_forcement(
            self, regles, tmp_path):
        p = tmp_path / "rst_sur_session_etablie.pcap"
        write_pcap(p, _rst_sur_session_etablie())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.bytes_c2s == 400, "la capture porte bien les donnees client"
        assert "rst-to-syn" not in ids, (
            "un port ou personne n'ecoute n'acquitte pas 400 octets : la regle "
            "qui affirme « rien n'ecoute » ne doit pas matcher, meme en "
            "signal secondaire")
        assert not sig.rst_to_syn, (
            "rst_to_syn est un FAIT mesure : un RST 31 s apres le SYN, apres "
            "deux acquittements du serveur, n'est pas une reponse au SYN")
        assert "rien n'ecoute" not in preuves.lower()

    def test_la_capture_prouve_que_la_session_a_existe(self, regles, tmp_path):
        """Le signal qui manquait. `handshake_complete` exige d'avoir VU le
        SYN/ACK ; il reste faux ici, a juste titre. Mais un ACK du serveur qui
        couvre des octets applicatifs prouve la meme chose autrement, et aucun
        champ ne le portait — donc aucune regle ne pouvait s'en servir."""
        p = tmp_path / "rst_sur_session_etablie.pcap"
        write_pcap(p, _rst_sur_session_etablie())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert not sig.handshake_complete, "le SYN/ACK n'est pas dans la capture"
        assert sig.established_seen, (
            "le serveur a acquitte des donnees applicatives : la session a "
            "existe, et la capture le prouve sans le SYN/ACK")

    def test_le_bon_diagnostic_est_une_session_coupee_en_plein_travail(
            self, regles, tmp_path):
        """Ne pas mentir ne suffit pas : se taire renverrait l'admin au repli
        « tableau incomplet », c'est-a-dire a rien. La signature est celle de
        rst-midstream — une session qui travaillait, tuee net — et sa
        remediation nomme les trois familles de causes reelles."""
        p = tmp_path / "rst_sur_session_etablie.pcap"
        write_pcap(p, _rst_sur_session_etablie())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.rst_midstream, (
            "une session dont le serveur acquitte 400 octets travaillait ; "
            "exiger des donnees dans LES DEUX sens ecarte tout collecteur "
            "(syslog/TCP, metriques, MQTT) dont le serveur ne repond rien")
        assert fv.primary.rule.id == "rst-midstream"
        assert fv.verdict == "AMBIGU", (
            "qui a emis ce RST — firewall, IPS ou serveur — n'est pas dans la "
            "capture : l'outil doit le dire, pas choisir")
        assert sig.rst_emitter == SERVER
        assert "timeout" in fv.primary.remediation.lower()

    def test_un_vrai_port_ferme_reste_diagnostique(self, regles, tmp_path):
        """Le garde-fou. Sans lui, « ne plus jamais dire rien n'ecoute » se
        satisferait d'une regle morte, et l'outil perdrait un de ses
        diagnostics les plus surs."""
        p = tmp_path / "port_ferme.pcap"
        write_pcap(p, [
            _tcp(0.0, CLIENT, SERVER, 51102, 8443, TH_SYN, seq=1000),
            _tcp(0.002, SERVER, CLIENT, 8443, 51102, TH_RST | TH_ACK,
                 seq=0, ack=1001),
        ])
        sig, fv, ids, preuves = _analyse(regles, p)
        assert sig.rst_to_syn
        assert not sig.established_seen
        assert fv.primary.rule.id == "rst-to-syn"
        assert fv.verdict == "APP"

    def test_un_RST_apres_SYN_ACK_vu_reste_hors_de_ce_diagnostic(
            self, regles, tmp_path):
        """L'autre borne : quand le SYN/ACK EST dans la capture, la session est
        etablie par le chemin historique (`synack_seen`) et le correctif ne doit
        rien changer a ce qui marchait deja."""
        p = tmp_path / "rst_apres_handshake.pcap"
        pkts = list(_handshake(0.0, 51103, 1433))
        pkts += [
            _tcp(0.01, CLIENT, SERVER, 51103, 1433, TH_PUSH | TH_ACK,
                 seq=1001, ack=2001, payload=b"q" * 200),
            _tcp(0.02, SERVER, CLIENT, 1433, 51103, TH_PUSH | TH_ACK,
                 seq=2001, ack=1201, payload=b"r" * 300),
            _tcp(0.025, CLIENT, SERVER, 51103, 1433, TH_ACK, seq=1201, ack=2301),
            _tcp(30.0, SERVER, CLIENT, 1433, 51103, TH_RST, seq=2301, ack=0),
        ]
        write_pcap(p, pkts)
        sig, fv, ids, preuves = _analyse(regles, p)
        assert sig.established_seen and sig.handshake_complete
        assert not sig.rst_to_syn
        assert fv.primary.rule.id == "rst-midstream"


# --------------------------------------------------------------------------
# CAS 2 — un REJECT sur une session qui a parfaitement fonctionne
# --------------------------------------------------------------------------

def _reject_sur_session_reussie(cport: int = 51104, sport: int = 443,
                                cloture_fin: bool = True):
    """Session HTTPS complete et saine — handshake, trois aller-retours,
    cloture FIN — traversee par UN ICMP administratively-prohibited.

    Cas de terrain : chemin a plusieurs routes (ECMP, VRRP, bascule de
    firewall). Un paquet de la session emprunte le brin dont la table d'etats
    ignore cette connexion et se fait rejeter par politique ; le reste passe par
    l'autre brin et la session n'en souffre pas.
    """
    pkts = _handshake(0.0, cport, sport)
    cseq, sseq = 1001, 2001
    for t0 in (0.01, 0.5, 1.0):
        req = b"GET " + b"a" * 96
        pkts.append(_tcp(t0, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                         seq=cseq, ack=sseq, payload=req))
        pkts.append(_tcp(t0 + 0.005, SERVER, CLIENT, sport, cport, TH_ACK,
                         seq=sseq, ack=cseq + len(req)))
        cseq += len(req)
        resp = b"200 " + b"b" * 496
        pkts.append(_tcp(t0 + 0.03, SERVER, CLIENT, sport, cport,
                         TH_PUSH | TH_ACK, seq=sseq, ack=cseq, payload=resp))
        sseq += len(resp)
        pkts.append(_tcp(t0 + 0.035, CLIENT, SERVER, cport, sport, TH_ACK,
                         seq=cseq, ack=sseq))
    pkts.append(_icmp_unreach(1.2, ROUTER, 13, CLIENT, SERVER, cport, sport))
    if cloture_fin:
        pkts.append(_tcp(1.5, CLIENT, SERVER, cport, sport, TH_FIN | TH_ACK,
                         seq=cseq, ack=sseq))
        pkts.append(_tcp(1.501, SERVER, CLIENT, sport, cport, TH_FIN | TH_ACK,
                         seq=sseq, ack=cseq + 1))
        pkts.append(_tcp(1.502, CLIENT, SERVER, cport, sport, TH_ACK,
                         seq=cseq + 1, ack=sseq + 1))
    return pkts


class TestConnexionRefuseeAlorsQuElleAReussi:
    """PREJUDICE : sur la foi d'UN paquet ICMP, l'outil rend « Connexion
    REFUSEE explicitement par un equipement », RESEAU, confiance haute, a la
    priorite 92 — la plus haute du moteur. Trois consequences, toutes payantes :

      1. Il affirme le contraire de la capture : le handshake a abouti, 1500
         octets sont revenus, la session s'est fermee par FIN.
      2. Il envoie l'admin chercher, sur un equipement nomme, une regle de
         filtrage qui bloquerait un trafic qui n'a PAS ete bloque.
      3. Priorite 92, ce flux passe en tete du rapport et repousse les vrais
         verdicts hors de --top : le faux positif cache les vrais.

    Le fait mesure — un equipement rejette du trafic de cette conversation —
    reste vrai et doit rester dit. C'est l'HISTOIRE qui etait fausse.
    """

    def test_une_session_qui_a_reussi_n_a_pas_ete_refusee(self, regles, tmp_path):
        p = tmp_path / "reject_sur_session_reussie.pcap"
        write_pcap(p, _reject_sur_session_reussie())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.handshake_complete and sig.bytes_s2c == 1500
        assert sig.closed_by == "fin"
        assert "reject-icmp" not in ids, (
            "« connexion refusee » sur une session etablie, servie et fermee "
            "proprement : la regle ne doit pas matcher, meme en secondaire")
        assert "REFUSEE" not in preuves and "REFUSE" not in preuves

    def test_le_rejet_reste_signale_mais_avec_la_bonne_histoire(
            self, regles, tmp_path):
        """Supprimer le faux verdict sans rien mettre a la place serait un
        autre defaut : un equipement a bel et bien rejete du trafic de cette
        conversation, et il est NOMME dans le pcap. Ce qu'il faut corriger,
        c'est l'affirmation « la connexion a ete refusee » et sa confiance."""
        p = tmp_path / "reject_sur_session_reussie.pcap"
        write_pcap(p, _reject_sur_session_reussie())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert fv.primary.rule.id == "reject-icmp-session-etablie"
        assert fv.verdict == "AMBIGU", (
            "que ce rejet ait gene ou non l'utilisateur n'est pas dans la "
            "capture : la session, elle, a fonctionne")
        assert fv.primary.rule.confidence != "haute"
        assert ROUTER in preuves, "l'equipement qui rejette reste nomme"
        # La preuve doit porter la contradiction elle-meme, sinon l'admin
        # relira le titre et repartira sur la mauvaise piste.
        assert "1500" in preuves and "fin" in preuves

    def test_le_faux_positif_ne_passe_plus_devant_les_vrais_verdicts(
            self, regles, tmp_path):
        """La priorite 92 mettait ce flux en tete du rapport. Un flux qui a
        fonctionne ne doit jamais primer sur un flux en panne : c'est ce
        classement qui decide de ce que l'admin lit en premier, et de ce que
        --top laisse tomber."""
        p = tmp_path / "reject_sur_session_reussie.pcap"
        write_pcap(p, _reject_sur_session_reussie())
        _, fv, _, _ = _analyse(regles, p)

        pp = tmp_path / "port_ferme_2.pcap"
        write_pcap(pp, [
            _tcp(0.0, CLIENT, SERVER, 51105, 8443, TH_SYN, seq=1000),
            _tcp(0.002, SERVER, CLIENT, 8443, 51105, TH_RST | TH_ACK,
                 seq=0, ack=1001),
        ])
        _, panne, _, _ = _analyse(regles, pp)

        assert fv.primary.rule.priority < panne.primary.rule.priority, (
            "une session qui a reussi ne doit pas etre classee au-dessus d'un "
            "service injoignable")

    def test_un_vrai_REJECT_de_connexion_reste_intact(self, regles, tmp_path):
        """Le garde-fou : le cas nominal — le SYN part, le firewall repond
        admin-prohibited, rien ne s'etablit — doit garder son verdict RESEAU,
        sa confiance haute et sa priorite maximale."""
        p = tmp_path / "reject_vrai.pcap"
        write_pcap(p, [
            _tcp(0.0, CLIENT, SERVER, 51106, 445, TH_SYN, seq=1000),
            _icmp_unreach(0.003, ROUTER, 13, CLIENT, SERVER, 51106, 445),
        ])
        sig, fv, ids, preuves = _analyse(regles, p)
        assert not sig.established_seen
        assert fv.primary.rule.id == "reject-icmp"
        assert fv.verdict == "RESEAU"
        assert fv.primary.rule.confidence == "haute"
        assert "reject-icmp-session-etablie" not in ids

    def test_un_REJECT_qui_tue_la_session_reste_visible(self, regles, tmp_path):
        """Variante sans cloture propre : la session s'etablit, echange, puis
        s'arrete net juste apres l'ICMP. Le diagnostic doit rester affiche —
        c'est la moitie du cas ou le rejet compte vraiment."""
        p = tmp_path / "reject_tue_session.pcap"
        write_pcap(p, _reject_sur_session_reussie(cport=51107,
                                                  cloture_fin=False))
        sig, fv, ids, preuves = _analyse(regles, p)
        assert sig.closed_by == "none"
        assert fv.primary.rule.id == "reject-icmp-session-etablie"
        assert ROUTER in preuves


# --------------------------------------------------------------------------
# CAS 3 — un port client reutilise fabrique 50 % de perte reseau
# --------------------------------------------------------------------------

def _session_parfaite(t0: float, cseq: int, sseq: int, cport: int = 51201,
                      sport: int = 443, echanges: int = 6):
    """Une session HTTPS irreprochable : handshake, N aller-retours a 10 ms,
    cloture FIN. Aucune perte, aucun dup-ACK, aucune anomalie."""
    pkts = [
        _tcp(t0, CLIENT, SERVER, cport, sport, TH_SYN, seq=cseq),
        _tcp(t0 + 0.001, SERVER, CLIENT, sport, cport, TH_SYN | TH_ACK,
             seq=sseq, ack=cseq + 1),
        _tcp(t0 + 0.002, CLIENT, SERVER, cport, sport, TH_ACK,
             seq=cseq + 1, ack=sseq + 1),
    ]
    c, s, t = cseq + 1, sseq + 1, t0 + 0.01
    for _ in range(echanges):
        req = b"GET " + b"a" * 96
        pkts.append(_tcp(t, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=req))
        pkts.append(_tcp(t + 0.002, SERVER, CLIENT, sport, cport, TH_ACK,
                         seq=s, ack=c + len(req)))
        c += len(req)
        resp = b"200 " + b"b" * 496
        pkts.append(_tcp(t + 0.01, SERVER, CLIENT, sport, cport,
                         TH_PUSH | TH_ACK, seq=s, ack=c, payload=resp))
        s += len(resp)
        pkts.append(_tcp(t + 0.012, CLIENT, SERVER, cport, sport, TH_ACK,
                         seq=c, ack=s))
        t += 0.05
    pkts.append(_tcp(t, CLIENT, SERVER, cport, sport, TH_FIN | TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.001, SERVER, CLIENT, sport, cport, TH_FIN | TH_ACK,
                     seq=s, ack=c + 1))
    pkts.append(_tcp(t + 0.002, CLIENT, SERVER, cport, sport, TH_ACK,
                     seq=c + 1, ack=s + 1))
    return pkts


def _port_client_reutilise():
    """DEUX sessions saines et successives sur le MEME quadruplet : le noyau a
    recycle le port ephemere 51201, chose banale des qu'une capture dure ou que
    l'hote est charge. Les ISN sont tires au hasard a chaque connexion, donc la
    seconde demarre ici SOUS la premiere — une chance sur deux dans la vraie
    vie."""
    return (_session_parfaite(0.0, cseq=3_000_000, sseq=4_000_000)
            + _session_parfaite(5.0, cseq=1000, sseq=2000))


class TestPerteReseauFabriqueeParUnPortRecycle:
    """PREJUDICE : deux sessions PARFAITES ressortaient en une seule
    conversation portant « 12 retransmissions sur 60 paquets (50,0 %) », verdict
    RESEAU, confiance haute — sur une capture ou pas un octet n'a ete perdu.

    La remediation envoie alors relever les compteurs CRC des switchs, chercher
    un duplex mismatch, changer un cable ou un SFP, voire ouvrir un ticket
    operateur. Tout cela pour un compteur de sequence remis a zero par une
    nouvelle connexion.

    La preuve se refutait d'ailleurs elle-meme : « Rafales de dup-ACK : client 0,
    serveur 0 ». Une perte reelle de 50 % sans un seul dup-ACK n'existe pas.

    Cause : build_flows indexait par quadruplet SEUL. Deux connexions
    successives sur le meme port ephemere fusionnaient, et chaque segment de la
    seconde — numeros de sequence plus bas que le maximum atteint par la
    premiere — etait compte comme une retransmission.
    """

    def test_deux_connexions_sur_le_meme_port_ne_fusionnent_pas(
            self, regles, tmp_path):
        p = tmp_path / "port_reuse.pcap"
        write_pcap(p, _port_client_reutilise())
        flows = build_flows(read_capture(p))
        assert len(flows) == 2, (
            "un port ephemere recycle porte DEUX connexions TCP distinctes ; "
            "les fusionner melange deux espaces de numeros de sequence")
        assert [f.key for f in flows] == [
            f"{CLIENT}:51201 -> {SERVER}:443"] * 2

    def test_aucune_perte_n_est_inventee(self, regles, tmp_path):
        p = tmp_path / "port_reuse.pcap"
        write_pcap(p, _port_client_reutilise())
        sigs = [compute_signals(f) for f in build_flows(read_capture(p))]
        for s in sigs:
            assert s.retrans_total == 0, (
                f"{s.retrans_total} retransmissions inventees sur une capture "
                f"qui n'en contient aucune")
            assert s.retrans_rate == 0.0

    def test_le_verdict_n_accuse_plus_le_reseau(self, regles, tmp_path):
        p = tmp_path / "port_reuse.pcap"
        write_pcap(p, _port_client_reutilise())
        sigs = [compute_signals(f) for f in build_flows(read_capture(p))]
        verdicts = evaluate(sigs, regles)
        ids = [m.rule.id for fv in verdicts for m in fv.matches]
        assert "retrans-heavy" not in ids, (
            "aucun paquet n'a ete perdu : accuser le chemin envoie l'admin "
            "changer des cables et ouvrir un ticket operateur pour rien")
        assert all(fv.verdict == "RAS" for fv in verdicts), (
            f"deux sessions irreprochables doivent sortir saines, obtenu "
            f"{[fv.verdict for fv in verdicts]}")

    def test_des_SYN_retransmis_ne_sont_PAS_deux_connexions(
            self, regles, tmp_path):
        """La borne qui rend le correctif sur : un SYN retransmis garde le MEME
        ISN, une nouvelle connexion en tire un nouveau. C'est cette difference,
        et non un delai, qui separe les deux cas. Decouper sur chaque SYN
        casserait le diagnostic de DROP silencieux — trois SYN deviendraient
        trois flux d'un paquet, sous le seuil de syn-no-answer, et la panne la
        mieux detectee de l'outil disparaitrait."""
        p = tmp_path / "syn_retries.pcap"
        write_pcap(p, [
            _tcp(0.0, CLIENT, SERVER, 51202, 443, TH_SYN, seq=1000),
            _tcp(1.0, CLIENT, SERVER, 51202, 443, TH_SYN, seq=1000),
            _tcp(3.0, CLIENT, SERVER, 51202, 443, TH_SYN, seq=1000),
        ])
        sig, fv, ids, preuves = _analyse(regles, p)
        assert sig.syn_count == 3
        assert fv.primary.rule.id == "syn-no-answer"

    def test_une_vraie_retransmission_est_toujours_comptee(
            self, regles, tmp_path):
        """L'autre borne : le correctif ne doit pas rendre le detecteur aveugle.
        Meme connexion, meme ISN, un segment reemis 200 ms plus tard."""
        p = tmp_path / "vraie_retrans.pcap"
        pkts = list(_handshake(0.0, 51203, 443))
        pkts += [
            _tcp(0.01, CLIENT, SERVER, 51203, 443, TH_PUSH | TH_ACK,
                 seq=1001, ack=2001, payload=b"z" * 500),
            _tcp(0.21, CLIENT, SERVER, 51203, 443, TH_PUSH | TH_ACK,
                 seq=1001, ack=2001, payload=b"z" * 500),
        ]
        write_pcap(p, pkts)
        sig, fv, ids, preuves = _analyse(regles, p)
        assert sig.retrans_total == 1

    def test_un_ICMP_va_a_la_connexion_de_son_horodatage(self, regles, tmp_path):
        """Effet de bord a ne pas rater : avec deux connexions sur le meme
        quadruplet, le rattachement des erreurs ICMP devient ambigu. Un REJECT
        emis pendant la seconde connexion ne doit pas etre colle a la premiere,
        sinon l'outil accuse la mauvaise tranche de temps — et l'admin cherche
        le changement de configuration a la mauvaise minute."""
        pkts = _port_client_reutilise()
        pkts.append(_icmp_unreach(5.1, ROUTER, 13, CLIENT, SERVER, 51201, 443))
        p = tmp_path / "port_reuse_icmp.pcap"
        write_pcap(p, pkts)
        flows = build_flows(read_capture(p))
        assert len(flows) == 2
        assert not flows[0].icmp, "la premiere connexion s'est terminee a 0,3 s"
        assert len(flows[1].icmp) == 1, (
            "l'ICMP de 5,1 s appartient a la connexion qui vivait a 5,1 s")


# --------------------------------------------------------------------------
# CAS 4 — un client bouche, accuse sous les traits d'un serveur lent
# --------------------------------------------------------------------------

def _client_qui_ne_vide_pas_sa_socket(cport: int = 51301, sport: int = 5432,
                                      fenetre_fermee: bool = True):
    """Client lent (viewer de logs, tableur, client JDBC qui ne consomme pas son
    curseur) : il envoie sa requete, le serveur accuse reception en 5 ms, puis
    le client ANNONCE UNE FENETRE A ZERO pendant 800 ms. Le serveur a sa reponse
    prete et n'a pas le droit de l'emettre — le controle de flux TCP le bloque.
    La reponse part 10 ms apres la reouverture de la fenetre.

    `fenetre_fermee=False` rejoue la meme conversation SANS la fenetre fermee :
    la, le serveur est reellement lent, et le diagnostic applicatif est juste.
    """
    pkts = _handshake(0.0, cport, sport)
    c, s = 1001, 2001
    for t0 in (0.01, 2.0, 4.0):
        req = b"SELECT" + b"x" * 194
        pkts.append(_tcp(t0, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=req))
        # ACK pur immediat : la pile TCP du serveur a bien recu la requete.
        pkts.append(_tcp(t0 + 0.005, SERVER, CLIENT, sport, cport, TH_ACK,
                         seq=s, ack=c + len(req)))
        c += len(req)
        if fenetre_fermee:
            for dt in (0.01, 0.40):
                pkts.append(_tcp(t0 + dt, CLIENT, SERVER, cport, sport, TH_ACK,
                                 seq=c, ack=s, win=0))
            pkts.append(_tcp(t0 + 0.81, CLIENT, SERVER, cport, sport, TH_ACK,
                             seq=c, ack=s, win=65535))
        resp = b"ROWS" + b"y" * 396
        pkts.append(_tcp(t0 + 0.82, SERVER, CLIENT, sport, cport,
                         TH_PUSH | TH_ACK, seq=s, ack=c, payload=resp))
        s += len(resp)
        pkts.append(_tcp(t0 + 0.825, CLIENT, SERVER, cport, sport, TH_ACK,
                         seq=c, ack=s))
    return pkts


class TestServeurAccuseAlorsQueLeClientEtaitBouche:
    """PREJUDICE : le verdict de tete est « APP — Reponse applicative lente,
    reception prouvee par ACK rapide », confiance haute, et sa remediation dit
    mot pour mot : « Le reseau a livre la requete (ACK immediat) puis a attendu
    l'application. Chercher COTE APPLICATIF de 10.0.0.5:5432 ».

    Or la capture prouve l'inverse : pendant 800 des 820 ms, c'est le CLIENT qui
    tenait sa fenetre fermee. Le serveur avait sa reponse prete et n'avait pas le
    droit de l'emettre. L'admin part profiler une base de donnees, relire des
    logs applicatifs et suspecter un pool de connexions, sur une machine qui n'a
    rien fait de mal — pendant que le poste reellement en cause n'est meme pas
    regarde.

    Le bon verdict etait bien present, mais relegue en ligne grise de signaux
    secondaires : zero-window-client (HOTE, priorite 83) perdait d'un point
    contre slow-app-proven (84). Une preuve qui contredit le verdict principal
    ne doit pas etre imprimee sous lui — elle doit l'empecher.
    """

    def test_le_serveur_n_est_pas_accuse_quand_le_client_bloque_le_flux(
            self, regles, tmp_path):
        p = tmp_path / "client_bouche.pcap"
        write_pcap(p, _client_qui_ne_vide_pas_sa_socket())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.zw_max_ms_from_client >= 100, "le piege est bien arme"
        assert sig.ttfb_ms_p95 >= 500 and sig.server_ack_delay_ms_p95 < 250
        assert "slow-app-proven" not in ids, (
            "800 ms de fenetre fermee cote client expliquent a eux seuls les "
            "820 ms de reponse : la capture ne prouve plus rien sur l'app du "
            "serveur, et la regle doit se taire au lieu de l'accuser")
        assert "slow-app-likely" not in ids
        assert "COTE APPLICATIF" not in fv.primary.remediation

    def test_le_verdict_designe_le_poste_reellement_bloque(
            self, regles, tmp_path):
        p = tmp_path / "client_bouche.pcap"
        write_pcap(p, _client_qui_ne_vide_pas_sa_socket())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert fv.primary.rule.id == "zero-window-client"
        assert fv.verdict == "HOTE"
        assert CLIENT in preuves and "800" in preuves

    def test_un_serveur_vraiment_lent_reste_accuse(self, regles, tmp_path):
        """Le garde-fou, et il est vital : slow-app-proven est le diagnostic
        phare de l'outil, celui de la page d'accueil. La meme conversation, sans
        la fenetre fermee, doit rendre exactement le meme verdict qu'avant."""
        p = tmp_path / "serveur_lent.pcap"
        write_pcap(p, _client_qui_ne_vide_pas_sa_socket(cport=51302,
                                                        fenetre_fermee=False))
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.zw_from_client == 0
        assert fv.primary.rule.id == "slow-app-proven"
        assert fv.verdict == "APP"
        assert fv.primary.rule.confidence == "haute"

    def test_une_fenetre_client_fugace_n_inhibe_rien(self, regles, tmp_path):
        """L'autre borne. Le seuil d'inhibition est CELUI de
        zero-window-client (100 ms), pas « une annonce quelconque » : les deux
        regles restent strictement complementaires, donc aucun flux ne peut
        tomber entre elles et ressortir « tableau incomplet ». Ici la fenetre se
        referme 20 ms — du reglage fin de buffer, pas une explication des
        820 ms."""
        pkts = _handshake(0.0, 51303, 5432)
        c, s = 1001, 2001
        for t0 in (0.01, 2.0, 4.0):
            req = b"SELECT" + b"x" * 194
            pkts.append(_tcp(t0, CLIENT, SERVER, 51303, 5432, TH_PUSH | TH_ACK,
                             seq=c, ack=s, payload=req))
            pkts.append(_tcp(t0 + 0.005, SERVER, CLIENT, 5432, 51303, TH_ACK,
                             seq=s, ack=c + len(req)))
            c += len(req)
            pkts.append(_tcp(t0 + 0.01, CLIENT, SERVER, 51303, 5432, TH_ACK,
                             seq=c, ack=s, win=0))
            pkts.append(_tcp(t0 + 0.03, CLIENT, SERVER, 51303, 5432, TH_ACK,
                             seq=c, ack=s, win=65535))
            resp = b"ROWS" + b"y" * 396
            pkts.append(_tcp(t0 + 0.82, SERVER, CLIENT, 5432, 51303,
                             TH_PUSH | TH_ACK, seq=s, ack=c, payload=resp))
            s += len(resp)
            pkts.append(_tcp(t0 + 0.825, CLIENT, SERVER, 51303, 5432, TH_ACK,
                             seq=c, ack=s))
        p = tmp_path / "fenetre_fugace.pcap"
        write_pcap(p, pkts)
        sig, fv, ids, preuves = _analyse(regles, p)

        assert 0 < sig.zw_max_ms_from_client < 100
        assert fv.primary.rule.id == "slow-app-proven", (
            "20 ms de fenetre fermee n'expliquent pas 820 ms d'attente")

    def test_le_serveur_bouche_reste_un_probleme_du_serveur(
            self, regles, tmp_path):
        """Symetrie : quand c'est le SERVEUR qui ferme sa fenetre, rien ne
        change — l'inhibition ne porte que sur le cote client, seul capable
        d'expliquer une reponse retardee par le controle de flux."""
        sig, fv, ids, preuves = _analyse(
            regles, _ecrire(tmp_path / "serveur_bouche.pcap",
                            _zero_window_serveur()))
        assert fv.primary.rule.id == "zero-window-server"
        assert fv.verdict == "HOTE"


# --------------------------------------------------------------------------
# CAS 5 — la decouverte de MTU qui fonctionne, declaree panne reseau
# --------------------------------------------------------------------------

def _pmtud(cport: int = 51401, sport: int = 443, reduit: bool = True):
    """Transfert sortant a travers un tunnel (IPsec, VPN, PPPoE) dont la MTU
    est plus petite. Le premier segment de 1460 octets ne passe pas, le routeur
    renvoie un ICMP 'fragmentation needed' — et l'emetteur fait exactement ce
    que la norme prevoit : il repart a 1400 octets, tout passe, la session se
    ferme par FIN.

    `reduit=False` rejoue le vrai trou noir : l'emetteur n'ecoute pas l'ICMP et
    continue a pousser du 1460 qui ne passera jamais.
    """
    taille = 1400 if reduit else 1460
    pkts = _handshake(0.0, cport, sport)
    c, s = 1001, 2001
    pkts.append(_tcp(0.010, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                     seq=c, ack=s, payload=b"P" * 1460))
    pkts.append(_icmp_unreach(0.013, ROUTER, 4, CLIENT, SERVER, cport, sport))
    t = 0.02
    for _ in range(5):
        pkts.append(_tcp(t, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
                         seq=c, ack=s, payload=b"P" * taille))
        if reduit:
            pkts.append(_tcp(t + 0.003, SERVER, CLIENT, sport, cport, TH_ACK,
                             seq=s, ack=c + taille))
            c += taille
        t += 0.2
    if not reduit:
        return pkts                     # rien ne passe, rien ne se ferme
    pkts.append(_tcp(t, SERVER, CLIENT, sport, cport, TH_PUSH | TH_ACK,
                     seq=s, ack=c, payload=b"OK" * 100))
    s += 200
    pkts.append(_tcp(t + 0.002, CLIENT, SERVER, cport, sport, TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.01, CLIENT, SERVER, cport, sport, TH_FIN | TH_ACK,
                     seq=c, ack=s))
    pkts.append(_tcp(t + 0.011, SERVER, CLIENT, sport, cport, TH_FIN | TH_ACK,
                     seq=s, ack=c + 1))
    pkts.append(_tcp(t + 0.012, CLIENT, SERVER, cport, sport, TH_ACK,
                     seq=c + 1, ack=s + 1))
    return pkts


class TestDecouverteDeMTUReussieDeclareePanne:
    """PREJUDICE : sur un site derriere un tunnel a MTU reduite — cas de figure
    d'une entreprise sur deux — CHAQUE connexion produit un ICMP 'fragmentation
    needed', et la pile emettrice reduit son calibre comme prevu. Le transfert
    passe, la session se ferme proprement.

    L'outil rendait quand meme « Probleme de MTU sur le chemin », RESEAU,
    confiance haute, priorite 86. Consequences :
      * TOUS les flux de la capture ressortent en rouge, et la panne pour
        laquelle l'admin a capture disparait sous le bruit ou hors de --top ;
      * la remediation prescrit un clamp de MSS sur un equipement de tunnel en
        production, pour un mecanisme qui fonctionnait deja.

    Un trou noir de MTU, c'est precisement l'inverse : l'emetteur ne reduit
    JAMAIS son calibre (souvent parce que l'ICMP est filtre en amont) et le
    transfert gele. La capture porte la difference — la taille des segments
    avant et apres l'erreur — mais aucun champ ne la mesurait.
    """

    def test_une_decouverte_de_MTU_qui_marche_n_est_pas_une_panne_reseau(
            self, regles, tmp_path):
        p = tmp_path / "pmtud_ok.pcap"
        write_pcap(p, _pmtud())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.icmp_frag_needed and sig.closed_by == "fin"
        assert sig.bytes_c2s > 7000, "le transfert est bien passe"
        assert not sig.frag_needed_ignored, (
            "l'emetteur est passe de 1460 a 1400 octets : la decouverte de MTU "
            "a fonctionne, la capture le montre segment par segment")
        assert "mtu-blackhole" not in ids, (
            "un transfert de 7 ko qui aboutit et se ferme par FIN n'est pas un "
            "trou noir de MTU")
        assert fv.verdict != "RESEAU"

    def test_le_constat_reste_dit_sans_prescrire_de_changement(
            self, regles, tmp_path):
        """Se taire completement serait un autre defaut : la MTU reduite est
        reelle, et le jour ou un equipement filtrera l'ICMP type 3 code 4 elle
        deviendra un blocage total. Le fait est dit, a sa vraie place dans le
        classement, et sans confiance haute."""
        p = tmp_path / "pmtud_ok.pcap"
        write_pcap(p, _pmtud())
        sig, fv, ids, preuves = _analyse(regles, p)

        assert fv.primary.rule.id == "mtu-decouverte-reussie"
        assert fv.primary.rule.confidence == "faible"
        assert "1460" in preuves and "1400" in preuves, (
            "la preuve doit porter les deux calibres : c'est elle qui distingue "
            "ce cas d'un trou noir")

    def test_un_vrai_trou_noir_de_MTU_reste_diagnostique(self, regles, tmp_path):
        """Le garde-fou. Meme tunnel, meme ICMP, mais l'emetteur n'a pas reduit :
        rien ne passe. Verdict RESEAU, confiance haute, priorite maximale — et
        c'est la que le clamp de MSS est le bon geste."""
        p = tmp_path / "mtu_trou_noir.pcap"
        write_pcap(p, _pmtud(cport=51402, reduit=False))
        sig, fv, ids, preuves = _analyse(regles, p)

        assert sig.frag_needed_ignored, (
            "l'emetteur continue a 1460 octets apres l'ICMP : il ne l'a pas "
            "pris en compte")
        assert fv.primary.rule.id == "mtu-blackhole"
        assert fv.verdict == "RESEAU"
        assert fv.primary.rule.confidence == "haute"
        assert "mtu-decouverte-reussie" not in ids

    def test_le_cas_informatif_ne_passe_pas_devant_une_vraie_panne(
            self, regles, tmp_path):
        p = tmp_path / "pmtud_ok.pcap"
        write_pcap(p, _pmtud())
        _, ok, _, _ = _analyse(regles, p)
        pb = tmp_path / "mtu_trou_noir.pcap"
        write_pcap(pb, _pmtud(cport=51402, reduit=False))
        _, panne, _, _ = _analyse(regles, pb)
        assert ok.primary.rule.priority < panne.primary.rule.priority


def _ecrire(path: Path, pkts) -> Path:
    write_pcap(path, pkts)
    return path


def _zero_window_serveur(cport: int = 51304, sport: int = 8080):
    """Le cas nominal de zero-window-server, inchange par ce durcissement."""
    pkts = _handshake(0.0, cport, sport)
    pkts += [
        _tcp(0.01, CLIENT, SERVER, cport, sport, TH_PUSH | TH_ACK,
             seq=1001, ack=2001, payload=b"Q" * 1000),
        _tcp(0.04, SERVER, CLIENT, sport, cport, TH_ACK,
             seq=2001, ack=2001, win=0),
        _tcp(0.20, SERVER, CLIENT, sport, cport, TH_ACK,
             seq=2001, ack=2001, win=0),
        _tcp(0.44, SERVER, CLIENT, sport, cport, TH_ACK,
             seq=2001, ack=2001, win=65535),
        _tcp(0.45, SERVER, CLIENT, sport, cport, TH_PUSH | TH_ACK,
             seq=2001, ack=2001, payload=b"R" * 500),
        _tcp(0.46, CLIENT, SERVER, cport, sport, TH_ACK, seq=2001, ack=2501),
    ]
    return pkts
