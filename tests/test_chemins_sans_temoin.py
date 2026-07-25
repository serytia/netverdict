"""Chemins de code qui n'avaient AUCUN test capable de detecter leur panne.

Trouves le 25/07/2026 non pas en lisant les tests — un test peut passer sans
rien prouver — mais en cassant chaque chemin et en constatant que les 158 tests
de la suite restaient verts. Les cinq mutations passaient inapercues :

  1. `unless` n'inhibe plus aucune regle          (engine.py)
  2. le repli AMBIGU n'est jamais emis            (engine.py)
  3. l'ancre d'annee RFC3164 est ignoree          (cli.py)
  4. l'attribution ne trie plus par proximite     (correlate.py)
  5. l'ancre est sautee quand t_last == 0.0       (cli.py, defaut corrige ici)

Les quatre premiers etaient du code juste mais sans filet. Le cinquieme etait un
vrai defaut : `if cap.t_last:` traite l'epoch 0 comme une absence.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from dpkt.tcp import TH_SYN
from make_fixtures import CLIENT, SERVER, _tcp, write_pcap

from netverdict.cli import main
from netverdict.correlate import attribution_for
from netverdict.rules.engine import FlowVerdict, evaluate, load_rules
from netverdict.signals import FlowSignals
from netverdict.timeline import ConnectionInfo, Timeline, TimelineEvent


@pytest.fixture(scope="module")
def regles():
    return load_rules()


class TestUnlessInhibeVraiment:
    """`unless` est le seul mecanisme qui empeche deux regles de raconter la
    meme panne deux fois. Le test qui existait verifiait la regle GAGNANTE, or
    reject-icmp (priorite 92) gagne de toute facon contre 91 : la mutation
    « unless n'inhibe plus rien » passait donc inapercue."""

    def test_un_reject_explicite_inhibe_la_regle_generique(self, regles):
        sig = FlowSignals(client=CLIENT, server=SERVER, cport=51001, sport=443,
                          pkts_total=6, syn_count=3, synack_seen=False,
                          rst_to_syn=False, icmp_unreach_count=2,
                          icmp_admin_prohibited=True,
                          icmp_admin_prohibited_from="192.168.1.1")
        ids = [m.rule.id for m in evaluate([sig], regles)[0].matches]
        assert ids[0] == "reject-icmp"
        # LE point du test : la regle inhibee ne doit pas apparaitre du tout,
        # pas meme en signal secondaire.
        assert "syn-no-answer-icmp-unreach" not in ids, (
            "un REJECT explicite doit inhiber le diagnostic generique")

    def test_sans_le_reject_la_regle_generique_matche(self, regles):
        """Le controle : sans quoi le test ci-dessus passerait aussi si la regle
        ne matchait jamais, pour une raison quelconque."""
        sig = FlowSignals(client=CLIENT, server=SERVER, cport=51001, sport=443,
                          pkts_total=6, syn_count=3, synack_seen=False,
                          rst_to_syn=False, icmp_unreach_count=2)
        ids = [m.rule.id for m in evaluate([sig], regles)[0].matches]
        assert "syn-no-answer-icmp-unreach" in ids


class TestRepliAmbigu:
    """Quand des anomalies sont mesurees mais qu'aucune regle ne compose un
    diagnostic, l'outil doit le DIRE. Sans ce repli, le flux ressort sans
    verdict du tout : l'admin conclut « rien vu » alors que la mesure porte des
    retransmissions. Le silence est le pire des trois etats possibles."""

    def _sig(self, **k):
        return FlowSignals(client=CLIENT, server=SERVER, cport=51001, sport=443,
                           pkts_total=40, **k)

    def test_des_retransmissions_sous_le_seuil_produisent_un_AMBIGU(self, regles):
        # Handshake absent de la capture (demarree en pleine session) donc
        # `clean` ne peut pas matcher, et le taux est sous le seuil de
        # retrans-heavy : aucune regle ne compose. C'est le cas du repli.
        fv = evaluate([self._sig(handshake_complete=False, retrans_total=2,
                                 retrans_rate=0.002)], regles)[0]
        assert fv.verdict == "AMBIGU"
        assert fv.primary.rule.id == "fallback-ambigu"
        # La preuve doit porter les chiffres bruts : c'est tout ce que l'outil
        # sait, et le cacher rendrait le verdict inexploitable.
        assert "retrans=2" in fv.primary.evidence[0]

    def test_un_flux_sans_aucune_anomalie_ne_recoit_PAS_de_repli(self, regles):
        """La borne : le repli ne doit pas se declencher sur un flux muet, sinon
        toute capture tronquee ressortirait « anomalies presentes »."""
        fv = evaluate([self._sig(handshake_complete=False)], regles)[0]
        assert fv.matches == []
        assert fv.verdict == "RAS"

    @pytest.mark.parametrize("champs", [
        {"retrans_total": 1},
        {"zw_from_client": 1},
        {"zw_from_server": 1},
        {"rst_midstream": True},
        {"syn_count": 1, "synack_seen": False},
    ])
    def test_chaque_famille_d_anomalie_declenche_le_repli(self, regles, champs):
        fv = evaluate([self._sig(handshake_complete=False, **champs)], regles)[0]
        assert fv.primary is not None, f"aucun verdict pour {champs}"
        assert fv.verdict in ("AMBIGU", "RESEAU", "HOTE")


class TestAncrageDeLAnneeSyslog:
    """Une ligne RFC3164 ne porte PAS l'annee. L'ancre de datation doit etre la
    capture et non l'horloge du poste, sinon tout bundle archive voit ses
    evenements projetes dans l'annee courante et sortir de la fenetre — la
    correlation disparait en silence, sans un message d'erreur.

    Les fixtures pcap synthetiques vivent en epoch ~0 (1970) : une ligne
    « Jan  1 00:00:00 » ne tombe dans la fenetre QUE si l'ancre vient du pcap.
    """

    LIGNE = ("<134>Jan  1 00:00:00 fw01 firewalld[512]: "
             "firewall rules reloaded\n")

    def test_l_annee_vient_de_la_capture_et_non_du_poste(self, tmp_path, capsys):
        log = tmp_path / "fw.log"
        log.write_text(self.LIGNE, encoding="utf-8")
        rc = main(["analyze", "tests/fixtures/slow_app.pcap",
                   "--syslog", str(log), "--syslog-tz", "UTC", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1
        evs = out["timeline"]["events"]
        assert len(evs) == 1, (
            "l'evenement doit tomber dans la fenetre de la capture (1970) ; "
            "date sur l'horloge du poste il en sortirait de plusieurs decennies")
        # Ancre = t_last de la capture (~3 s), donc 1970 : l'horodatage resolu
        # doit rester au voisinage de l'epoch, jamais dans l'annee courante.
        assert abs(evs[0]["ts"]) < 86400.0

    def test_un_pcap_a_epoch_zero_garde_son_ancre(self, tmp_path, capsys):
        """Le defaut corrige : `if cap.t_last:` traitait 0.0 comme une absence.
        Sur une capture dont TOUS les paquets sont a l'epoch 0 — pcap
        synthetique ou anonymise — l'ancre etait silencieusement remplacee par
        l'horloge du poste et la correlation tombait a zero."""
        pcap = tmp_path / "epoch0.pcap"
        # Trois SYN sans reponse, tous horodates exactement 0.0 :
        # t_first == t_last == 0.0.
        write_pcap(pcap, [_tcp(0.0, CLIENT, SERVER, 51001, 443, TH_SYN, seq=1000)
                          for _ in range(3)])
        log = tmp_path / "fw.log"
        log.write_text(self.LIGNE, encoding="utf-8")

        rc = main(["analyze", str(pcap), "--syslog", str(log),
                   "--syslog-tz", "UTC", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc in (0, 1), "le CLI ne doit pas sortir en erreur sur cette entree"
        evs = out["timeline"]["events"]
        assert len(evs) == 1, (
            "l'epoch 0 est une VALEUR, pas une absence : l'ancre doit venir du "
            "pcap, sinon la correlation disparait sans le moindre signal")
        # Datee sur 1970 (l'ancre), la ligne « Jan 1 00:00:00 » vaut exactement
        # l'epoch 0. Datee sur l'horloge du poste elle vaudrait ~1,8 milliard.
        assert evs[0]["ts"] == 0.0


class TestTriDesAttributionsProcess:
    """Sur une capture longue, un port client est reutilise : plusieurs
    evenements de connexion collent au meme quadruplet. Le plus proche du debut
    du flux est retenu — sans ce tri, l'outil nomme un process au hasard, ce qui
    envoie l'admin auditer le mauvais programme avec l'air d'une certitude."""

    def _event(self, ts, pid, image):
        return TimelineEvent(
            ts=ts, source="evtx", host="hote", category="network", severity=0,
            ident="3", message=f"connexion {pid}", tz_known=True,
            connection=ConnectionInfo(src_ip=CLIENT, src_port=51001,
                                      dst_ip=SERVER, dst_port=443,
                                      protocol="tcp", pid=pid, image=image,
                                      user="hote\\svc", initiated=True))

    def _flux(self, t_first=1000.0, duration=2.0):
        sig = FlowSignals(client=CLIENT, server=SERVER, cport=51001, sport=443,
                          t_first=t_first, duration_s=duration)
        return FlowVerdict(signals=sig, matches=[])

    def test_le_process_retenu_est_le_plus_proche_du_debut_du_flux(self):
        # Deux candidats valides : l'un a 30 s avant, l'autre a 1 s avant.
        tl = Timeline()
        tl.events = [self._event(970.0, 111, "C:\\vieux.exe"),
                     self._event(999.0, 222, "C:\\bon.exe")]
        a = attribution_for(self._flux(), tl)
        assert a is not None
        assert a.connection.pid == 222, "le plus proche du debut du flux"
        assert a.candidates == 2, "l'ambiguite doit etre signalee, pas tue"
        assert "2 connexions" in a.describe()

    def test_l_ordre_du_fichier_journal_ne_decide_pas(self):
        """Le meme cas, evenements inverses dans le journal : le resultat doit
        etre identique. Sans tri, c'est l'ordre de lecture qui gagne — un
        detail de mise en forme deciderait quel process est accuse."""
        tl = Timeline()
        tl.events = [self._event(999.0, 222, "C:\\bon.exe"),
                     self._event(970.0, 111, "C:\\vieux.exe")]
        assert attribution_for(self._flux(), tl).connection.pid == 222

    def test_un_evenement_pendant_le_flux_peut_gagner(self):
        """La proximite se mesure en valeur ABSOLUE : un evenement 0,5 s apres
        le premier paquet est plus proche qu'un evenement 30 s avant."""
        tl = Timeline()
        tl.events = [self._event(970.0, 111, "C:\\vieux.exe"),
                     self._event(1000.5, 333, "C:\\pendant.exe")]
        assert attribution_for(self._flux(), tl).connection.pid == 333
