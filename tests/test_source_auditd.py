"""Unitaires du parseur auditd Linux (netverdict/sources/auditd.py).

sample_audit.log est un fichier audit.log "pur" (aucun commentaire dedans :
un vrai audit.log n'en a pas). Les attentes sont documentees ICI.

Contenu de la fixture (l'ordre PHYSIQUE des blocs SYSCALL/SOCKADDR est
volontairement melange -- serial 12346 (ts .202) puis 12347 (ts .777) puis
12345 (ts .501) -- pour prouver que le tri final n'est pas un hasard) :

  - CONFIG_CHANGE, DAEMON_START : records auditd valides, hors sujet (ni
    SYSCALL ni SOCKADDR) -> ni parsed ni unparsed.
  - ligne vide -> unparsed.
  - serial 12346 : wget -> 10.2.0.2:443 (saddr donne dans l'enonce), avec un
    PROCTITLE(99999) INTERCALE entre le SYSCALL et le SOCKADDR -> prouve la
    jointure par serial, pas par adjacence.
  - serial 12347 : ssh -> 2001:db8::42:8443 (IPv6).
  - serial 12345 : curl -> 172.16.0.10:80 (saddr donne dans l'enonce, verifie
    a la main).
  - serial 12348 : dockerd -> AF_UNIX (/var/run/docker.sock) -> ignore, PAS
    unparsed (record valide, juste hors sujet).
  - serial 12349 : nc, SYSCALL success=no malgre un SOCKADDR valide -> pas de
    connexion (echec du connect()), PAS unparsed.
  - serial 12350 : python3, SYSCALL success=yes SANS SOCKADDR associe -> pas
    de connexion, pas de crash.
  - 2 lignes poubelle (SYSCALL tronque en plein milieu, ligne de commentaire
    de corruption disque) -> unparsed.

  Donc : total_lines=26, evenements produits=3 (12345, 12346, 12347),
  unparsed=3 (ligne vide + 2 lignes poubelle).
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from netverdict.sources import auditd
from netverdict.sources.auditd import _NotIpFamily, _decode_saddr, _parse_fields
from netverdict.timeline import SourceStats, Timeline

FIXTURE = Path(__file__).parent / "fixtures" / "events" / "sample_audit.log"


def _parsed():
    return auditd.parse(FIXTURE)


def _by_pid(events, pid):
    return next(e for e in events if e.connection is not None and e.connection.pid == pid)


def _tl(events):
    tl = Timeline()
    tl.add_source("auditd", events, SourceStats())
    return tl


# --------------------------------------------------------------- decodage saddr
# Verifie A LA MAIN, avec les deux exemples fournis dans la specification.

class TestDecodeSaddr:
    def test_ipv4_exemple_1_verifie_a_la_main(self):
        # saddr=02000050AC10000A0000000000000000
        # famille : "0200" en little-endian -> 0x0002 = 2 = AF_INET.
        # port    : "0050" en big-endian    -> 0x0050 = 80.
        # ip      : "AC10000A" -> AC=172, 10=16, 00=0, 0A=10 -> 172.16.0.10.
        ip, port = _decode_saddr("02000050AC10000A0000000000000000")
        assert (ip, port) == ("172.16.0.10", 80)

    def test_ipv4_exemple_2_verifie_a_la_main(self):
        # saddr=020001BB0A020002
        # port : "01BB" -> 0x01BB = 443. ip : "0A020002" -> 10.2.0.2.
        ip, port = _decode_saddr("020001BB0A020002")
        assert (ip, port) == ("10.2.0.2", 443)

    def test_ipv6(self):
        # Construit a partir des memes regles (family=10 "0A00", port BE,
        # flowinfo 4 octets, puis 16 octets d'adresse) : 2001:db8::42, port
        # 8443 (0x20FB). L'assemblage est verifie ci-dessous par un chemin
        # INDEPENDANT (encodage via les primitives socket/int, plutot que
        # recopier le meme calcul a la main que le decodeur).
        family = (10).to_bytes(2, "little")
        port_bytes = (8443).to_bytes(2, "big")
        flowinfo = b"\x00" * 4
        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::42")
        saddr_hex = (family + port_bytes + flowinfo + addr).hex()
        assert saddr_hex.upper() == "0A0020FB0000000020010DB8000000000000000000000042"

        ip, port = _decode_saddr(saddr_hex)
        assert (ip, port) == ("2001:db8::42", 8443)

    def test_af_unix_leve_not_ip_family_sans_etre_une_erreur(self):
        # "0100" = AF_UNIX : famille valide, mais pas une connexion reseau.
        with pytest.raises(_NotIpFamily):
            _decode_saddr("01002F7661722F72756E2F646F636B65722E736F636B0000")

    @pytest.mark.parametrize("bad,pourquoi", [
        ("", "vide"),
        ("0", "longueur impaire"),
        ("020", "longueur impaire"),
        ("02000ZZZ", "non hexadecimal"),
        ("0200", "trop court pour porter un port"),
        ("020000500A", "AF_INET tronque (adresse incomplete)"),
    ])
    def test_hex_casse_leve_value_error(self, bad, pourquoi):
        with pytest.raises(ValueError):
            _decode_saddr(bad)


class TestParseFields:
    def test_valeurs_quotees_et_nues(self):
        fields = _parse_fields(
            'arch=c000003e syscall=42 success=yes comm="curl" '
            'exe="/usr/bin/curl" key="netverdict_connect"')
        assert fields["syscall"] == "42"
        assert fields["success"] == "yes"
        assert fields["comm"] == "curl"
        assert fields["exe"] == "/usr/bin/curl"


# --------------------------------------------------------------- parse() bout en bout

class TestParseFixture:
    def test_comptes(self):
        events, stats = _parsed()
        assert stats.total_lines == 26
        assert stats.unparsed == 3        # ligne vide + 2 lignes poubelle
        # 4 et non 3 : le connect() en success=no (serial 12349, nc) compte
        # desormais comme une connexion — voir
        # test_success_no_produit_QUAND_MEME_une_connexion pour le pourquoi.
        assert len(events) == 4
        assert stats.parsed == 4          # meme raison

    def test_trie_par_ts_croissant_malgre_l_ordre_du_fichier(self):
        """Le fichier place le serial 12346 (ts .202) avant 12347 (.777) avant
        12345 (.501) : un ordre de sortie qui suit l'ordre du fichier ne
        prouverait rien sur le tri."""
        events, _ = _parsed()
        tss = [e.ts for e in events]
        assert tss == sorted(tss)
        # 1785018190.3 = le connect() success=no, desormais retenu.
        assert tss == [1785018155.501, 1785018160.202, 1785018170.777,
                       1785018190.3]

    def test_connexion_ipv4_curl(self):
        events, _ = _parsed()
        e = _by_pid(events, 11900)
        c = e.connection
        assert (c.src_ip, c.src_port) == ("", 0)
        assert (c.dst_ip, c.dst_port) == ("172.16.0.10", 80)
        assert (c.protocol, c.initiated) == ("tcp", True)
        assert c.image == "/usr/bin/curl"
        assert c.user == "1000"
        assert e.ts == 1785018155.501
        assert e.source == "auditd"
        assert e.host == ""
        assert e.category == "info"
        assert e.severity == 0
        assert e.ident == "connect"
        assert e.tz_known is True
        assert "curl (pid 11900)" in e.message
        assert "172.16.0.10:80" in e.message

    def test_connexion_ipv4_wget_jointure_non_adjacente(self):
        """Le SOCKADDR de ce serial est separe du SYSCALL par un PROCTITLE
        d'un AUTRE serial (99999) dans le fichier : la jointure doit quand
        meme se faire, par serial et non par position."""
        events, _ = _parsed()
        e = _by_pid(events, 11901)
        c = e.connection
        assert (c.dst_ip, c.dst_port) == ("10.2.0.2", 443)
        assert c.image == "/usr/bin/wget"

    def test_connexion_ipv6_ssh(self):
        events, _ = _parsed()
        e = _by_pid(events, 11902)
        c = e.connection
        assert (c.dst_ip, c.dst_port) == ("2001:db8::42", 8443)
        assert c.image == "/usr/bin/ssh"

    def test_af_unix_ignore_sans_etre_unparsed(self):
        """serial 12348 (dockerd -> /var/run/docker.sock) : record SOCKADDR
        valide mais hors sujet. Ne doit produire NI evenement NI unparsed --
        c'est deja verifie par test_comptes (unparsed==3 pile), ce test
        rend l'intention explicite."""
        events, _ = _parsed()
        assert all(e.connection is None or e.connection.pid != 11903
                   for e in events)

    def test_success_no_produit_QUAND_MEME_une_connexion(self):
        """serial 12349 (nc) : SYSCALL avec success=no.

        INVERSION VOLONTAIRE du test d'origine, sur constat kernel (26/07).
        Un `success=no` ne signifie PAS « pas de connexion » :
          - les sockets NON BLOQUANTES (curl, navigateurs, clients async)
            journalisent systematiquement `success=no exit=-115` (EINPROGRESS)
            alors que la connexion s'etablit normalement ensuite ;
          - un echec reel (ECONNREFUSED, ETIMEDOUT) laisse un flux dans le
            pcap, et c'est justement le cas ou l'admin veut savoir QUI a tente.
        Sur le journal reel du lab, filtrer sur success=yes rejetait 100 % des
        connexions de curl."""
        events, _ = _parsed()
        assert any(e.connection is not None and e.connection.pid == 11904
                   for e in events)

    def test_syscall_sans_sockaddr_ne_crashe_pas(self):
        """serial 12350 (python3) : SYSCALL reussi mais aucun SOCKADDR ne
        porte ce serial -> pas de connexion, et surtout pas d'exception."""
        events, _ = _parsed()
        assert all(e.connection is None or e.connection.pid != 11905
                   for e in events)


# --------------------------------------------------------------- garde-fou

class TestGardeFou:
    def test_records_valides_sans_connexion_pose_une_note_actionnable(self, tmp_path):
        """auditd tourne (le fichier contient de vrais records) mais la
        regle -S connect n'est pas chargee : aucun SYSCALL+SOCKADDR de
        connexion n'apparait jamais. La note doit contenir la commande a
        lancer, pas juste dire que quelque chose manque."""
        f = tmp_path / "audit.log"
        f.write_text(
            'type=CONFIG_CHANGE msg=audit(1785018139.000:1): op=add_rule list=4 res=1\n'
            'type=SYSCALL msg=audit(1785018140.000:2): arch=c000003e syscall=59 '
            'success=yes exit=0 pid=100 uid=0 comm="bash" exe="/usr/bin/bash"\n'
            'type=EOE msg=audit(1785018140.000:2):\n',
            encoding="utf-8")
        events, stats = auditd.parse(f)
        assert events == []
        assert "auditctl -a always,exit -F arch=b64 -S connect" in stats.note
        assert "/etc/audit/rules.d/" in stats.note

    def test_fichier_avec_connect_note_vide(self):
        _events, stats = _parsed()
        assert stats.note == ""

    def test_fichier_sans_aucun_record_valide_pas_de_note(self, tmp_path):
        """Un fichier qui ne contient RIEN qui ressemble a de l'audit (pas
        un seul record reconnu) n'est pas le cas que la note vise -- pas de
        quoi alerter sur une regle manquante si le fichier n'est meme pas
        un audit.log."""
        f = tmp_path / "audit.log"
        f.write_text("ceci n'est pas un fichier audit\n", encoding="utf-8")
        events, stats = auditd.parse(f)
        assert events == []
        assert stats.note == ""
        assert stats.unparsed == 1


# --------------------------------------------------------------- robustesse

class TestRobustesse:
    def test_fichier_illisible_leve_value_error(self, tmp_path):
        absent = tmp_path / "n_existe_pas.log"
        with pytest.raises(ValueError):
            auditd.parse(absent)


# --------------------------------------------------------------- integration correlate
#
# correlate._side_of (v1.2) accepte desormais un match SUR LA DESTINATION
# SEULE quand conn.src_ip/src_port sont vides (c'est exactement le cas
# auditd : connect() ne donne jamais la source), et marque alors
# ProcessAttribution.exact=False -- le rapport doit dire que la correspondance
# est plus faible (un autre process visant le meme service:port au meme
# instant serait indiscernable). Ce test integre auditd.parse() de bout en
# bout avec attribution_for() pour le PROUVER plutot que l'affirmer : c'est
# le test qui aurait echoue si cette prise en charge n'existait pas.

class TestIntegrationCorrelate:
    def test_dst_seul_attribue_le_process_cote_client_en_mode_non_exact(
            self, analyze, tmp_path):
        from netverdict.correlate import attribution_for

        _sig, fv = analyze("syn_no_answer")
        s = fv.signals  # client 10.99.0.1:46004 -> serveur 10.99.0.2:8080

        family = (2).to_bytes(2, "little")
        port_bytes = s.sport.to_bytes(2, "big")
        addr = socket.inet_aton(s.server)
        saddr_hex = (family + port_bytes + addr).hex()

        f = tmp_path / "audit.log"
        ts = f"{s.t_first:.3f}"
        f.write_text(
            f'type=SYSCALL msg=audit({ts}:1): arch=c000003e syscall=42 '
            f'success=yes exit=0 pid=4212 uid=1000 comm="curl" '
            f'exe="/usr/bin/curl" key="netverdict_connect"\n'
            f'type=SOCKADDR msg=audit({ts}:1): saddr={saddr_hex}\n',
            encoding="utf-8")

        events, _stats = auditd.parse(f)
        assert len(events) == 1
        c = events[0].connection
        # Le dst produit par le parseur colle exactement au flux...
        assert (c.dst_ip, c.dst_port) == (s.server, s.sport)
        # ...et la source est structurellement vide (connect() ne la donne
        # pas) -- c'est justement le cas que le fallback dst-seul couvre :
        assert (c.src_ip, c.src_port) == ("", 0)

        a = attribution_for(fv, _tl(events))
        assert a is not None
        assert a.side == "client"
        assert a.exact is False
        assert a.candidates == 1
        assert "curl (pid 4212)" in a.describe()
        # describe() sans lang explicite suit desormais le defaut de l'outil
        # (anglais depuis 0.7.0) : voir test_i18n.py pour la bascule --lang.
        assert "DESTINATION only" in a.describe()

    def test_un_dst_different_ne_matche_toujours_pas(self, analyze, tmp_path):
        """Le fallback dst-seul ne doit pas devenir un match a vide : un
        serveur:port different reste un flux different, meme sans source."""
        from netverdict.correlate import attribution_for

        _sig, fv = analyze("syn_no_answer")
        s = fv.signals

        family = (2).to_bytes(2, "little")
        port_bytes = (9999).to_bytes(2, "big")   # port serveur DIFFERENT
        addr = socket.inet_aton(s.server)
        saddr_hex = (family + port_bytes + addr).hex()

        f = tmp_path / "audit.log"
        ts = f"{s.t_first:.3f}"
        f.write_text(
            f'type=SYSCALL msg=audit({ts}:1): arch=c000003e syscall=42 '
            f'success=yes exit=0 pid=1 uid=0 comm="x" exe="/x"\n'
            f'type=SOCKADDR msg=audit({ts}:1): saddr={saddr_hex}\n',
            encoding="utf-8")

        events, _stats = auditd.parse(f)
        assert attribution_for(fv, _tl(events)) is None
