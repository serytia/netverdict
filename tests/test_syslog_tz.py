"""--syslog-tz : fuseau explicite pour les lignes RFC3164 (v1.2).

Le defaut du RFC3164 est d'etre SANS fuseau. Interprete dans le fuseau du
poste d'analyse, un syslog central en UTC se decale et sort de la fenetre de
la capture -> le rapport dit « aucun changement detecte », ce qui se lit
« rien n'a change ». Panne silencieuse : ces tests verrouillent le correctif.

EPOCH DE REFERENCE, calcule A LA MAIN par DEUX chemins independants qui
doivent converger (meme discipline que test_source_syslog.py) :

  Cible : 2026-07-24 14:02:11 (heure de paroi, fuseau variable selon le test)

  Chemin 1 (jours depuis l'epoch 1970-01-01) :
    1970->2026 = 56 ans ; bissextiles dans [1972..2024] par pas de 4, dont
    2000 (divisible par 400, donc bissextile) = 14 -> 56*365 + 14 = 20 454 j
    jusqu'au 2026-01-01. Puis jan31+fev28+mar31+avr30+mai31+jun30 = 181 j
    jusqu'au 01/07, + 23 j jusqu'au 24/07 = 204 j.
    20 454 + 204 = 20 658 j * 86 400 = 1 784 851 200 s = 2026-07-24T00:00:00Z

  Chemin 2 (ancre independante 2000-01-01T00:00:00Z = 946 684 800) :
    2000->2026 = 26 ans ; bissextiles [2000..2024] pas de 4 = 7
    -> 26*365 + 7 = 9 497 j, + 204 j = 9 701 j * 86 400 = 838 166 400
    946 684 800 + 838 166 400 = 1 784 851 200  <- IDENTIQUE, les deux
    chemins concordent.

  14h02m11 de paroi = 50 531 s apres minuit dans le fuseau considere.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netverdict.sources.syslog import _rfc3164_epoch, parse, parse_tz

_MIDNIGHT_24_07_2026_UTC = 1_784_851_200
_WALL_14_02_11 = 14 * 3600 + 2 * 60 + 11          # 50 531 s

TS_RAW = "Jul 24 14:02:11"
# Ancre de datation : sans annee dans le format, le parseur a besoin d'un
# "maintenant" de reference. On l'injecte pour que le test soit deterministe.
NOW = datetime(2026, 7, 24, 16, 0, 0, tzinfo=timezone.utc)


class TestParseTz:
    """La specification vient de la ligne de commande : elle doit etre
    tolerante aux formes usuelles et refuser clairement le reste."""

    @pytest.mark.parametrize("spec", ["UTC", "utc", "Z", "GMT"])
    def test_utc_sous_ses_differents_noms(self, spec):
        assert parse_tz(spec).utcoffset(None) == timedelta(0)

    @pytest.mark.parametrize("spec,attendu", [
        ("+02:00", timedelta(hours=2)),
        ("+0200", timedelta(hours=2)),
        ("+02", timedelta(hours=2)),
        ("-05:00", timedelta(hours=-5)),
        ("-0530", timedelta(hours=-5, minutes=-30)),
        ("+05:45", timedelta(hours=5, minutes=45)),   # Nepal, offset non entier
    ])
    def test_decalages_fixes(self, spec, attendu):
        assert parse_tz(spec).utcoffset(None) == attendu

    @pytest.mark.parametrize("spec", ["", "   ", "+99:00", "+02:99", "n'importe quoi"])
    def test_refuse_ce_qui_n_est_pas_un_fuseau(self, spec):
        with pytest.raises(ValueError):
            parse_tz(spec)

    def test_nom_iana_introuvable_donne_une_consigne_actionnable(self):
        """Un nom qui RESSEMBLE a une zone IANA (avec '/') : le message doit
        proposer un remede, pas laisser l'utilisateur devant un echec nu.
        parse_tz() sans lang explicite rend desormais l'anglais (defaut de
        l'outil depuis 0.7.0) : le test verifie le CONTENU du message, pas sa
        langue — voir test_i18n.py pour la bascule --lang."""
        with pytest.raises(ValueError) as exc:
            parse_tz("Europe/Nulle_Part")
        message = str(exc.value)
        assert "Europe/Nulle_Part" in message
        # Selon la machine : soit la base manque (remede tzdata), soit elle est
        # la et c'est le nom qui est faux (formes acceptees). Les deux sont
        # actionnables ; on exige l'un ou l'autre, jamais un echec muet.
        assert ("tzdata" in message) or ("Accepted forms" in message)

    def test_une_chaine_absurde_ne_conseille_PAS_d_installer_tzdata(self):
        """Defaut trouve en verification : 'nawak' recevait le message
        « installer tzdata », ce qui envoie installer un paquet pour rien.
        Une chaine sans '/' n'est pas un nom de zone plausible."""
        with pytest.raises(ValueError) as exc:
            parse_tz("nawak")
        message = str(exc.value)
        assert "tzdata" not in message
        assert "Accepted forms" in message

    def test_nom_iana_si_la_base_est_disponible(self):
        """Environnement-dependant : verifie seulement que, quand la base
        existe, Europe/Paris donne bien +02:00 en juillet (heure d'ete)."""
        try:
            tz = parse_tz("Europe/Paris")
        except ValueError:
            pytest.skip("base de fuseaux IANA absente (pip install tzdata)")
        juillet = datetime(2026, 7, 24, 14, 0, 0, tzinfo=tz)
        assert juillet.utcoffset() == timedelta(hours=2)


class TestEpochAvecFuseauExplicite:
    def test_utc_donne_l_epoch_calcule_a_la_main(self):
        attendu = _MIDNIGHT_24_07_2026_UTC + _WALL_14_02_11
        assert _rfc3164_epoch(TS_RAW, NOW, timezone.utc) == attendu

    def test_decalage_positif_recule_l_instant_absolu(self):
        """14h02 a +02:00, c'est 12h02 UTC : l'epoch est 2 h PLUS PETIT."""
        attendu = _MIDNIGHT_24_07_2026_UTC + _WALL_14_02_11 - 2 * 3600
        assert _rfc3164_epoch(TS_RAW, NOW, parse_tz("+02:00")) == attendu

    def test_decalage_negatif_avance_l_instant_absolu(self):
        attendu = _MIDNIGHT_24_07_2026_UTC + _WALL_14_02_11 + 5 * 3600
        assert _rfc3164_epoch(TS_RAW, NOW, parse_tz("-05:00")) == attendu

    def test_le_choix_du_fuseau_change_reellement_le_resultat(self):
        """Garde-fou anti-regression : si un refactor ignorait `tz`, tous les
        tests ci-dessus passeraient encore sur une machine reglee en UTC."""
        utc = _rfc3164_epoch(TS_RAW, NOW, timezone.utc)
        plus_deux = _rfc3164_epoch(TS_RAW, NOW, parse_tz("+02:00"))
        assert utc - plus_deux == 2 * 3600

    def test_sans_fuseau_le_comportement_historique_est_conserve(self):
        """tz=None doit rester l'interpretation en heure locale du poste :
        c'est le defaut, et le changer casserait les analyses existantes."""
        local = _rfc3164_epoch(TS_RAW, NOW, None)
        attendu = datetime(2026, 7, 24, 14, 2, 11).timestamp()
        assert local == attendu


class TestFenetreEtAnneeImplicite:
    def test_un_syslog_utc_reste_dans_la_fenetre_grace_a_l_option(self):
        """LE cas d'usage. Un syslog central en UTC, une capture UTC : sans
        l'option, un poste a +02:00 daterait l'evenement 2 h trop tot et le
        ferait sortir d'une fenetre de 15 min. Ce test compare les DEUX
        interpretations du meme texte et exige l'ecart de 2 h."""
        epoch_utc = _rfc3164_epoch(TS_RAW, NOW, timezone.utc)
        epoch_paris_fixe = _rfc3164_epoch(TS_RAW, NOW, parse_tz("+02:00"))
        assert epoch_utc - epoch_paris_fixe == 7200
        # 7200 s = 2 h : bien au-dela de la fenetre de 15 min (900 s), donc
        # l'un des deux tombe forcement hors fenetre. C'est exactement la
        # panne silencieuse que l'option supprime.
        assert abs(epoch_utc - epoch_paris_fixe) > 900

    def test_annee_precedente_deduite_quand_la_date_serait_dans_le_futur(self):
        """Log de decembre relu en janvier : l'annee courante placerait
        l'evenement 11 mois dans le futur -> annee precedente."""
        now = datetime(2026, 1, 5, 10, 0, 0, tzinfo=timezone.utc)
        epoch = _rfc3164_epoch("Dec 20 23:30:00", now, timezone.utc)
        assert epoch is not None
        assert datetime.fromtimestamp(epoch, timezone.utc).year == 2025

    def test_le_29_fevrier_inexistant_ne_fait_pas_planter(self):
        """Ligne corrompue ou log d'une annee bissextile relu une autre
        annee : on renvoie None (compte en unparsed), jamais d'exception."""
        now = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
        assert _rfc3164_epoch("Feb 29 12:00:00", now, timezone.utc) is None

    def test_now_naif_et_now_avec_fuseau_donnent_le_meme_instant(self):
        """`now` arrive naif depuis cli.py et avec fuseau depuis les tests :
        melanger les deux levait TypeError avant le passage en epoch."""
        naif = datetime.fromtimestamp(NOW.timestamp())
        assert (_rfc3164_epoch(TS_RAW, naif, timezone.utc)
                == _rfc3164_epoch(TS_RAW, NOW, timezone.utc))


class TestIntegrationFichier:
    def _ecrire(self, tmp_path, lignes):
        p = tmp_path / "central.log"
        p.write_text("\n".join(lignes) + "\n", encoding="utf-8")
        return p

    def test_tz_known_devient_vrai_avec_l_option(self, tmp_path):
        """Consequence visible dans le rapport : sans fuseau connu il affiche
        « ~ » et un delta « environ N min » ; avec l'option, la seconde."""
        p = self._ecrire(tmp_path, ["<34>Jul 24 14:02:11 fw01 firewalld[955]: "
                                    "firewall rules reloaded"])
        sans, _ = parse(p, now=NOW)
        avec, _ = parse(p, now=NOW, tz=timezone.utc)
        assert sans[0].tz_known is False
        assert avec[0].tz_known is True
        assert avec[0].category == "change"      # categorisation inchangee

    def test_l_option_n_ecrase_jamais_le_fuseau_d_une_ligne_rfc5424(self, tmp_path):
        """RFC5424 impose un fuseau explicite : remplacer une information
        certaine par une supposition de l'utilisateur serait une regression."""
        ligne = ("<38>1 2026-07-24T14:02:11.532+02:00 srv01 sshd 1234 - - "
                 "Accepted publickey for root")
        p = self._ecrire(tmp_path, [ligne])
        attendu = _MIDNIGHT_24_07_2026_UTC + _WALL_14_02_11 - 2 * 3600 + 0.532
        for tz in (None, timezone.utc, parse_tz("-05:00")):
            evs, _ = parse(p, now=NOW, tz=tz)
            assert evs[0].ts == pytest.approx(attendu)
            assert evs[0].tz_known is True

    def test_formats_melanges_dans_un_meme_fichier(self, tmp_path):
        """Un fichier reel melange les formats : seules les lignes RFC3164
        doivent bouger quand on change --syslog-tz."""
        p = self._ecrire(tmp_path, [
            "<38>1 2026-07-24T14:02:11+02:00 srv01 sshd 1 - - session ouverte",
            "<34>Jul 24 14:02:11 fw01 firewalld[955]: firewall rules reloaded",
            "Jul 24 14:02:11 deb13 kernel: Booting Linux",
        ])
        utc, stats = parse(p, now=NOW, tz=timezone.utc)
        assert (stats.total_lines, stats.parsed, stats.unparsed) == (3, 3, 0)
        moins_cinq, _ = parse(p, now=NOW, tz=parse_tz("-05:00"))

        par_ident_utc = {e.ident: e.ts for e in utc}
        par_ident_m5 = {e.ident: e.ts for e in moins_cinq}
        # RFC5424 : figee.
        assert par_ident_utc["sshd"] == par_ident_m5["sshd"]
        # RFC3164 avec et sans PRI : decalees de 5 h.
        for ident in ("firewalld", "kernel"):
            assert par_ident_m5[ident] - par_ident_utc[ident] == 5 * 3600
