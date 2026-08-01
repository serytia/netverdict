"""Support de l'anglais (--lang en) : la sortie bascule, le francais ne bouge
pas, et rien ne casse quand une traduction manque.

Trois proprietes sont testees ici, dans l'ordre de ce qu'elles couteraient si
elles lachaient :

  1. Le francais reste le defaut, AU MOT PRES. Une regression ici change la
     sortie de tous les utilisateurs actuels sans prevenir.
  2. Les JETONS (verdict, confidence, side) ne suivent PAS la langue. S'ils la
     suivaient, un script qui filtre `verdict == "RESEAU"` casserait le jour ou
     quelqu'un exporte NETVERDICT_LANG=en — panne muette exemplaire.
  3. Une traduction absente retombe sur le francais au lieu de lever. Un
     rapport degrade vaut mieux qu'un rapport perdu.
"""

import io
import json
import re
from pathlib import Path

import pytest
from rich.console import Console

from netverdict.cli import main
from netverdict.explain import system_prompt
from netverdict.flows import build_flows
from netverdict.i18n import DEFAULT_LANG, ENV_VAR, LANGS, STRINGS, resolve_lang, t
from netverdict.pcap import read_capture
from netverdict.report import conf_label, render_console, to_json, verdict_label
from netverdict.rules.engine import Rule, evaluate, load_rules
from netverdict.signals import compute_signals

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Les pcaps qui couvrent le plus de regles differentes : chacun fait sortir un
# titre, une preuve et une remediation distincts.
PCAPS = ["retrans_heavy", "syn_no_answer", "zero_window_server", "slow_app",
         "rst_to_syn", "mtu_blackhole", "midstream_rst", "reject_icmp",
         "clean"]

# Mots francais sans ambiguite anglaise, choisis dans les chaines reellement
# emises par l'outil. Volontairement PAS de mots communs aux deux langues
# ("port", "session", "capture", "client") : un filet qui cherche des faux
# positifs finit desactive.
MOTS_FR = [
    "aucun", "aucune", "avant", "pendant", "chercher", "verifier", "reseau",
    "fenetre", "illisibles", "paquets", "flux", "serveur", "hote", "regle",
    "regles", "etat", "changement", "changements", "entrees", "detenue",
    "piste", "sens", "emis", "perdus", "retrouves", "confiance", "sain",
    "anodine", "masquee", "utiliser", "trafic", "probleme", "systeme",
    "preuve", "preuves", "correction", "lues", "sur le chemin",
]
_FR_RE = re.compile(r"\b(" + "|".join(MOTS_FR) + r")\b", re.IGNORECASE)

# Lettres latines accentuees : aucune ne doit apparaitre dans la sortie EN.
# (Le depot ecrit le francais sans accents, sauf « façon » — d'ou ce filet en
# complement, jamais a la place, de la liste de mots ci-dessus.)
_ACCENTS_RE = re.compile(r"[À-ÿ]")


def _rendu(nom: str, lang: str) -> str:
    """Rapport console complet d'une fixture, largeur fixe (deterministe)."""
    cap = read_capture(FIXTURES_DIR / f"{nom}.pcap")
    verdicts = evaluate([compute_signals(f) for f in build_flows(cap)],
                        load_rules(), lang)
    buf = io.StringIO()
    render_console(cap, verdicts, console=Console(file=buf, width=100),
                   lang=lang)
    return buf.getvalue()


# --- 1. La sortie anglaise est reellement anglaise -------------------------

@pytest.mark.parametrize("nom", PCAPS)
def test_sortie_en_sans_residu_francais(nom):
    sortie = _rendu(nom, "en")
    residus = sorted(set(m.group(0).lower() for m in _FR_RE.finditer(sortie)))
    assert not residus, f"{nom}: mots francais dans la sortie EN: {residus}"
    accents = _ACCENTS_RE.findall(sortie)
    assert not accents, f"{nom}: lettres accentuees dans la sortie EN: {accents}"


def test_sortie_en_dit_bien_quelque_chose():
    """Garde-fou du test precedent : une sortie VIDE n'a pas de mot francais
    non plus. On verifie donc qu'il y a bien du texte anglais dedans."""
    sortie = _rendu("retrans_heavy", "en")
    assert "Significant packet loss on the path" in sortie
    assert "Suggested fix:" in sortie
    assert "packets read" in sortie


def test_toutes_les_regles_builtin_sont_traduites():
    """Une regle embarquee sans traduction sortirait en francais au milieu
    d'un rapport anglais — le genre de detail qui decredibilise l'outil."""
    manquantes = [r.id for r in load_rules()
                  if "en" not in r.title_i18n
                  or "en" not in r.remediation_i18n
                  or (r.evidence and "en" not in r.evidence_i18n)]
    assert not manquantes, f"regles sans traduction EN: {manquantes}"


def test_les_preuves_traduites_gardent_les_memes_champs():
    """Un gabarit de preuve interpole des signaux. Si la traduction perd un
    champ, la preuve anglaise devient moins precise que la francaise SANS que
    rien ne le signale (load_rules ne verifie que la validite, pas la parite)."""
    champs = re.compile(r"\{(\w+)")
    for r in load_rules():
        for lang in LANGS:
            if lang == DEFAULT_LANG:
                continue
            if lang not in r.evidence_i18n:
                continue
            attendus = {c for tpl in r.evidence for c in champs.findall(tpl)}
            obtenus = {c for tpl in r.evidence_i18n[lang]
                       for c in champs.findall(tpl)}
            assert attendus == obtenus, (
                f"{r.id} ({lang}): champs de preuve divergents, "
                f"manquants={attendus - obtenus} en trop={obtenus - attendus}")


# --- 2. Le francais ne bouge pas -------------------------------------------

def test_defaut_reste_le_francais(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert resolve_lang() == "fr"
    sortie = _rendu("retrans_heavy", resolve_lang())
    assert "Piste de correction :" in sortie
    assert "Perte de paquets significative sur le chemin" in sortie
    assert "paquets lus" in sortie
    assert "confiance haute" in sortie


def test_cli_sans_lang_rend_du_francais(capsys, monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    main(["analyze", str(FIXTURES_DIR / "retrans_heavy.pcap")])
    out = capsys.readouterr().out
    assert "Piste de correction" in out
    assert "Suggested fix" not in out


def test_faible_reste_non_traduit_en_francais():
    """`confidence: faible` n'a jamais eu de libelle francais (la regle
    latency-tail-unexplained affiche « faible » brut depuis la v1). On ne
    corrige PAS ici : ce serait changer la sortie francaise existante sous
    couvert d'i18n. L'anglais, lui, est neuf, donc il a son libelle."""
    assert conf_label("faible", "fr") == "faible"
    assert conf_label("faible", "en") == "low confidence"
    assert conf_label("haute", "fr") == "confiance haute"


# --- 3. Les jetons machine ne suivent pas la langue ------------------------

def test_json_garde_ses_jetons_quelle_que_soit_la_langue():
    cap = read_capture(FIXTURES_DIR / "retrans_heavy.pcap")
    signaux = [compute_signals(f) for f in build_flows(cap)]
    rendus = {}
    for lang in LANGS:
        rendus[lang] = json.loads(
            to_json(cap, evaluate(signaux, load_rules(), lang), lang=lang))

    fr, en = rendus["fr"]["flows"][0], rendus["en"]["flows"][0]
    # Les identifiants sont identiques...
    assert fr["verdict"] == en["verdict"] == "RESEAU"
    assert fr["matches"][0]["rule"] == en["matches"][0]["rule"]
    assert fr["matches"][0]["confidence"] == en["matches"][0]["confidence"] == "haute"
    # ...et seule la prose change.
    assert fr["matches"][0]["title"] != en["matches"][0]["title"]
    assert en["matches"][0]["title"] == "Significant packet loss on the path"


def test_le_libelle_affiche_suit_la_langue_mais_pas_le_jeton():
    assert verdict_label("RESEAU", "fr") == "RESEAU"
    assert verdict_label("RESEAU", "en") == "NETWORK"
    assert verdict_label("HOTE", "en") == "HOST"
    assert verdict_label("RAS", "en") == "CLEAN"
    # Un jeton inconnu (regle utilisateur exotique) sort tel quel, sans lever.
    assert verdict_label("MAISON", "en") == "verdict.MAISON"


def test_code_retour_identique_dans_les_deux_langues(capsys):
    codes = set()
    for lang in LANGS:
        codes.add(main(["analyze", str(FIXTURES_DIR / "retrans_heavy.pcap"),
                        "--lang", lang]))
        capsys.readouterr()
    assert codes == {1}, "le code retour ne doit pas dependre de la langue"


# --- 4. Repli : rien ne casse quand une traduction manque ------------------

def test_regle_sans_traduction_retombe_sur_le_francais():
    """Cas d'une regle utilisateur (--rules) ecrite en francais seul."""
    r = Rule.from_dict({
        "id": "user-rule", "verdict": "APP", "title": "Titre francais",
        "when": ["retrans_total >= 0"], "evidence": ["preuve {retrans_total}"],
        "remediation": "remede francais",
    })
    assert r.title_for("en") == "Titre francais"
    assert r.evidence_for("en") == ["preuve {retrans_total}"]
    assert r.remediation_for("en") == "remede francais"


def test_regle_traduite_partiellement():
    """Titre traduit mais pas la remediation : chaque champ replie seul."""
    r = Rule.from_dict({
        "id": "half", "verdict": "APP", "title": "Titre francais",
        "title_en": "English title", "when": ["retrans_total >= 0"],
        "remediation": "remede francais",
    })
    assert r.title_for("en") == "English title"
    assert r.remediation_for("en") == "remede francais"


def test_t_ne_leve_jamais():
    # Cle inconnue -> la cle, visible dans la sortie plutot qu'une exception.
    assert t("cle.inexistante", "en") == "cle.inexistante"
    # Langue inconnue -> francais.
    assert t("report.fix_header", "de") == "Piste de correction :"
    # Traduction absente dans cette langue -> francais.
    assert t("conf.faible", "fr") == "conf.faible"
    # Arguments qui ne collent pas au gabarit -> gabarit brut, pas de crash.
    assert "{" in t("report.hidden_flows", "en", mauvais_champ=1)


def test_pas_de_traduction_vide_dans_la_table():
    """Une chaine vide passerait le repli de t() (or/None) sans qu'on le voie
    au premier coup d'oeil : autant l'interdire franchement."""
    vides = [f"{cle}:{lang}" for cle, e in STRINGS.items()
             for lang, valeur in e.items() if not valeur.strip()]
    assert not vides, f"traductions vides: {vides}"


# --- 5. Resolution de la langue --------------------------------------------

def test_resolve_lang_precedence(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "en")
    assert resolve_lang() == "en"
    assert resolve_lang("fr") == "fr", "--lang doit primer sur l'environnement"
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert resolve_lang() == "fr"


@pytest.mark.parametrize("valeur,attendu", [
    ("en", "en"), ("EN", "en"), ("en_US", "en"), ("en-GB", "en"),
    ("fr_FR.UTF-8", "fr"), ("de_DE", "fr"), ("", "fr"), ("klingon", "fr"),
])
def test_resolve_lang_tolere_les_formes_de_l_environnement(monkeypatch, valeur,
                                                           attendu):
    """$NETVERDICT_LANG n'est valide par personne : une valeur heritee d'un
    $LANG systeme ne doit jamais empecher l'analyse de sortir."""
    monkeypatch.setenv(ENV_VAR, valeur)
    assert resolve_lang() == attendu


def test_env_pilote_le_cli(capsys, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "en")
    main(["analyze", str(FIXTURES_DIR / "retrans_heavy.pcap")])
    out = capsys.readouterr().out
    assert "Suggested fix:" in out
    assert "Piste de correction" not in out


def test_lang_explicite_prime_sur_env(capsys, monkeypatch):
    monkeypatch.setenv(ENV_VAR, "en")
    main(["analyze", str(FIXTURES_DIR / "retrans_heavy.pcap"), "--lang", "fr"])
    out = capsys.readouterr().out
    assert "Piste de correction" in out
    assert "Suggested fix" not in out


def test_lang_invalide_refusee_par_argparse(capsys):
    with pytest.raises(SystemExit):
        main(["analyze", str(FIXTURES_DIR / "clean.pcap"), "--lang", "de"])


# --- 6. --explain demande bien la langue choisie ---------------------------

def test_le_prompt_explain_bascule():
    assert "Redige en francais" in system_prompt("fr")
    assert "Redige en English" in system_prompt("en")
    assert "TOUTE ta reponse est en English" in system_prompt("en")


def test_explain_prompt_defaut_inchange():
    from netverdict.explain import SYSTEM
    assert SYSTEM == system_prompt("fr")
    assert "Redige en francais" in SYSTEM


# --- 7. Messages d'erreur ---------------------------------------------------

def test_erreur_fichier_absent_suit_la_langue(capsys):
    assert main(["analyze", "nexiste-pas.pcap", "--lang", "en"]) == 2
    assert "File not found" in capsys.readouterr().err
    assert main(["analyze", "nexiste-pas.pcap", "--lang", "fr"]) == 2
    assert "Fichier introuvable" in capsys.readouterr().err


def test_erreur_syslog_tz_suit_la_langue(capsys, tmp_path):
    pcap = str(FIXTURES_DIR / "clean.pcap")
    assert main(["analyze", pcap, "--syslog-tz", "UTC", "--lang", "en"]) == 2
    assert "only has an effect" in capsys.readouterr().err

    log = tmp_path / "s.log"
    log.write_text("<30>Jul 24 14:09:38 h p[1]: x\n", encoding="utf-8")
    assert main(["analyze", pcap, "--syslog", str(log),
                 "--syslog-tz", "Pas/UnFuseau", "--lang", "en"]) == 2
    err = capsys.readouterr().err
    assert "--syslog-tz:" in err
    assert "Accepted forms" in err


def test_format_pcap_non_reconnu_suit_la_langue(capsys, tmp_path):
    faux = tmp_path / "faux.pcap"
    faux.write_bytes(b"ceci n'est pas un pcap")
    assert main(["analyze", str(faux), "--lang", "en"]) == 2
    assert "Unrecognised format" in capsys.readouterr().err
    assert main(["analyze", str(faux), "--lang", "fr"]) == 2
    assert "Format non reconnu" in capsys.readouterr().err


# --- 8. La sous-commande rules ---------------------------------------------

def test_rules_affiche_les_titres_traduits(capsys):
    assert main(["rules", "--lang", "en"]) == 0
    out = capsys.readouterr().out
    assert "Significant packet loss on the path" in out
    # Le JETON de verdict reste : cette sortie sert a ecrire des regles.
    assert "RESEAU" in out


# --- 9. Les sections que les pcaps seuls n'atteignent pas ------------------
#
# La timeline, le snapshot d'hote et l'attribution de process ne sortent que
# si on leur fournit des sources. Sans ces tests, un tiers des chaines
# traduites ne serait jamais rendu par la suite.

def _timeline_rendue(lang: str, vide: bool = False) -> str:
    from netverdict.report import render_timeline
    from netverdict.timeline import SourceStats, Timeline, TimelineEvent

    tl = Timeline(windowed=True)
    evs = [] if vide else [
        TimelineEvent(ts=0.0, source="syslog", host="fw01", category="change",
                      severity=1, ident="firewalld",
                      message="Configuration reloaded"),
        # tz_known=False -> branche « heure source approximative ».
        TimelineEvent(ts=-60.0, source="syslog", host="sw01",
                      category="network", severity=2, ident="kernel",
                      message="link down", tz_known=False),
    ]
    tl.add_source("syslog:fw.log", evs,
                  SourceStats(total_lines=500, parsed=len(evs),
                              unparsed=500 - len(evs)))
    buf = io.StringIO()
    render_timeline(tl, incident_ts=100.0, con=Console(file=buf, width=100),
                    windowed=True, lang=lang)
    return buf.getvalue()


@pytest.mark.parametrize("vide", [False, True])
def test_timeline_en_sans_residu_francais(vide):
    sortie = _timeline_rendue("en", vide)
    residus = sorted(set(m.group(0).lower() for m in _FR_RE.finditer(sortie)))
    assert not residus, f"timeline EN (vide={vide}): residus {residus}"


def test_timeline_en_dit_bien_quelque_chose():
    assert "Infrastructure changes" in _timeline_rendue("en")
    assert "precedes the incident by" in _timeline_rendue("en")
    assert "entries read" in _timeline_rendue("en")
    assert "unreadable" in _timeline_rendue("en")
    assert ("no infrastructure changes detected"
            in _timeline_rendue("en", vide=True))


def test_timeline_fr_inchangee():
    """La formulation francaise exacte, celle que test_review_fixes assere."""
    assert "aucun changement" in _timeline_rendue("fr", vide=True)
    assert "Changements dans l'infra (fenetre de la capture) :" in _timeline_rendue("fr")
    assert "precede l'incident de" in _timeline_rendue("fr")
    assert "entrees lues" in _timeline_rendue("fr")


def test_timeline_fenetre_non_appliquee_suit_la_langue():
    from netverdict.report import render_timeline
    from netverdict.timeline import SourceStats, Timeline

    def _rendre(lang):
        tl = Timeline()
        tl.add_source("s", [], SourceStats())
        buf = io.StringIO()
        render_timeline(tl, None, Console(file=buf, width=100),
                        windowed=False, lang=lang)
        return buf.getvalue()

    assert "NON appliquee" in _rendre("fr")
    assert "window NOT applied" in _rendre("en")


def test_suspect_describe_suit_la_langue():
    from netverdict.correlate import Suspect
    from netverdict.timeline import TimelineEvent

    def _sp(delay, tz_known):
        ev = TimelineEvent(ts=0.0, source="syslog", host="h",
                           category="change", severity=1, ident="i",
                           message="m", tz_known=tz_known)
        return Suspect(event=ev, delay_s=delay, affinity=True)

    assert _sp(42.0, True).describe("fr") == "42 s avant le flux"
    assert _sp(42.0, True).describe("en") == "42 s before the flow"
    assert _sp(-42.0, True).describe("fr") == "42 s pendant le flux"
    assert _sp(-42.0, True).describe("en") == "42 s during the flow"
    # Horodatage sans fuseau fiable : pas de precision a la seconde.
    assert "environ 2 min" in _sp(120.0, False).describe("fr")
    assert "about 2 min" in _sp(120.0, False).describe("en")
    assert "source time approximate" in _sp(120.0, False).describe("en")


def test_attribution_process_suit_la_langue():
    from netverdict.correlate import ProcessAttribution
    from netverdict.timeline import ConnectionInfo, TimelineEvent

    conn = ConnectionInfo(src_ip="10.0.0.42", src_port=51004,
                          dst_ip="10.0.0.5", dst_port=80, protocol="tcp",
                          pid=4212, image=r"C:\app\java.exe", user="SYSTEM")
    ev = TimelineEvent(ts=0.0, source="evtx", host="h", category="info",
                       severity=0, ident="3", message="m", connection=conn)
    attr = ProcessAttribution(event=ev, side="serveur", candidates=3,
                              exact=False)

    fr, en = attr.describe("fr"), attr.describe("en")
    assert fr.startswith("java.exe (pid 4212) cote serveur, utilisateur SYSTEM")
    assert en.startswith("java.exe (pid 4212) on the server side, user SYSTEM")
    assert "rapproche par la DESTINATION seule" in fr
    assert "matched on the DESTINATION only" in en
    assert "3 connexions correspondaient" in fr
    assert "3 connections matched" in en
    # `side` reste la valeur machine, quel que soit l'affichage.
    assert attr.side == "serveur"
    residus = sorted(set(m.group(0).lower() for m in _FR_RE.finditer(en)))
    assert not residus, f"attribution EN: residus {residus}"


def test_snapshot_hote_suit_la_langue():
    from netverdict.hostsnap import HostContext

    ctx = HostContext(host="SRV-APP01", process="java", pid=4212,
                      cpu_pct=63.0, disk_busy_pct=98.0, mem_free_mb=512.0,
                      process_cpu_pct=97.0)
    fr, en = ctx.summary("fr"), ctx.summary("en")
    assert fr == ("[SRV-APP01] socket detenue par java (pid 4212), "
                  "cpu process 97%, cpu machine 63%, disque 98%, "
                  "ram libre 512 Mo")
    assert en == ("[SRV-APP01] socket held by java (pid 4212), "
                  "process cpu 97%, host cpu 63%, disk 98%, free ram 512 MB")
    assert ctx.summary() == fr, "le defaut doit rester le francais"


def test_compare_verdicts_suivent_la_langue():
    from netverdict.compare import CleFlux, ComparaisonFlux, Ecart

    def _comp(ecarts):
        return ComparaisonFlux(cle=CleFlux("10.0.0.1", 1, "10.0.0.2", 80),
                               offset_horloge_s=None, latence_reseau_ms=None,
                               ecarts=ecarts)

    # Aucun segment appariable.
    assert _comp([]).verdict("fr")[0] == _comp([]).verdict("en")[0] == "AMBIGU"
    assert "no segment could be paired" in _comp([]).verdict("en")[1]

    perte = [Ecart(sens="client->server", segments_amont=10, segments_aval=7,
                   perdus=3)]
    jeton, phrase = _comp(perte).verdict("en")
    assert jeton == "RESEAU", "le jeton ne suit pas la langue"
    assert "the loss happens BETWEEN the two points" in phrase
    assert "3/10 lost" in phrase

    sain = [Ecart(sens="client->server", segments_amont=10, segments_aval=10,
                  perdus=0)]
    jeton, phrase = _comp(sain).verdict("en")
    assert jeton == "RAS"
    assert "all 10 segments" in phrase
