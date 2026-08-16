"""Table des chaines affichees, indexee par cle puis par langue (v1).

POURQUOI PAS GETTEXT
--------------------
gettext apporte des .po/.mo a compiler, une etape de build et un fichier
binaire dans le wheel, pour deux langues et ~120 chaines. Un dictionnaire
Python est diffable, greppable, et se relit dans une revue de PR — ce qui
compte davantage ici : la valeur de l'outil est la confiance qu'on accorde a
ses phrases, et une phrase qu'on ne peut pas relire est une phrase qu'on ne
peut pas verifier.

CE QUI EST TRADUIT, CE QUI NE L'EST PAS
---------------------------------------
Traduit : tout ce qu'un humain LIT (console, --help, messages d'erreur,
prompt --explain, titres/preuves/remediations des regles).

PAS traduit : tout ce qu'une MACHINE lit. Les jetons de verdict
(RESEAU/APP/OS/HOTE/AMBIGU/RAS), les valeurs de `confidence` et les cles JSON
sont des identifiants : ils apparaissent dans les fichiers --rules ecrits par
les utilisateurs et dans le JSON sur lequel des scripts filtrent. Les traduire
rendrait la sortie machine dependante de la langue — un `verdict == "RESEAU"`
casserait le jour ou quelqu'un exporte NETVERDICT_LANG=en, sans le moindre
signal. Seul le LIBELLE D'AFFICHAGE de ces jetons est traduit (voir
VERDICT_LABEL / CONF_LABEL dans report.py).

REGLE DE REPLI
--------------
t() ne leve jamais. Traduction manquante -> francais ; cle inconnue -> la cle
elle-meme (visible et diagnosticable dans la sortie, la ou une exception
perdrait tout le rapport) ; gabarit incompatible avec ses arguments -> le
gabarit brut. Un rapport degrade vaut mieux qu'un rapport absent.
"""

from __future__ import annotations

import os

LANGS = ("fr", "en")
# Anglais par defaut depuis 0.7.0 : l'outil est sur PyPI et son public est
# international. Un francophone garde tout par `--lang fr` ou NETVERDICT_LANG=fr.
DEFAULT_LANG = "en"

# Secours quand --lang est absent. Meme convention que les autres outils en
# ligne de commande : l'option explicite prime toujours sur l'environnement.
ENV_VAR = "NETVERDICT_LANG"


def resolve_lang(explicit: str | None = None) -> str:
    """Langue effective : --lang, sinon $NETVERDICT_LANG, sinon anglais.

    Une valeur inconnue (faute de frappe, "de_DE" herite d'un $LANG systeme)
    retombe sur la langue par defaut SANS erreur : l'analyse doit sortir, une
    langue inattendue n'est pas une raison de ne rien rendre. argparse valide
    deja --lang ; ce repli couvre la variable d'environnement, que personne ne
    valide. A ne pas confondre avec le repli de t(), qui vise toujours le
    francais : ici on choisit une LANGUE, la-bas on comble une TRADUCTION
    manquante.
    """
    for candidat in (explicit, os.environ.get(ENV_VAR)):
        if candidat:
            code = candidat.strip().lower().replace("-", "_").split("_")[0]
            if code in LANGS:
                return code
    return DEFAULT_LANG


def t(key: str, lang: str = DEFAULT_LANG, **kwargs) -> str:
    """Chaine traduite et interpolee. Ne leve jamais (voir le module)."""
    entry = STRINGS.get(key)
    if entry is None:
        return key
    # Repli fixe sur "fr", jamais sur DEFAULT_LANG : le francais est la SEULE
    # langue garantie complete (voir REGLE DE REPLI plus haut et
    # i18n-inventory.md), donc c'est le filet qui doit tenir quelle que soit
    # la langue par defaut du jour. Avant ce correctif, le repli visait
    # DEFAULT_LANG ; cela ne se voyait pas tant que DEFAULT_LANG valait "fr",
    # mais son passage a "en" faisait retomber toute langue inconnue ou toute
    # traduction manquante sur de l'anglais SILENCIEUSEMENT, au lieu du
    # francais documente -- bug reel revele par le changement de defaut.
    template = entry.get(lang) or entry.get("fr") or key
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):
        # Gabarit et arguments desaccordes : c'est un bug de traduction, mais
        # il ne doit pas emporter le rapport avec lui.
        return template


STRINGS: dict[str, dict[str, str]] = {

    # ------------------------------------------------------------- report.py
    "report.header": {
        "fr": "{total} paquets lus — {tcp} TCP, {udp} UDP, {icmp} ICMP, "
              "{other} autres IP, {non_ip} non-IP, {frags} fragments, "
              "{errors} illisibles — {flows} conversations TCP",
        "en": "{total} packets read — {tcp} TCP, {udp} UDP, {icmp} ICMP, "
              "{other} other IP, {non_ip} non-IP, {frags} fragments, "
              "{errors} unreadable — {flows} TCP conversations",
    },
    "err.capture_unreadable": {
        "fr": "capture illisible : {path} ({e})",
        "en": "capture unreadable: {path} ({e})",
    },
    "err.capture_corrupt": {
        "fr": "capture corrompue ou tronquee : {path} — la lecture s'est "
              "arretee sur {e}. Verifier que le fichier a ete transfere en "
              "entier (un pcap coupe en plein bloc n'est pas relisible).",
        "en": "corrupt or truncated capture: {path} — reading stopped on {e}. "
              "Check the file was transferred in full (a pcap cut mid-block "
              "cannot be read back).",
    },
    "report.udp_header": {
        "fr": "Conversations UDP",
        "en": "UDP conversations",
    },
    "report.udp_healthy": {
        "fr": "{n} conversation(s) UDP sans erreur",
        "en": "{n} UDP conversation(s) with no error",
    },
    "report.udp_direction_unsure": {
        "fr": "sens client/serveur devine (UDP n'a pas de handshake)",
        "en": "client/server direction guessed (UDP has no handshake)",
    },
    "report.udp_unidirectional_hint": {
        "fr": "port {sport} = {service}, un service qui repond normalement",
        "en": "port {sport} = {service}, a service that normally answers",
    },
    "report.dns_header": {
        "fr": "Resolutions DNS — ce qui s'est passe AVANT les connexions",
        "en": "DNS resolutions — what happened BEFORE the connections",
    },
    "report.dns_leads_to": {
        "fr": "connexion(s) qui ont suivi : ",
        "en": "connection(s) that followed: ",
    },
    "report.dns_healthy": {
        "fr": "{n} resolution(s) DNS saine(s)",
        "en": "{n} healthy DNS resolution(s)",
    },
    "report.dns_silent": {
        "fr": "{n} resolution(s) DNS sur lesquelles aucune regle ne s'est "
              "prononcee",
        "en": "{n} DNS resolution(s) no rule had anything to say about",
    },
    "report.udp_silent": {
        "fr": "{n} conversation(s) UDP sur lesquelles aucune regle ne s'est "
              "prononcee",
        "en": "{n} UDP conversation(s) no rule had anything to say about",
    },
    "report.dns_name_hint": {
        "fr": "nom resolu : {qname}",
        "en": "resolved name: {qname}",
    },
    "report.dns_before_flow": {
        "fr": "precede de {ms:.0f} ms de resolution DNS pour {qname} — "
              "ce delai s'ajoute a ce que l'utilisateur a subi",
        "en": "preceded by {ms:.0f} ms of DNS resolution for {qname} — "
              "that delay adds to what the user experienced",
    },
    "report.dns_answers_unreadable": {
        "fr": "attention : {n} reponse(s) DNS coupee(s) par le snaplen — "
              "latence et codes de retour restent justes, mais les adresses "
              "sont illisibles, donc aucun flux ne peut etre nomme "
              "(capturer avec un snaplen plus grand pour les obtenir)",
        "en": "warning: {n} DNS answer(s) cut by the snaplen — latency and "
              "response codes remain accurate, but the addresses are "
              "unreadable, so no flow can be named (capture with a larger "
              "snaplen to get them)",
    },
    "report.warn_dns_no_resolution": {
        "fr": "attention : {n} paquets DNS lus, mais aucune resolution n'a pu "
              "etre reconstituee (questions illisibles, ou reponses dont la "
              "question precede la capture)",
        "en": "warning: {n} DNS packets read, but no resolution could be "
              "reconstructed (unreadable queries, or answers whose query "
              "predates the capture)",
    },
    "report.warn_horodatage": {
        "fr": "attention : le dernier paquet est date {ecart} s apres le "
              "precedent — horloge d'equipement, capture concatenee ou epoch "
              "mal converti. Toute duree mesuree jusqu'a la fin de capture "
              "est a lire avec cette reserve.",
        "en": "warning: the last packet is dated {ecart} s after the previous "
              "one — device clock, concatenated capture or mis-converted "
              "epoch. Any duration measured up to the end of the capture "
              "should be read with that caveat.",
    },
    "report.warn_dns_orphelins": {
        "fr": "attention : {n} message(s) DNS lus mais rattaches a aucune "
              "resolution (question absente de la capture, reponse trop "
              "tardive, ou nom illisible) — un verdict « le serveur ne repond "
              "pas » ci-dessous peut concerner une question dont la reponse "
              "est pourtant dans ce fichier",
        "en": "warning: {n} DNS message(s) read but attached to no resolution "
              "(query missing from the capture, answer too late, or unreadable "
              "name) — a « the DNS server is not answering » verdict below may "
              "concern a query whose answer IS in this file",
    },
    "report.warn_dns_unreadable": {
        "fr": "attention : {n} datagramme(s) UDP/53 trop courts pour porter "
              "meme un en-tete DNS, ignores",
        "en": "warning: {n} UDP/53 datagram(s) too short to carry even a DNS "
              "header, skipped",
    },
    "report.warn_dns_not_analyzed": {
        "fr": "attention : {dns} paquets DNS (UDP/53) ne sont PAS analyses — "
              "une resolution lente ou en echec se produit avant le SYN et "
              "n'apparait dans aucun verdict ci-dessous",
        "en": "warning: {dns} DNS packets (UDP/53) are NOT analyzed — a slow "
              "or failed resolution happens before the SYN and appears in "
              "none of the verdicts below",
    },
    "report.warn_parse_errors": {
        "fr": "attention : {errors}/{total} paquets illisibles, les verdicts "
              "peuvent etre incomplets",
        "en": "warning: {errors}/{total} packets unreadable, verdicts may be "
              "incomplete",
    },
    "report.warn_linktype": {
        "fr": "attention : linktype partiellement supporte, des trames ont "
              "ete ignorees",
        "en": "warning: linktype only partially supported, some frames were "
              "skipped",
    },
    "report.warn_mixed_linktypes": {
        "fr": "ATTENTION : cette capture declare PLUSIEURS interfaces de types "
              "differents (fusion type mergecap). Seul le type de la premiere "
              "est applique : les paquets des autres sont comptes « non-IP » et "
              "N'APPARAISSENT PAS dans les verdicts. Analyser chaque capture "
              "separement.",
        "en": "WARNING: this capture declares SEVERAL interfaces of different "
              "types (a mergecap-style merge). Only the first type is applied: "
              "packets from the other interfaces are counted as non-IP and DO "
              "NOT APPEAR in the verdicts. Analyse each capture separately.",
    },
    "report.host_state": {
        "fr": "etat hote : ",
        "en": "host state: ",
    },
    "report.process_retro": {
        "fr": "process (journal, retroactif) : ",
        "en": "process (from logs, retroactive): ",
    },
    "report.direction_unsure": {
        "fr": "sens client/serveur estime (pas de SYN dans la capture) : lire "
              "les roles avec prudence",
        "en": "client/server direction inferred (no SYN in the capture): read "
              "the roles with caution",
    },
    "report.suspects_header": {
        "fr": "A verifier en premier (suspects, pas une cause etablie) :",
        "en": "Check these first (suspects, not an established cause):",
    },
    "report.suspects_legend": {
        "fr": "* = type de changement pouvant produire ce verdict",
        "en": "* = change type that could produce this verdict",
    },
    "report.fix_header": {
        "fr": "Piste de correction :",
        "en": "Suggested fix:",
    },
    "report.secondary": {
        "fr": "Signaux secondaires : ",
        "en": "Secondary signals: ",
    },
    "report.hidden_flows": {
        "fr": "... {n} autre(s) conversation(s) avec verdict masquee(s) — "
              "utiliser --top pour en voir plus",
        "en": "... {n} more conversation(s) with a verdict hidden — use --top "
              "to see more",
    },
    "report.healthy_flows": {
        "fr": "[{label}] {n} conversation(s) au transport sain",
        "en": "[{label}] {n} conversation(s) with healthy transport",
    },
    "report.silent_flows": {
        "fr": "{n} conversation(s) anodine(s) (trop peu de trafic pour juger)",
        "en": "{n} unremarkable conversation(s) (too little traffic to judge)",
    },

    # Libelles d'affichage des jetons de verdict. Le jeton lui-meme ne bouge
    # jamais (YAML, JSON, code de retour) — seule cette etiquette est traduite.
    "verdict.RESEAU": {"fr": "RESEAU", "en": "NETWORK"},
    "verdict.APP": {"fr": "APP", "en": "APP"},
    "verdict.OS": {"fr": "OS", "en": "OS"},
    "verdict.HOTE": {"fr": "HOTE", "en": "HOST"},
    "verdict.AMBIGU": {"fr": "AMBIGU", "en": "AMBIGUOUS"},
    "verdict.RAS": {"fr": "RAS", "en": "CLEAN"},

    # Libelles de confiance. "faible" n'a JAMAIS eu d'entree francaise (la
    # regle latency-tail-unexplained affiche donc "faible" brut depuis la
    # v1) : on ne la cree pas ici, sous peine de changer la sortie francaise
    # existante. Anomalie signalee dans i18n-inventory.md, a corriger a part.
    "conf.haute": {"fr": "confiance haute", "en": "high confidence"},
    "conf.moyenne": {"fr": "confiance moyenne", "en": "medium confidence"},
    "conf.basse": {"fr": "confiance basse", "en": "low confidence"},
    "conf.faible": {"en": "low confidence"},

    # ----------------------------------------------------- report.py/timeline
    "timeline.header_windowed": {
        "fr": "Changements dans l'infra (fenetre de la capture) :",
        "en": "Infrastructure changes (capture window):",
    },
    "timeline.header_unwindowed": {
        "fr": "Changements dans l'infra — fenetre NON appliquee (capture sans "
              "paquet TCP date) :",
        "en": "Infrastructure changes — window NOT applied (the capture has no "
              "timestamped TCP packet):",
    },
    "timeline.no_change": {
        "fr": "aucun changement detecte dans la fenetre — les sources fournies "
              "n'expliquent pas l'incident par un changement recent",
        "en": "no infrastructure changes detected in the window — the sources "
              "provided do not explain the incident by a recent change",
    },
    "timeline.precedes": {
        "fr": "  << precede l'incident de {delta:.0f}s",
        "en": "  << precedes the incident by {delta:.0f}s",
    },
    "timeline.precedes_approx": {
        "fr": "  << precede l'incident d'environ {delta:.0f} min (heure source "
              "approximative)",
        "en": "  << precedes the incident by about {delta:.0f} min (source "
              "time approximate)",
    },
    "timeline.more_changes": {
        "fr": "... {n} autre(s) changement(s) masque(s) — --top pour en voir plus",
        "en": "... {n} more change(s) hidden — use --top to see more",
    },
    "timeline.other_errors": {
        "fr": "+ {n} erreur(s) hors changement dans la fenetre (--json pour le "
              "detail)",
        "en": "+ {n} error(s) unrelated to a change in the window (--json for "
              "details)",
    },
    "timeline.entries_read": {
        "fr": "{parsed}/{total} entrees lues",
        "en": "{parsed}/{total} entries read",
    },
    "timeline.entries_unreadable": {
        "fr": ", {n} illisibles",
        "en": ", {n} unreadable",
    },

    # ---------------------------------------------------------- correlate.py
    "correlate.seconds": {
        "fr": "{n:.0f} s",
        "en": "{n:.0f} s",
    },
    "correlate.minutes_approx": {
        "fr": "environ {n} min (heure source approximative)",
        "en": "about {n} min (source time approximate)",
    },
    "correlate.during_flow": {
        "fr": "pendant le flux",
        "en": "during the flow",
    },
    "correlate.before_flow": {
        "fr": "avant le flux",
        "en": "before the flow",
    },
    "correlate.attr_side": {
        "fr": "{proc} cote {side}",
        "en": "{proc} on the {side} side",
    },
    # `side` vaut litteralement "client"/"serveur" en interne et en JSON :
    # seul l'affichage est traduit.
    "correlate.side_client": {"fr": "client", "en": "client"},
    "correlate.side_serveur": {"fr": "serveur", "en": "server"},
    "correlate.attr_user": {
        "fr": ", utilisateur {user}",
        "en": ", user {user}",
    },
    "correlate.attr_clock_tolerance": {
        "fr": " [hors de la duree du flux : rattache par la tolerance "
              "d'horloge, verifier la synchro des deux machines]",
        "en": " [outside the flow's lifetime: matched through the clock "
              "tolerance, check both machines' time sync]",
    },
    "correlate.attr_inexact": {
        "fr": " — rapproche par la DESTINATION seule (le journal ne donne pas "
              "le port source) : un autre process contactant le meme service "
              "au meme moment serait indiscernable",
        "en": " — matched on the DESTINATION only (the log does not carry the "
              "source port): another process contacting the same service at "
              "the same time would be indistinguishable",
    },
    "correlate.attr_candidates": {
        "fr": " — {n} connexions correspondaient (port reutilise ?), la plus "
              "proche du debut du flux",
        "en": " — {n} connections matched (port reuse?), showing the one "
              "closest to the start of the flow",
    },

    # ----------------------------------------------------------- hostsnap.py
    "host.socket_owner": {
        "fr": "socket detenue par {process}",
        "en": "socket held by {process}",
    },
    "host.pid": {"fr": " (pid {pid})", "en": " (pid {pid})"},
    "host.process_cpu": {
        "fr": ", cpu process {pct:.0f}%",
        "en": ", process cpu {pct:.0f}%",
    },
    "host.cpu": {"fr": "cpu machine {pct:.0f}%", "en": "host cpu {pct:.0f}%"},
    "host.disk": {"fr": "disque {pct:.0f}%", "en": "disk {pct:.0f}%"},
    "host.mem_free": {
        "fr": "ram libre {mb:.0f} Mo",
        "en": "free ram {mb:.0f} MB",
    },

    # ---------------------------------------------------- messages d'erreur
    "err.rules": {
        "fr": "Erreur dans les regles : {e}",
        "en": "Error in the rules: {e}",
    },
    "err.file_not_found": {
        "fr": "Fichier introuvable : {path}",
        "en": "File not found: {path}",
    },
    "err.syslog_tz_needs_syslog": {
        "fr": "--syslog-tz n'a d'effet qu'avec --syslog (aucun fichier syslog "
              "fourni)",
        "en": "--syslog-tz only has an effect together with --syslog (no "
              "syslog file provided)",
    },
    "err.capture_unsupported_os": {
        "fr": "`netverdict capture` ne gere que Windows et Linux "
              "(detecte : {systeme}).\n"
              "Capturer avec l'outil natif du systeme, puis analyser :\n"
              "  sudo tcpdump -i <interface> -s 96 -w capture.pcap\n"
              "  netverdict analyze capture.pcap",
        "en": "`netverdict capture` only supports Windows and Linux "
              "(detected: {systeme}).\n"
              "Capture with the platform's native tool, then analyse:\n"
              "  sudo tcpdump -i <interface> -s 96 -w capture.pcap\n"
              "  netverdict analyze capture.pcap",
    },
    "err.capture_os_unknown": {"fr": "inconnu", "en": "unknown"},
    "err.capture_script_missing": {
        "fr": "Script de capture introuvable : {path}",
        "en": "Capture script not found: {path}",
    },
    "err.interpreter_missing": {
        "fr": "Interpreteur introuvable : `{cmd}` n'est pas installe ou absent "
              "du PATH.",
        "en": "Interpreter not found: `{cmd}` is not installed or not on PATH.",
    },
    "err.pcap_format": {
        "fr": "Format non reconnu (ni pcap ni pcapng). Si c'est un .etl "
              "Windows : le convertir d'abord avec 'pktmon etl2pcap "
              "fichier.etl -o fichier.pcapng'.",
        "en": "Unrecognised format (neither pcap nor pcapng). For a Windows "
              ".etl file, convert it first with 'pktmon etl2pcap file.etl -o "
              "file.pcapng'.",
    },

    # ------------------------------------------------- sources/syslog.py
    "err.tz_empty": {
        "fr": "--syslog-tz vide",
        "en": "--syslog-tz is empty",
    },
    "err.tz_out_of_range": {
        "fr": "decalage hors bornes: {spec!r} (attendu entre -23:59 et +23:59)",
        "en": "offset out of range: {spec!r} (expected between -23:59 and "
              "+23:59)",
    },
    "err.tz_forms": {
        "fr": "Formes acceptees : 'UTC', un nom IANA (Europe/Paris), ou un "
              "decalage fixe (+02:00). Attention, un decalage fixe est faux de "
              "part et d'autre d'un changement d'heure.",
        "en": "Accepted forms: 'UTC', an IANA name (Europe/Paris), or a fixed "
              "offset (+02:00). Beware: a fixed offset is wrong on one side of "
              "a daylight-saving change.",
    },
    "err.tz_unknown": {
        "fr": "fuseau inconnu: {spec!r}. {formes}",
        "en": "unknown timezone: {spec!r}. {formes}",
    },
    "err.tz_no_database": {
        "fr": "fuseau {spec!r} introuvable : la base de fuseaux IANA n'est pas "
              "installee (cas de Windows, qui n'en fournit pas). Corriger avec "
              "'pip install tzdata'. {formes}",
        "en": "timezone {spec!r} not found: the IANA timezone database is not "
              "installed (the case on Windows, which does not ship one). Fix "
              "with 'pip install tzdata'. {formes}",
    },
    "err.tz_invalid": {
        "fr": "fuseau invalide: {spec!r} ({e})",
        "en": "invalid timezone: {spec!r} ({e})",
    },
    "err.syslog_unreadable": {
        "fr": "syslog illisible ({path}): {e}",
        "en": "syslog unreadable ({path}): {e}",
    },

    # --------------------------------------------------- sources/evtx.py
    "err.evtx_xml_truncated": {
        "fr": "Export XML tronque ou encodage incoherent ({path}) : regenerer "
              "avec  wevtutil qe System /f:xml > events.xml",
        "en": "XML export truncated or inconsistent encoding ({path}): "
              "regenerate with  wevtutil qe System /f:xml > events.xml",
    },
    "err.evtx_xml_unreadable": {
        "fr": "XML illisible dans {path} ({e}). L'export wevtutil est-il "
              "complet ? Regenerer avec : wevtutil qe System /f:xml > events.xml",
        "en": "Unreadable XML in {path} ({e}). Is the wevtutil export "
              "complete? Regenerate with: wevtutil qe System /f:xml > events.xml",
    },
    "err.evtx_no_lib": {
        "fr": "Fichier .evtx binaire detecte mais python-evtx n'est pas "
              "installe. Deux options : installer l'extra "
              "(pip install 'netverdict[evtx]'), ou exporter en XML (zero "
              "dependance) puis relancer netverdict sur le fichier XML : "
              "wevtutil qe System /f:xml > events.xml  (canal en direct) ; "
              "wevtutil qe C:\\chemin\\fichier.evtx /lf:true /f:xml > events.xml"
              "  (canal sauvegarde / .evtx deja exporte).",
        "en": "Binary .evtx file detected but python-evtx is not installed. "
              "Two options: install the extra "
              "(pip install 'netverdict[evtx]'), or export to XML (no "
              "dependency) and re-run netverdict on the XML file: "
              "wevtutil qe System /f:xml > events.xml  (live channel) ; "
              "wevtutil qe C:\\path\\file.evtx /lf:true /f:xml > events.xml"
              "  (saved channel / already-exported .evtx).",
    },
    "err.evtx_read_interrupted": {
        "fr": "Lecture du .evtx {path} interrompue : {e}",
        "en": "Reading .evtx {path} was interrupted: {e}",
    },

    # ------------------------------------------------- sources/auditd.py
    "err.auditd_unreadable": {
        "fr": "audit.log illisible ({path}) : {e}. Verifier le chemin et les "
              "permissions (souvent 0640 root:adm sur /var/log/audit/audit.log).",
        "en": "audit.log unreadable ({path}): {e}. Check the path and the "
              "permissions (often 0640 root:adm on /var/log/audit/audit.log).",
    },

    # --- Avertissements de parseur, affiches en evidence dans le rapport ---
    "note.evtx_empty": {
        "fr": "aucun evenement lu dans ce fichier. S'il ne devait pas etre "
              "vide : verifier l'export (canal, filtre de date, droits) — pour "
              "un .evtx binaire, reexporter en XML avec  wevtutil qe <canal> "
              "/f:xml > events.xml",
        "en": "no events read from this file. If it was not meant to be "
              "empty: check the export (channel, date filter, permissions) — "
              "for a binary .evtx, re-export to XML with  wevtutil qe "
              "<channel> /f:xml > events.xml",
    },
    "note.evtx_no_sysmon_eid3": {
        "fr": "events Sysmon lus mais AUCUN NetworkConnect (EID3) : "
              "l'attribution process<->flux ne peut pas fonctionner. "
              "Activer : sysmon -c <chemin>\\netverdict\\capture\\"
              "sysmon-netverdict.xml (console administrateur)",
        "en": "Sysmon events read but NO NetworkConnect (EID3): "
              "process<->flow attribution cannot work. "
              "Enable with: sysmon -c <path>\\netverdict\\capture\\"
              "sysmon-netverdict.xml (administrator console)",
    },
    "note.evtx_no_wfp": {
        "fr": "events de securite Windows lus mais AUCUN WFP 5156/5157 "
              "(Filtering Platform Connection) : l'attribution "
              "process<->flux ne peut pas fonctionner. Activer : "
              'auditpol /set /subcategory:"Filtering Platform Connection" '
              "/success:enable /failure:enable -- TRES verbeux (beaucoup "
              "d'evenements sur une machine chargee) : a n'activer que le "
              "temps du diagnostic, puis desactiver avec "
              'auditpol /set /subcategory:"Filtering Platform Connection" '
              "/success:disable /failure:disable",
        "en": "Windows security events read but NO WFP 5156/5157 "
              "(Filtering Platform Connection): process<->flow attribution "
              "cannot work. Enable with: "
              'auditpol /set /subcategory:"Filtering Platform Connection" '
              "/success:enable /failure:enable -- VERY verbose (a lot of "
              "events on a busy host): enable it only for the duration of the "
              "diagnosis, then disable with "
              'auditpol /set /subcategory:"Filtering Platform Connection" '
              "/success:disable /failure:disable",
    },
    "note.auditd_no_connection": {
        "fr": "records auditd lus mais aucune connexion reseau (SYSCALL "
              "connect() + SOCKADDR) : la regle d'audit n'est probablement "
              "pas chargee. Activer : auditctl -a always,exit -F arch=b64 "
              "-S connect -k netverdict_connect  (a rendre persistant dans "
              "/etc/audit/rules.d/, sinon la regle disparait au redemarrage)",
        "en": "auditd records read but no network connection (SYSCALL "
              "connect() + SOCKADDR): the audit rule is probably not loaded. "
              "Enable it with: auditctl -a always,exit -F arch=b64 "
              "-S connect -k netverdict_connect  (make it persistent in "
              "/etc/audit/rules.d/, otherwise the rule is gone on reboot)",
    },

    # ------------------------------------------------------------ compare
    "compare.diag": {
        "fr": "amont : {a} flux   aval : {b} flux   communs : {communs}",
        "en": "upstream: {a} flows   downstream: {b} flows   in common: "
              "{communs}",
    },
    "compare.nat": {
        "fr": "AUCUN flux commun alors que les deux captures contiennent du "
              "trafic : un equipement reecrit probablement les adresses (NAT) "
              "entre les deux points, ou les captures ne portent pas sur le "
              "meme trafic. Comparaison impossible en l'etat — capturer en "
              "amont ET en aval du NAT, ou filtrer sur le trafic traduit.",
        "en": "NO flow in common even though both captures contain traffic: a "
              "device is probably rewriting the addresses (NAT) between the "
              "two points, or the captures are not of the same traffic. "
              "Comparison is impossible as it stands — capture both upstream "
              "AND downstream of the NAT, or filter on the translated traffic.",
    },
    "compare.no_common": {
        "fr": "aucun flux commun aux deux captures : verifier qu'elles portent "
              "sur le meme trafic et se recouvrent dans le temps.",
        "en": "no flow common to both captures: check that they cover the same "
              "traffic and overlap in time.",
    },
    "compare.direction_line": {
        "fr": "  * {sens} : {amont} emis, {aval} retrouves",
        "en": "  * {sens}: {amont} sent, {aval} found again",
    },
    "compare.lost": {
        "fr": ", {n} PERDUS ({taux:.1%})",
        "en": ", {n} LOST ({taux:.1%})",
    },
    "compare.latency": {
        "fr": "  * latence entre les deux points : {ms:.1f} ms (estimee sur "
              "des segments non retransmis, hypothese de symetrie des deux "
              "sens)",
        "en": "  * latency between the two points: {ms:.1f} ms (estimated on "
              "segments that were not retransmitted, assuming both directions "
              "are symmetric)",
    },
    "compare.clock_offset": {
        "fr": "  * decalage d'horloge estime entre les deux machines : {s:+.3f} s",
        "en": "  * estimated clock offset between the two hosts: {s:+.3f} s",
    },
    "compare.more_flows": {
        "fr": "\n... {n} autre(s) flux — --top pour en voir plus",
        "en": "\n... {n} more flow(s) — use --top to see more",
    },
    "compare.dir_c2s": {"fr": "client->serveur", "en": "client->server"},
    "compare.dir_s2c": {"fr": "serveur->client", "en": "server->client"},
    "compare.verdict_ambigu": {
        "fr": "aucun segment appariable : captures trop courtes ou non "
              "simultanees",
        "en": "no segment could be paired: captures too short or not "
              "simultaneous",
    },
    "compare.verdict_reseau": {
        "fr": "des segments emis ne sont jamais arrives au second point de "
              "capture ({detail}) — la perte se produit ENTRE les deux points",
        "en": "segments that were sent never reached the second capture point "
              "({detail}) — the loss happens BETWEEN the two points",
    },
    "compare.verdict_reseau_detail": {
        "fr": "{sens} : {perdus}/{amont} perdus",
        "en": "{sens}: {perdus}/{amont} lost",
    },
    "compare.verdict_ras": {
        "fr": "les {n} segments emis ont tous ete retrouves au second point : "
              "le chemin ENTRE les deux points de capture est hors de cause "
              "(chercher au-dela du second point)",
        "en": "all {n} segments that were sent were found again at the second "
              "point: the path BETWEEN the two capture points is not at fault "
              "(look beyond the second point)",
    },
    "compare.note_no_handshake": {
        "fr": "handshake absent d'au moins une des captures : decalage "
              "d'horloge non estimable, aucune latence n'est donnee (les "
              "comptages restent valables)",
        "en": "handshake missing from at least one capture: the clock offset "
              "cannot be estimated, so no latency is given (the counts remain "
              "valid)",
    },
    "compare.note_negative_latency": {
        "fr": "latence estimee negative : les deux sens du chemin n'ont pas la "
              "meme duree (routage asymetrique) ou une horloge a saute pendant "
              "la capture — traiter la latence comme indicative",
        "en": "estimated latency is negative: the two directions of the path "
              "do not take the same time (asymmetric routing) or a clock "
              "jumped during the capture — treat the latency as indicative "
              "only",
    },

    # ------------------------------------------------------------ explain
    "explain.unavailable": {
        "fr": "[--explain indisponible] {e}",
        "en": "[--explain unavailable] {e}",
    },
    "explain.no_sdk": {
        "fr": "Le SDK 'anthropic' n'est pas installe. Installer avec : "
              "pip install netverdict[explain]",
        "en": "The 'anthropic' SDK is not installed. Install it with: "
              "pip install netverdict[explain]",
    },
    "explain.no_credentials": {
        "fr": "Pas de credentials API valides. Definir ANTHROPIC_API_KEY ou se "
              "connecter avec `ant auth login`.",
        "en": "No valid API credentials. Set ANTHROPIC_API_KEY or log in with "
              "`ant auth login`.",
    },
    "explain.unreachable": {
        "fr": "API Anthropic injoignable (reseau ?).",
        "en": "Anthropic API unreachable (network?).",
    },
    "explain.api_error": {
        "fr": "Erreur API ({code}): {message}",
        "en": "API error ({code}): {message}",
    },
    "explain.refusal": {
        "fr": "La requete a ete declinee par les garde-fous du modele. Les "
              "verdicts et remediations du rapport restent valables tels quels.",
        "en": "The request was declined by the model's safeguards. The "
              "verdicts and fixes in the report remain valid as they are.",
    },
    "explain.user_prompt": {
        "fr": "Rapport netverdict a expliquer :\n\n{report}",
        "en": "netverdict report to explain:\n\n{report}",
    },
    # Nom de la langue tel qu'il est injecte dans le prompt systeme. C'est
    # CETTE ligne qui decide de la langue de la synthese narrative.
    "explain.language_name": {"fr": "francais", "en": "English"},

    # ------------------------------------------------------ cli : --help
    "help.description": {
        "fr": "Triage d'incident : la capture dit si c'est le reseau, "
              "l'application ou le systeme — avec preuves.",
        "en": "Incident triage: the capture tells you whether it is the "
              "network, the application or the host — with evidence.",
    },
    "help.lang": {
        "fr": "Langue de la sortie (defaut : en, ou $NETVERDICT_LANG)",
        "en": "Output language (default: en, or $NETVERDICT_LANG)",
    },
    "help.analyze": {
        "fr": "Analyse un pcap/pcapng et rend les verdicts",
        "en": "Analyse a pcap/pcapng and produce the verdicts",
    },
    "help.capture_arg": {
        "fr": "Fichier .pcap ou .pcapng (pour un .etl Windows : pktmon "
              "etl2pcap d'abord)",
        "en": "A .pcap or .pcapng file (for a Windows .etl: run pktmon "
              "etl2pcap first)",
    },
    "help.snapshot": {
        "fr": "snapshot.json d'etat hote pris pendant la capture",
        "en": "snapshot.json of host state taken during the capture",
    },
    "help.events": {
        "fr": "Events Windows : .evtx ou export XML wevtutil (cumulable) — "
              "alimente la timeline des changements",
        "en": "Windows events: .evtx or a wevtutil XML export (repeatable) — "
              "feeds the change timeline",
    },
    "help.syslog": {
        "fr": "Fichier syslog plat (cumulable) — alimente la timeline des "
              "changements",
        "en": "Flat syslog file (repeatable) — feeds the change timeline",
    },
    "help.audit": {
        "fr": "Journal auditd Linux (/var/log/audit/audit.log, cumulable) — "
              "retrouve le process d'un flux meme deja mort (parite Linux de "
              "Sysmon)",
        "en": "Linux auditd log (/var/log/audit/audit.log, repeatable) — "
              "finds the process behind a flow even once it is dead (the "
              "Linux counterpart of Sysmon)",
    },
    "help.syslog_tz": {
        "fr": "Fuseau des lignes RFC3164 (sans fuseau dans le format) : UTC, "
              "un decalage fixe (+02:00) ou un nom IANA (Europe/Paris). Par "
              "defaut : fuseau du poste d'analyse, ce qui decale un syslog "
              "central en UTC hors de la fenetre de la capture. Sans effet sur "
              "les lignes RFC5424, qui portent leur propre fuseau",
        "en": "Timezone of RFC3164 lines (the format carries none): UTC, a "
              "fixed offset (+02:00) or an IANA name (Europe/Paris). Default: "
              "the analysis host's timezone, which shifts a central syslog in "
              "UTC outside the capture window. No effect on RFC5424 lines, "
              "which carry their own timezone",
    },
    "help.syslog_tz_metavar": {"fr": "FUSEAU", "en": "TZ"},
    "help.rules": {
        "fr": "Fichier YAML de regles additionnelles (cumulable)",
        "en": "YAML file of additional rules (repeatable)",
    },
    "help.json": {"fr": "Sortie JSON complete", "en": "Full JSON output"},
    "help.top": {
        "fr": "Nombre max de conversations detaillees (defaut 10)",
        "en": "Max number of detailed conversations (default 10)",
    },
    "help.explain": {
        "fr": "Ajoute une synthese narrative via l'API Claude (optionnel, "
              "n'envoie que le rapport, jamais le pcap)",
        "en": "Add a narrative summary via the Claude API (optional, sends "
              "only the report, never the pcap)",
    },
    "help.capture": {
        "fr": "Capture assistee : trafic + etat hote en un coup",
        "en": "Assisted capture: traffic + host state in one go",
    },
    "help.duration": {
        "fr": "Duree de capture en secondes (defaut 60)",
        "en": "Capture duration in seconds (default 60)",
    },
    "help.out": {
        "fr": "Dossier de sortie du bundle",
        "en": "Output directory for the bundle",
    },
    "help.compare": {
        "fr": "Compare deux captures du meme trafic prises en deux points "
              "(client et serveur) : dit OU les paquets se perdent",
        "en": "Compare two captures of the same traffic taken at two points "
              "(client and server): tells you WHERE the packets are lost",
    },
    "help.amont": {
        "fr": "Capture cote CLIENT (point amont)",
        "en": "Capture on the CLIENT side (upstream point)",
    },
    "help.aval": {
        "fr": "Capture cote SERVEUR (point aval)",
        "en": "Capture on the SERVER side (downstream point)",
    },
    "help.compare_json": {"fr": "Sortie JSON", "en": "JSON output"},
    "help.compare_top": {
        "fr": "Nombre max de flux detailles (defaut 10)",
        "en": "Max number of detailed flows (default 10)",
    },
    "help.rules_cmd": {
        "fr": "Liste les regles de verdict chargees",
        "en": "List the verdict rules that are loaded",
    },
}
