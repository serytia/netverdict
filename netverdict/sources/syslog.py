"""Parseur syslog (RFC5424 et RFC3164, plus le cas degrade kern.log/messages
sans <PRI>) -> TimelineEvent normalises. Voir timeline.py pour LE CONTRAT
(TimelineEvent, SourceStats, signature de parse()) : ce module ne fait
qu'implementer un parseur de sources, il ne juge pas la pertinence.

Etage "decoder" au sens Wazuh (meme framing que pcap.py) : parser et
classer par mots-cles, jamais choisir ce qui est pertinent (ca, c'est
timeline.Timeline : fenetre, tri de priorite).

Un fichier syslog reel melange les formats LIGNE PAR LIGNE (rsyslog peut
reecrire en 5424 pendant qu'une vieille appliance parle encore 3164, et le
kernel local ecrit dans /var/log/kern.log sans meme un <PRI>) : la decision
de format se prend par ligne, jamais au niveau du fichier entier.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from ..timeline import SourceStats, TimelineEvent

# --------------------------------------------------------------------------
# Formats de ligne reconnus, dans l'ordre ou on les essaie :
#   a) RFC5424 : <PRI>1 TIMESTAMP-ISO-AVEC-FUSEAU HOST APP PID MSGID SD MSG
#   b) RFC3164 : <PRI>Mon dd HH:MM:SS HOST TAG[PID]: MSG (pas d'annee/fuseau)
#   c) meme forme que (b) mais SANS <PRI> (kern.log/messages bruts)
#   d) tout le reste -> stats.unparsed, on saute (jamais fatal : un fichier
#      syslog reel contient toujours une ligne tronquee ou binaire).
# --------------------------------------------------------------------------

_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$"
)

# Le jour est zero- OU espace-pade selon l'emetteur ("Jul 24" ou "Jul  1",
# ce dernier issu de %e en C) : \s+ tolere les deux, \d{1,2} le jour seul.
_RFC3164_TS = r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
_RFC3164_PRI_RE = re.compile(r"^<(\d{1,3})>(" + _RFC3164_TS + r")\s+(\S+)\s+(.*)$")
_RFC3164_NOPRI_RE = re.compile(r"^(" + _RFC3164_TS + r")\s+(\S+)\s+(.*)$")
_RFC3164_TS_FIELDS_RE = re.compile(
    r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$"
)

# TAG[PID]: MESSAGE - le PID est optionnel (ex. "kernel:" n'en a pas) ; le
# tag s'arrete au premier '[' ou ':' rencontre (jamais d'espace dedans en
# pratique). Si aucun ':' n'est trouve, la ligne est hors-forme : on garde
# tout comme message plutot que d'inventer une coupure (jamais fatal).
_TAG_RE = re.compile(r"^([^\s\[\]:]+)(?:\[(\d+)\])?:\s*(.*)$")

# Blocs de structured-data RFC5424 consecutifs : "[id a=\"1\"][id2 b=\"2\"]"
# (pas de separateur entre elements, c'est la grammaire RFC5424). Un ']'
# ECHAPPE (\]) dans une valeur de parametre ne termine pas le bloc — sans
# cette alternative, un SD contenant \] tronquait le debut du message.
_SD_BLOCK_RE = re.compile(r"^(?:\[(?:[^\\\]]|\\.)*\])+")

_MONTHS = {m: i + 1 for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun",
     "jul", "aug", "sep", "oct", "nov", "dec"])}

# Un log RFC3164 n'a pas d'annee : on suppose l'annee courante, sauf si ca
# place le timestamp trop loin dans le futur (log de decembre relu en
# janvier) - 26h de marge pour couvrir un decalage d'horloge/fuseau
# raisonnable sans confondre "cette nuit" avec "il y a un an".
_FUTURE_SLACK = timedelta(hours=26)


def _nil(value: str) -> str:
    """Convention NILVALUE syslog ("-") -> inconnu, meme regle que le
    contrat pour host ("" si inconnu) : on l'applique aussi a ident."""
    return "" if value == "-" else value


def _severity_from_pri(pri: Optional[int]) -> int:
    """PRI syslog -> echelle projet 0 (info) a 3 (critique).

    Sans PRI du tout (RFC3164 degrade, cas c) : 1 par convention - ni
    anodin ni critique, on ne sait juste pas et on ne l'invente pas.
    """
    if pri is None:
        return 1
    syslog_severity = pri % 8
    if syslog_severity <= 2:      # emergency/alert/critical
        return 3
    if syslog_severity == 3:      # error
        return 2
    if syslog_severity == 4:      # warning
        return 1
    return 0                      # notice/info/debug


# Categorisation par mots-cles, appliquee sur "ident message" en un bloc.
# PREMIER pattern qui matche gagne : la liste est deja dans l'ordre de
# priorite des categories (network > reboot > change > service) - a
# l'interieur d'une categorie l'ordre des patterns n'importe pas, ils
# menent tous a la meme categorie. Tout est compile une fois a l'import.
_CATEGORY_RULES: list[tuple[str, re.Pattern]] = [
    # --- network : lien/interface/routage --------------------------------
    ("network", re.compile(r"\blink\s+(down|up)\b", re.I)),
    ("network", re.compile(r"\bcarrier\s+(lost|acquired|detected)\b", re.I)),
    # ifdown/ifup : scripts Debian/RedHat historiques, le nom dit tout.
    ("network", re.compile(r"\bif(down|up)\b", re.I)),
    ("network", re.compile(r"\binterface\b.*\b(down|up)\b", re.I)),
    # Un bail DHCP qui change = adressage qui bouge, cause frequente de
    # trous reseau qu'aucune autre source ne signale.
    ("network", re.compile(r"\bdhcp\b.*\b(lease|bound|renew)", re.I)),
    ("network", re.compile(r"\bport\b.*\b(down|up)\b", re.I)),

    # --- reboot : demarrage/arret de l'hote entier ------------------------
    ("reboot", re.compile(r"\b(system|kernel)\s+(boot|start|restart|shutdown|halt)\b", re.I)),
    # rsyslogd qui (re)demarre = l'hote lui-meme vient de le faire.
    ("reboot", re.compile(r"\brsyslogd\b.*\bstart", re.I)),
    # Premiere ligne du kernel au demarrage (dmesg/kern.log classique).
    ("reboot", re.compile(r"\bbooting\b", re.I)),
    # Les formes les plus courantes d'un cycle Linux reel : systemd-shutdown
    # ecrit "Rebooting."/"Powering off." (pas de frontiere de mot avant
    # "boot" dans "Rebooting" -> pattern dedie), et la toute premiere ligne
    # du kernel est "Linux version ...".
    ("reboot", re.compile(r"\b(re)?boot(ing|ed)\b|\bpowering (off|down)\b"
                          r"|\blinux version\b", re.I)),

    # --- change : config/etat modifie, les suspects n 1 --------------------
    ("change", re.compile(r"\breload(ed|ing)?\b", re.I)),
    ("change", re.compile(r"\bconfiguration\b.*\b(chang\w*|commit\w*|appli\w*)", re.I)),
    ("change", re.compile(r"\bconfig\b.*\b(sav\w*|load\w*|commit\w*)", re.I)),
    ("change", re.compile(r"\bfirewall\b.*\b(reload\w*|rule\w*|appli\w*)", re.I)),
    ("change", re.compile(r"\b(install|upgrad|updat)(ed|ing)\b.*\bpackage\b", re.I)),
    ("change", re.compile(r"\bpackage\b.*\b(install\w*|upgrad\w*)", re.I)),

    # --- service : cycle de vie process/service ---------------------------
    ("service", re.compile(r"\bsystemd\b.*\b(started|stopped|starting|stopping|failed)\b", re.I)),
    ("service", re.compile(r"\b(daemon|service)\b.*\b(start\w*|stop\w*|restart\w*|fail\w*|crash\w*)", re.I)),
    ("service", re.compile(r"\bexited with (code|status)\b", re.I)),
    ("service", re.compile(r"\bsegfault\b", re.I)),
]


def _categorize(ident: str, message: str, severity: int) -> str:
    text = f"{ident} {message}"
    for category, pattern in _CATEGORY_RULES:
        if pattern.search(text):
            return category
    # Rien de specifique : une severite marquee reste un signal (error),
    # le reste est garde pour le contexte mais jamais mis en avant (info).
    return "error" if severity >= 2 else "info"


def _split_sd_and_message(rest: str) -> str:
    """Retire le champ structured-data RFC5424 en tete de `rest` et
    renvoie le message restant.

    SD = NILVALUE "-" (seul ou suivi du message) ou une ou plusieurs
    sequences "[SD-ID ...]" accolees. Si ni l'un ni l'autre (ligne hors
    forme), on garde tout comme message plutot que de deviner une coupure.
    """
    rest = rest.strip()
    if rest == "-":
        return ""
    if rest.startswith("- "):
        return rest[2:].strip()
    m = _SD_BLOCK_RE.match(rest)
    if m:
        return rest[m.end():].strip()
    return rest


def _split_tag(rest: str) -> tuple[str, str]:
    """"TAG[PID]: message" -> (ident sans le pid, message). Fallback si
    hors forme (pas de ':') : ident inconnu, tout devient le message."""
    m = _TAG_RE.match(rest)
    if not m:
        return "", rest.strip()
    tag, _pid, message = m.groups()
    return _nil(tag), message.strip()


def _rfc3164_epoch(ts_raw: str, now: Optional[datetime] = None) -> Optional[float]:
    """Timestamp RFC3164 ("Mon dd HH:MM:SS", pas d'annee ni de fuseau) ->
    epoch UTC.

    Annee absente : on suppose l'annee courante de la machine d'analyse,
    sauf si le resultat tombe a plus de _FUTURE_SLACK dans le futur (log
    de decembre relu en janvier) -> annee precedente. L'heure est
    interpretee dans le fuseau LOCAL de la machine d'analyse (c'est la
    seule info disponible) ; l'appelant pose tz_known=False en consequence.

    `now` est injectable (tests) ; par defaut l'horloge reelle.
    """
    m = _RFC3164_TS_FIELDS_RE.match(ts_raw)
    if not m:
        return None
    mon_s, day_s, h_s, mi_s, s_s = m.groups()
    month = _MONTHS.get(mon_s.lower())
    if month is None:
        return None
    now = now or datetime.now()
    try:
        day, hour, minute, second = int(day_s), int(h_s), int(mi_s), int(s_s)
        dt = datetime(now.year, month, day, hour, minute, second)
    except ValueError:
        return None
    if dt - now > _FUTURE_SLACK:
        try:
            dt = datetime(now.year - 1, month, day, hour, minute, second)
        except ValueError:
            return None
    # Naive + heure locale : datetime.timestamp() traite un datetime naif
    # comme de l'heure LOCALE de la machine et le convertit en epoch UTC -
    # exactement la semantique voulue ici (pas d'astimezone() a la main).
    return dt.timestamp()


def _parse_rfc5424(line: str) -> Optional[TimelineEvent]:
    m = _RFC5424_RE.match(line)
    if not m:
        return None
    pri_s, _version, ts_s, host, app, _pid, _msgid, rest = m.groups()
    try:
        pri = int(pri_s)
    except ValueError:
        return None
    try:
        dt = datetime.fromisoformat(ts_s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        # RFC5424 impose un fuseau explicite ; sans lui on ne devine pas
        # (contrairement au 3164, ou l'absence de fuseau est la norme).
        return None
    ts = dt.timestamp()
    message = _split_sd_and_message(rest)
    severity = _severity_from_pri(pri)
    ident = _nil(app)
    category = _categorize(ident, message, severity)
    return TimelineEvent(ts=ts, source="syslog", host=_nil(host), category=category,
                         severity=severity, ident=ident, message=message,
                         tz_known=True)


def _parse_rfc3164(line: str, now: Optional[datetime] = None) -> Optional[TimelineEvent]:
    m = _RFC3164_PRI_RE.match(line)
    if not m:
        return None
    pri_s, ts_raw, host, rest = m.groups()
    try:
        pri = int(pri_s)
    except ValueError:
        return None
    ts = _rfc3164_epoch(ts_raw, now)
    if ts is None:
        return None
    ident, message = _split_tag(rest)
    severity = _severity_from_pri(pri)
    category = _categorize(ident, message, severity)
    return TimelineEvent(ts=ts, source="syslog", host=_nil(host), category=category,
                         severity=severity, ident=ident, message=message,
                         tz_known=False)


def _parse_rfc3164_nopri(line: str, now: Optional[datetime] = None) -> Optional[TimelineEvent]:
    m = _RFC3164_NOPRI_RE.match(line)
    if not m:
        return None
    ts_raw, host, rest = m.groups()
    ts = _rfc3164_epoch(ts_raw, now)
    if ts is None:
        return None
    ident, message = _split_tag(rest)
    severity = _severity_from_pri(None)   # pas de PRI -> 1, par convention
    category = _categorize(ident, message, severity)
    return TimelineEvent(ts=ts, source="syslog", host=_nil(host), category=category,
                         severity=severity, ident=ident, message=message,
                         tz_known=False)


def parse(path: str | Path,
          now: Optional[datetime] = None) -> tuple[list[TimelineEvent], SourceStats]:
    """Lit un fichier syslog plat (formats melanges, ligne par ligne).

    Chaque ligne est essayee dans l'ordre a) RFC5424, b) RFC3164 avec PRI,
    c) RFC3164 sans PRI ; celle qui ne matche rien est comptee dans
    stats.unparsed et sautee - jamais fatal (une capture reelle contient
    toujours du bruit : ligne tronquee, binaire egare, encodage foireux).

    `now` est l'ANCRE de datation des lignes RFC3164 (sans annee) : par
    defaut l'horloge de la machine d'analyse, mais l'appelant qui analyse
    un bundle ARCHIVE doit passer la date de la capture (cli.py passe la
    fin du pcap) — sinon un log de fevrier relu en juillet prendrait
    l'annee en cours et sortirait de la fenetre en silence. Ce n'est pas
    un filtre temporel (le contrat l'interdit), juste l'ancre du calendrier.

    Ne leve que si le fichier lui-meme est illisible (chemin absent,
    permission refusee...) : ValueError avec message actionnable, pour que
    l'appelant (cli.py) l'affiche proprement plutot que de crasher.
    """
    p = Path(path)
    try:
        # errors="replace" : un octet non-UTF-8 egare (log binaire, encodage
        # legacy) devient un caractere de remplacement plutot qu'un crash ;
        # la ligne corrompue ne matchera aucun format et sera comptee.
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(f"syslog illisible ({p}): {exc}") from exc

    now = now or datetime.now()
    events: list[TimelineEvent] = []
    stats = SourceStats()

    for line in text.splitlines():
        stats.total_lines += 1
        ev = _parse_rfc5424(line)
        if ev is None:
            ev = _parse_rfc3164(line, now)
        if ev is None:
            ev = _parse_rfc3164_nopri(line, now)
        if ev is None:
            stats.unparsed += 1
            continue
        stats.parsed += 1
        events.append(ev)

    events.sort(key=lambda e: e.ts)
    return events, stats
