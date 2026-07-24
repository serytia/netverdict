"""Contrat de la timeline multi-sources (v1.1) : le "qu'est-ce qui a change".

Le pcap dit CE QUI se passe sur le fil ; la timeline dit CE QUI A CHANGE dans
l'infra juste avant — service redemarre, regle firewall rechargee, passage
sur batterie, lien tombe. Le croisement des deux transforme un verdict en
explication.

CE FICHIER EST LE CONTRAT entre les parseurs de sources (sources/evtx.py,
sources/syslog.py) et la correlation/le rapport. Les parseurs produisent des
TimelineEvent normalises et ne font QUE parser (etage decoder, toujours) ;
la selection de la fenetre et le jugement de pertinence vivent ici.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

# Caracteres de controle C0/C1 (dont ESC) : un message syslog hostile peut
# contenir des sequences ANSI qui reecrivent le rapport a l'ecran (effacer
# les verdicts au-dessus, falsifier des lignes). Neutralise A L'EMISSION,
# dans le contrat : toute source presente et future est couverte.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAX_TEXT = 300


def _clean(text: str) -> str:
    return _CTRL_RE.sub(".", text)[:_MAX_TEXT]

# Categories fermees — le rapport et les regles de correlation s'appuient
# dessus, on n'invente pas de categorie dans un parseur sans l'ajouter ici.
CATEGORIES = {
    "change",    # configuration/etat modifie : service installe, regle
                 # rechargee, patch, planificateur — les suspects n°1
    "power",     # alimentation/energie : passage batterie, throttle, sleep
    "network",   # lien/interface/routage : ifdown, carrier lost, dhcp
    "service",   # cycle de vie process/service : start/stop/crash/restart
    "reboot",    # demarrage/arret de l'hote entier
    "error",     # erreur signalee par la source, sans categorie plus fine
    "info",      # le reste — garde pour le contexte, jamais mis en avant
}

# Les categories considerees comme des CHANGEMENTS d'infra, celles que le
# rapport met en avant quand elles precedent l'incident.
CHANGE_CATEGORIES = {"change", "power", "network", "service", "reboot"}


@dataclass
class TimelineEvent:
    """Un evenement normalise, quelle que soit sa source.

    ts        : epoch en secondes, UTC (float — meme axe que les paquets).
                Les sources en heure locale doivent convertir AVANT d'emettre ;
                un parseur qui ne connait pas le fuseau le dit via tz_known.
    source    : "evtx" | "syslog" (extensible ; minuscule, court).
    host      : machine emettrice telle que la source la nomme ("" si inconnu).
    category  : une valeur de CATEGORIES.
    severity  : 0 (info) a 3 (critique) — echelle grossiere volontaire.
    ident     : identifiant natif : Event ID Windows ("7045"), program name
                syslog ("sshd") — ce que l'admin recherchera dans sa source.
    message   : resume humain UNE ligne, deja nettoye par le parseur.
    tz_known  : False si le timestamp a ete interprete sans fuseau fiable
                (syslog RFC3164...) — le rapport l'affiche avec prudence.
    """

    ts: float
    source: str
    host: str
    category: str
    severity: int
    ident: str
    message: str
    tz_known: bool = True

    def __post_init__(self):
        if self.category not in CATEGORIES:
            raise ValueError(f"categorie inconnue: {self.category!r} "
                             f"(attendu: {sorted(CATEGORIES)})")
        self.message = _clean(self.message)
        self.host = _clean(self.host)
        self.ident = _clean(self.ident)


@dataclass
class SourceStats:
    """Comptabilite de lecture d'une source — meme philosophie que ParseStats :
    l'honnetete du rapport exige de dire ce qu'on n'a PAS su lire."""

    total_lines: int = 0          # lignes/records rencontres
    parsed: int = 0               # convertis en TimelineEvent
    unparsed: int = 0             # illisibles (comptes, jamais fatals)


# ---------------------------------------------------------------------------
# Contrat des parseurs (sources/*.py) :
#
#   def parse(path: str | Path) -> tuple[list[TimelineEvent], SourceStats]
#
# - Ne leve que sur fichier illisible/format irreconnaissable (ValueError
#   avec message actionnable) ; une ligne/un record pourri est compte dans
#   stats.unparsed et saute.
# - Trie par ts croissant avant de retourner.
# - N'applique AUCUN filtre temporel : la fenetre, c'est ici.
# ---------------------------------------------------------------------------


# Fenetre d'interet par defaut autour de la capture : les changements des
# 15 minutes precedentes sont les suspects naturels ; apres la fin de la
# capture, plus rien ne peut avoir cause ce qu'elle contient.
DEFAULT_LOOKBACK_S = 15 * 60


@dataclass
class Timeline:
    events: list[TimelineEvent] = field(default_factory=list)
    stats: dict[str, SourceStats] = field(default_factory=dict)
    # True quand window() a REELLEMENT filtre — le rapport doit dire quand
    # la fenetre n'a pas pu s'appliquer (capture sans paquet TCP date),
    # sinon « fenetre de la capture » est un mensonge d'en-tete.
    windowed: bool = False

    def add_source(self, name: str, events: Iterable[TimelineEvent],
                   stats: SourceStats) -> None:
        # Deux fichiers homonymes (hostA/syslog.log, hostB/syslog.log) ne
        # doivent pas ecraser leurs stats : suffixe de collision.
        key = name
        n = 2
        while key in self.stats:
            key = f"{name}#{n}"
            n += 1
        self.events.extend(events)
        self.events.sort(key=lambda e: e.ts)
        self.stats[key] = stats

    def window(self, t_start: Optional[float], t_end: Optional[float],
               lookback_s: float = DEFAULT_LOOKBACK_S) -> "Timeline":
        """Evenements pertinents pour une capture [t_start, t_end].

        Sans bornes de capture (pcap sans TCP), on ne fenetre pas : tout
        garder, windowed reste False et le rapport le dit.
        """
        if t_start is None or t_end is None:
            return self
        lo, hi = t_start - lookback_s, t_end
        return Timeline(events=[e for e in self.events if lo <= e.ts <= hi],
                        stats=self.stats, windowed=True)

    def changes(self) -> list[TimelineEvent]:
        """Les evenements de changement d'infra, du plus recent au plus
        ancien (l'ordre dans lequel on suspecte)."""
        return sorted((e for e in self.events
                       if e.category in CHANGE_CATEGORIES),
                      key=lambda e: -e.ts)
