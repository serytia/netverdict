"""Correlation changement d'infra <-> verdict de flux (v1.2).

La timeline (timeline.py) repond « qu'est-ce qui a change dans l'infra ». Ce
module repond la question suivante, celle que l'admin se pose vraiment :
« lequel de ces changements concerne CE flux en panne ? »

CE QU'IL FAIT ET CE QU'IL NE FAIT PAS
-------------------------------------
Il RANGE des suspects par pertinence. Il ne conclut JAMAIS a la causalite, et
le vocabulaire du rapport doit rester celui du soupcon. Deux raisons :

  1. La coincidence temporelle n'est pas la causalite. Sur une infra vivante,
     un changement precede a peu pres toujours un incident.
  2. On ne connait pas l'instant exact de l'anomalie. FlowSignals porte
     t_first (premier paquet du flux) et duration_s, pas l'horodatage du RST
     ou de la retransmission. Un changement « pendant » le flux peut donc
     etre exactement la cause d'un RST en pleine session — ou n'avoir aucun
     rapport. On le signale, on ne tranche pas.

On CLASSE, on ne FILTRE pas : un changement dont la categorie ne « colle » pas
au verdict reste affiche, simplement plus bas. Ecarter un changement parce
qu'il ne correspond pas a la theorie du moment serait exactement la faute que
cet outil existe pour eviter.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .rules.engine import FlowVerdict
from .timeline import CHANGE_CATEGORIES, Timeline, TimelineEvent

# Fenetre au-dela de laquelle un changement anterieur n'est plus rattache a un
# flux precis. Alignee sur le seuil deja utilise par le rapport pour marquer
# « precede l'incident » (report.py) : un seul seuil dans l'outil, pas deux
# qui divergeraient.
STRONG_WINDOW_S = 300.0

# Combien de suspects au plus par flux. Au-dela, le panneau de verdict devient
# une liste de logs et noie ce qu'il devait mettre en avant ; la section
# globale de la timeline reste la pour tout voir.
MAX_SUSPECTS_PER_FLOW = 3

# Affinite categorie de changement <-> verdict : quel type de changement peut
# PLAUSIBLEMENT produire ce type de panne. Sert uniquement a classer, jamais a
# exclure. Chaque ligne encode un raisonnement d'expert, pas une statistique.
_AFFINITY: dict[str, set[str]] = {
    # Paquets perdus, SYN sans reponse, ICMP de rejet : un changement de lien,
    # d'adressage ou de regle de filtrage est le suspect naturel. Un hote qui
    # redemarre explique aussi un SYN sans reponse.
    "RESEAU": {"network", "change", "reboot"},
    # Rien n'ecoute sur le port, ou reponse applicative lente : un service qui
    # vient de tomber/redemarrer, un paquet mis a jour, un hote pas encore
    # remonte.
    "APP": {"service", "change", "reboot"},
    # L'application ne lit plus sa socket (zero window) : bascule sur batterie
    # (CPU bride), service en difficulte, changement de configuration.
    "OS": {"power", "service", "change"},
    "HOTE": {"power", "service", "change"},
    # AMBIGU l'est par construction : afficher une affinite donnerait une
    # fausse impression de piste. Aucune categorie privilegiee.
    "AMBIGU": set(),
}


@dataclass
class Suspect:
    """Un changement d'infra rattache a un flux, avec de quoi le juger."""

    event: TimelineEvent
    # Ecart signe par rapport au PREMIER PAQUET du flux : positif = le
    # changement precede le flux, negatif = il survient pendant.
    delay_s: float
    # La categorie du changement peut-elle plausiblement produire ce verdict ?
    affinity: bool

    @property
    def during_flow(self) -> bool:
        return self.delay_s < 0

    def describe(self) -> str:
        """Une ligne pour le rapport. Sur un horodatage sans fuseau fiable
        (RFC3164 sans --syslog-tz), pas de precision a la seconde : afficher
        un chiffre qu'on n'a pas serait mentir."""
        ecart = abs(self.delay_s)
        if self.event.tz_known:
            quand = f"{ecart:.0f} s"
        else:
            quand = f"environ {max(1, round(ecart / 60))} min (heure source approximative)"
        position = "pendant le flux" if self.during_flow else "avant le flux"
        return f"{quand} {position}"


def suspects_for(fv: FlowVerdict, timeline: Timeline,
                 window_s: float = STRONG_WINDOW_S,
                 limit: int = MAX_SUSPECTS_PER_FLOW) -> list[Suspect]:
    """Changements d'infra a verifier pour ce flux, du plus pertinent au moins.

    Candidats : les changements survenus dans [t_first - window_s, fin du flux].
    On inclut ce qui se produit PENDANT le flux parce qu'un RST en pleine
    session ou une chute de debit peut avoir ete cause par un changement
    posterieur au premier paquet — l'instant de l'anomalie nous est inconnu.

    Tri : affinite d'abord (un changement du bon type passe devant), puis
    proximite temporelle. Aucun candidat n'est exclu pour manque d'affinite.

    Un flux sain (RAS) ou sans verdict ne recoit rien : rattacher des
    changements a un flux qui va bien ne produirait que du bruit.
    """
    if fv.primary is None or fv.verdict == "RAS":
        return []

    # Pas de garde de "verite" sur t_first : l'epoch 0 est une VALEUR, pas une
    # absence (pcap synthetique ou anonymise). Un `if not t_first` desactivait
    # la correlation en silence sur ces captures — precisement le genre de
    # panne muette que cet outil existe pour debusquer.
    t_first = fv.signals.t_first
    t_end = t_first + max(0.0, fv.signals.duration_s)
    plausibles = _AFFINITY.get(fv.verdict or "", set())

    out: list[Suspect] = []
    for e in timeline.events:
        if e.category not in CHANGE_CATEGORIES:
            continue
        if not (t_first - window_s <= e.ts <= t_end):
            continue
        out.append(Suspect(event=e, delay_s=t_first - e.ts,
                           affinity=e.category in plausibles))

    # Affinite decroissante, puis le plus proche du debut du flux d'abord.
    out.sort(key=lambda s: (not s.affinity, abs(s.delay_s)))
    return out[:limit]


def correlate(verdicts: list[FlowVerdict],
              timeline: Optional[Timeline]) -> dict[int, list[Suspect]]:
    """Table {index du flux dans `verdicts` -> suspects}.

    Indexee par position et non par objet : FlowVerdict n'est pas hashable
    (dataclass mutable), et deux flux peuvent partager le meme quadruplet
    dans une capture longue.
    """
    if timeline is None:
        return {}
    return {i: s for i, fv in enumerate(verdicts)
            if (s := suspects_for(fv, timeline))}
