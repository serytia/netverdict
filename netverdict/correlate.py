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


# ---------------------------------------------------------------------------
# Jointure process <-> flux, retroactive (v1.2)
#
# Le snapshot d'hote (hostsnap.py) est pris a UN instant : il rate le process
# deja mort quand la capture s'arrete. Une source d'evenements date chaque
# connexion a son etablissement, donc elle retrouve le process meme disparu.
# ---------------------------------------------------------------------------

# Tolerance d'horloge entre la capture et le journal d'evenements. Sur une
# meme machine (cas normal : capture + Sysmon cote a cote), l'ecart est nul ;
# la marge couvre un pcap et des events venant de deux hotes.
CLOCK_TOLERANCE_S = 60.0


@dataclass
class ProcessAttribution:
    """Le process qui detenait la socket, retrouve a posteriori."""

    event: TimelineEvent
    # "client" ou "serveur" : de quel COTE du flux se trouve ce process. Savoir
    # lequel des deux on a identifie change entierement la lecture du verdict.
    side: str
    # Nombre total d'evenements de connexion qui collaient a ce flux. > 1 =
    # reutilisation de port sur une capture longue : on affiche le plus proche
    # du debut du flux, mais l'admin doit savoir qu'il y avait ambiguite.
    candidates: int = 1

    @property
    def connection(self):
        return self.event.connection

    def describe(self) -> str:
        c = self.connection
        assert c is not None                      # garanti par la construction
        txt = f"{c.process_label()} cote {self.side}"
        if c.user:
            txt += f", utilisateur {c.user}"
        if self.candidates > 1:
            txt += (f" — {self.candidates} connexions correspondaient "
                    f"(port reutilise ?), la plus proche du debut du flux")
        return txt


def _norm_ip(value: str) -> str:
    """Forme canonique d'une adresse, pour comparer deux sources qui ne
    l'ecrivent pas de la meme facon.

    pcap.py passe par socket.inet_ntop, donc l'IPv6 en sort COMPRESSEE
    ("fe80::1"). Sysmon rend la forme etendue ("fe80:0:0:0:0:0:0:1"), et une
    adresse lien-local peut trainer un identifiant de zone ("fe80::1%12").
    Comparer les chaines brutes faisait echouer la jointure sur TOUT flux
    IPv6, sans aucun signal — la panne muette typique.

    Une valeur non analysable revient telle quelle en minuscules : mieux vaut
    une comparaison litterale qu'une exception sur une donnee douteuse.
    """
    import ipaddress

    txt = (value or "").strip().lower()
    if not txt:
        return ""
    txt = txt.split("%", 1)[0]            # retire l'identifiant de zone
    try:
        return ipaddress.ip_address(txt).compressed
    except ValueError:
        return txt


def _same_endpoint(ip_a: str, port_a: int, ip_b: str, port_b: int) -> bool:
    return port_a == port_b and _norm_ip(ip_a) == _norm_ip(ip_b)


def _side_of(conn, sig) -> Optional[str]:
    """De quel cote du flux se trouve le process de cet evenement ?

    On teste les DEUX sens du quadruplet : l'evenement peut avoir ete emis par
    la machine cliente (elle initie) ou par la machine serveur (elle recoit).
    Une correspondance partielle ne compte pas — un port identique sur une
    autre adresse est un autre flux.
    """
    if (_same_endpoint(conn.src_ip, conn.src_port, sig.client, sig.cport)
            and _same_endpoint(conn.dst_ip, conn.dst_port, sig.server, sig.sport)):
        return "client"
    if (_same_endpoint(conn.src_ip, conn.src_port, sig.server, sig.sport)
            and _same_endpoint(conn.dst_ip, conn.dst_port, sig.client, sig.cport)):
        return "serveur"
    return None


def attribution_for(fv: FlowVerdict, timeline: Timeline,
                    tolerance_s: float = CLOCK_TOLERANCE_S,
                    ) -> Optional[ProcessAttribution]:
    """Retrouve le process d'un flux via les evenements de connexion.

    Contrairement aux suspects, cette jointure vaut AUSSI pour un flux sain :
    savoir quel process parle est utile meme sans panne.
    """
    sig = fv.signals
    t_end = sig.t_first + max(0.0, sig.duration_s)
    trouves: list[tuple[float, TimelineEvent, str]] = []

    for e in timeline.events:
        c = e.connection
        if c is None:
            continue
        # TCP seulement : le reste des flux n'est pas modelise par cet outil.
        if c.protocol and c.protocol != "tcp":
            continue
        if not (sig.t_first - tolerance_s <= e.ts <= t_end + tolerance_s):
            continue
        side = _side_of(c, sig)
        if side is None:
            continue
        trouves.append((abs(e.ts - sig.t_first), e, side))

    if not trouves:
        return None
    trouves.sort(key=lambda t: t[0])
    _ecart, event, side = trouves[0]
    return ProcessAttribution(event=event, side=side, candidates=len(trouves))


def attributions(verdicts: list[FlowVerdict],
                 timeline: Optional[Timeline]) -> dict[int, ProcessAttribution]:
    """Table {index du flux -> attribution}, meme convention que correlate()."""
    if timeline is None:
        return {}
    return {i: a for i, fv in enumerate(verdicts)
            if (a := attribution_for(fv, timeline))}


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
