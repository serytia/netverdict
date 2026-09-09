"""Detection des rafales de journaux : le "qui parle trop fort, et quand".

Une machine qui tombe juste apres une operation planifiee (scan, deploiement,
sauvegarde) fait accuser l'operation. Souvent a tort : ce qui l'a mise a terre
est une application partie en boucle d'erreur, qui ecrit des centaines de
lignes par minute jusqu'a saturer le disque, le collecteur ou le CPU. Cette
rafale est parfaitement visible dans le syslog, mais noyee : personne ne lit
900 lignes identiques, et aucun etage de netverdict ne les comptait.

Ce module compte, et rien d'autre. Il ne juge pas la cause (c'est
correlate.py) et ne parse rien (c'est sources/syslog.py) : il transforme un
tas d'evenements deja normalises en UN evenement par rafale, avec de quoi
l'ecrire dans le rapport. Meme discipline que le reste du projet : l'etage
qui mesure ne conclut jamais.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from statistics import median
from typing import Iterable, Iterator

from .timeline import TimelineEvent

# Longueur de l'extrait de message affiche : de quoi reconnaitre la ligne
# ("ORA-00060: deadlock detected while waiting for resource") sans casser la
# mise en page du rapport, qui tient sur 100 colonnes.
_SAMPLE_MAX = 80


@dataclass
class BurstEvent(TimelineEvent):
    """Une rafale, vue comme un TimelineEvent (contrat timeline.py) PLUS les
    champs chiffres dont le rapport a besoin.

    Le sous-typage est delibere : la rafale doit voyager dans `Timeline.events`
    comme n'importe quel evenement — sinon la fenetre, le tri et la correlation
    devraient chacun apprendre un type de plus. Les consommateurs qui n'en
    savent rien la traitent comme un evenement normal ; ceux qui veulent le
    detail testent `isinstance`.

    end             : fin du dernier seau (epoch, UTC), donc `end - ts` = duree.
    lines           : nombre de lignes de la rafale.
    peak_per_min    : le seau le plus haut, ramene a la minute.
    baseline_per_min: le rythme habituel du couple (host, ident), a la minute.
    sample          : extrait du message le plus frequent de la rafale.
    """

    end: float = 0.0
    lines: int = 0
    peak_per_min: int = 0
    baseline_per_min: int = 0
    sample: str = ""


def _bucket_of(ts: float, bucket_s: int) -> int:
    """Seau aligne contenant `ts`. La division entiere de Python arrondit vers
    le BAS y compris pour les negatifs (pcap a l'epoch 0, horodatage aberrant),
    la ou int() tronquerait vers zero et melangerait deux seaux."""
    return int(ts // bucket_s) * bucket_s


def _runs(buckets: list[int], bucket_s: int) -> Iterator[list[int]]:
    """Suites de seaux CONSECUTIFS dans une liste triee.

    Une application qui hurle pendant trois minutes est UN incident, pas trois.
    Sans cette fusion, le rapport afficherait la meme rafale autant de fois
    qu'elle dure, et « la plus grosse rafale » deviendrait un artefact du
    decoupage en seaux.
    """
    run: list[int] = []
    for b in buckets:
        if run and b != run[-1] + bucket_s:
            yield run
            run = []
        run.append(b)
    if run:
        yield run


def _baseline(counts: list[int]) -> float:
    """Rythme habituel d'un couple (host, ident), en lignes par seau.

    Mediane et non moyenne : une seule rafale de 900 lignes tire une moyenne
    assez haut pour se cacher elle-meme. Les DEUX seaux les plus hauts sont
    exclus avant le calcul, parce qu'une rafale occupe souvent deux seaux (elle
    tombe rarement pile sur une frontiere de minute) et qu'un seul exclu
    laisserait sa moitie polluer la base.

    Moins de trois seaux non vides : base = 0. On n'a alors AUCUNE idee du
    rythme normal, et une base inventee a partir de deux points ferait passer
    n'importe quel demarrage de service pour une rafale. Base 0 renvoie la
    decision au seuil absolu, seul defendable a ce stade.
    """
    if len(counts) < 3:
        return 0.0
    return float(median(sorted(counts)[:-2]))


def detect_bursts(events: Iterable[TimelineEvent], bucket_s: int = 60,
                  min_lines: int = 200, ratio: int = 20) -> list[TimelineEvent]:
    """Repere les rafales dans une liste d'evenements deja normalises.

    Regroupement par (host, ident) puis par seau de `bucket_s` secondes aligne
    sur l'epoch. Un seau est en rafale si son compte atteint
    `max(min_lines, ratio * base)` — les deux conditions ensemble, jamais l'une
    seule :

      - `min_lines = 200` lignes/minute, soit plus de 3 lignes par seconde :
        au-dessus de ce qu'un humain lit, et sous les limites de debit par
        defaut de rsyslog (qui commence a jeter des lignes bien plus haut), donc
        un seuil qu'un serveur sain ne franchit pas par hasard. Sans ce plancher,
        un hote silencieux a 1 ligne/min declencherait a 20 lignes.
      - `ratio = 20` fois la base : un demon bavard qui ecrit 10 lignes/min en
        temps normal ne doit pas declencher a 190. Sans ce facteur, un
        collecteur central verbeux serait en rafale en permanence.

    Retourne les rafales triees par date, une par suite de seaux consecutifs.
    Ne leve que sur un `bucket_s` absurde : cette fonction est un compteur, elle
    ne doit jamais faire echouer une analyse.
    """
    if bucket_s <= 0:
        raise ValueError(f"bucket_s must be > 0 (got {bucket_s})")

    groupes: dict[tuple[str, str], list[TimelineEvent]] = defaultdict(list)
    for e in events:
        groupes[(e.host, e.ident)].append(e)

    rafales: list[TimelineEvent] = []
    for (host, ident), evs in groupes.items():
        seaux: dict[int, list[TimelineEvent]] = defaultdict(list)
        for e in evs:
            seaux[_bucket_of(e.ts, bucket_s)].append(e)

        base = _baseline([len(v) for v in seaux.values()])
        seuil = max(float(min_lines), ratio * base)
        chauds = sorted(b for b, v in seaux.items() if len(v) >= seuil)

        # Facteur de mise a la minute : les seuils se raisonnent en
        # lignes/minute quelle que soit la taille du seau choisie.
        par_min = 60.0 / bucket_s
        for run in _runs(chauds, bucket_s):
            lignes = [e for b in run for e in seaux[b]]
            debut, fin = run[0], run[-1] + bucket_s
            pic = round(max(len(seaux[b]) for b in run) * par_min)
            base_min = round(base * par_min)
            # Le message le plus frequent DE LA RAFALE, pas du groupe entier :
            # c'est la ligne qui se repete qui explique la rafale. Prendre le
            # plus frequent du groupe ferait afficher le bruit de fond habituel
            # a cote d'un compte qui, lui, vient de la boucle d'erreur.
            commun = Counter((e.message.splitlines() or [""])[0]
                             for e in lignes).most_common(1)[0][0]
            sample = commun[:_SAMPLE_MAX]
            rafales.append(BurstEvent(
                ts=float(debut),
                # Fige : en 0.8.x seul l'etage syslog alimente ce module (les
                # sources evtx/auditd comptent des records, pas des lignes).
                source="syslog",
                host=host,
                category="burst",
                # 2 = "erreur" sur l'echelle du projet : une rafale merite
                # d'etre lue avant les infos, jamais avant un crash machine.
                severity=2,
                ident=ident,
                message=(f"{len(lignes)} lines in {fin - debut:.0f} s "
                         f"(peak {pic}/min, baseline {base_min}/min): {sample}"),
                # Un seul evenement mal date suffit a rendre TOUTE la rafale
                # approximative : le `and` est le choix prudent, il fait
                # afficher « ~ » plutot qu'une minute qu'on ne tient pas.
                tz_known=all(e.tz_known for e in lignes),
                end=float(fin),
                lines=len(lignes),
                peak_per_min=pic,
                baseline_per_min=base_min,
                sample=sample,
            ))

    rafales.sort(key=lambda e: (e.ts, e.host, e.ident))
    return rafales
