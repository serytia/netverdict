"""Comparaison de deux captures du MEME trafic, prises en deux points (v2).

LA QUESTION A LAQUELLE CE MODULE REPOND
---------------------------------------
Une capture d'un seul cote dit « il y a de la perte ». Elle ne dit pas OU.
Deux captures simultanees, une pres du client et une pres du serveur, le
disent : un segment present dans la premiere et absent de la seconde s'est
perdu ENTRE les deux points de capture. S'il est present des deux cotes, le
reseau intermediaire est hors de cause et le probleme est au-dela du second
point (pile, application, ou plus loin sur le chemin).

C'est le seul moyen de trancher « c'est le reseau » sans supposition — et
c'est precisement le geste que la remediation AMBIGU de cet outil
recommande depuis la v1.

LES DEUX PIEGES, ET COMMENT ILS SONT TRAITES
--------------------------------------------
1. LES HORLOGES NE SONT PAS SYNCHRONISEES. Deux machines derivent, parfois
   de plusieurs secondes. Soustraire betement les horodatages produit des
   latences absurdes (negatives, ou en heures) presentees avec aplomb. On
   estime donc le decalage par la methode NTP appliquee au handshake (voir
   estimer_horloges), et on REFUSE de donner une latence quand on n'a pas pu
   l'estimer, plutot que d'en inventer une.

2. LE NAT REECRIT LES ADRESSES. Si un equipement traduit entre les deux
   points, aucun flux ne s'apparie par quadruplet. On le DETECTE (zero flux
   commun alors que les deux captures ont du trafic) et on le dit, au lieu
   de rendre un rapport vide qui ressemble a « rien a signaler ».
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import dpkt

from .flows import build_flows
from .i18n import DEFAULT_LANG, t
from .pcap import read_capture

# Un segment est identifie par ce qui survit au transport de bout en bout :
# le numero de sequence, la taille utile et les drapeaux de controle. Ni
# l'IP-ID (reecrit par certains equipements) ni le TTL (decremente par
# construction) ne peuvent servir.
_FLAGS_SIGNIFIANTS = (dpkt.tcp.TH_SYN | dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST
                      | dpkt.tcp.TH_PUSH)


@dataclass(frozen=True)
class CleFlux:
    """Quadruplet oriente client -> serveur."""
    client: str
    cport: int
    server: str
    sport: int

    def __str__(self) -> str:
        return f"{self.client}:{self.cport} -> {self.server}:{self.sport}"


@dataclass
class Ecart:
    """Ce qu'un sens de circulation a montre entre les deux points."""

    sens: str                       # "client->serveur" | "serveur->client"
    segments_amont: int             # vus au point AMONT (l'emetteur)
    segments_aval: int              # retrouves au point AVAL
    perdus: int                     # vus en amont, jamais en aval
    latence_ms: Optional[float] = None      # mediane, si horloges estimees

    @property
    def taux_perte(self) -> float:
        return self.perdus / self.segments_amont if self.segments_amont else 0.0


@dataclass
class ComparaisonFlux:
    cle: CleFlux
    offset_horloge_s: Optional[float]        # a retrancher aux ts du point B
    latence_reseau_ms: Optional[float]       # estimee au handshake
    ecarts: list[Ecart] = field(default_factory=list)
    note: str = ""

    def verdict(self, lang: str = DEFAULT_LANG) -> tuple[str, str]:
        """(verdict, phrase) — le meme vocabulaire que le moteur de regles.

        Le JETON de verdict ne suit PAS la langue (identifiant, comme dans le
        moteur de regles) ; seule la phrase est traduite.

        On ne rend un verdict RESEAU que sur une perte MESUREE entre les deux
        points. Sans perte observee, on ne conclut pas « tout va bien » : on
        dit que le segment observe est hors de cause, ce qui est different.
        """
        perdus = sum(e.perdus for e in self.ecarts)
        amont = sum(e.segments_amont for e in self.ecarts)
        if not amont:
            return ("AMBIGU", t("compare.verdict_ambigu", lang))
        if perdus:
            detail = ", ".join(
                t("compare.verdict_reseau_detail", lang, sens=e.sens,
                  perdus=e.perdus, amont=e.segments_amont)
                for e in self.ecarts if e.perdus)
            return ("RESEAU", t("compare.verdict_reseau", lang, detail=detail))
        return ("RAS", t("compare.verdict_ras", lang, n=amont))


def _index_segments(flux) -> dict[tuple, list[float]]:
    """{(sens, seq, taille, drapeaux) -> [horodatages]} pour un flux.

    Une liste et non un instant : une retransmission produit la meme cle, et
    leur NOMBRE de chaque cote est justement l'information utile.
    """
    index: dict[tuple, list[float]] = {}
    for op in flux.pkts:
        p = op.pkt
        cle = ("c2s" if op.from_client else "s2c", p.seq, p.payload_len,
               p.flags & _FLAGS_SIGNIFIANTS)
        index.setdefault(cle, []).append(p.ts)
    return index


def estimer_horloges(idx_a: dict[tuple, list[float]],
                     idx_b: dict[tuple, list[float]],
                     ) -> tuple[Optional[float], Optional[float]]:
    """(offset, latence_ms) entre deux points, par la methode NTP.

    Le handshake donne deux traversees en sens opposes : le SYN va de A vers
    B, le SYN/ACK de B vers A. En notant o le decalage d'horloge (B - A) et
    en supposant la latence symetrique L :

        tB(SYN)    - tA(SYN)    =  L + o
        tA(SYNACK) - tB(SYNACK) =  L - o

    d'ou o = [(tB_syn - tA_syn) - (tA_sa - tB_sa)] / 2
    et   L = [(tB_syn - tA_syn) + (tA_sa - tB_sa)] / 2

    L'HYPOTHESE DE SYMETRIE EST FAUSSE en general (routage asymetrique,
    liens satellite, QoS differenciee) : l'offset est donc une ESTIMATION,
    et une latence negative — signature d'une asymetrie forte — est
    retournee telle quelle plutot que corrigee en douce, pour que l'appelant
    puisse la signaler.

    UNE REFERENCE DOIT ETRE UNIQUE DES DEUX COTES. Un segment RETRANSMIS
    porte la meme cle que son original : apparier « le premier de A » avec
    « le premier de B » revient alors a comparer l'original avec la
    retransmission, et le RTO entier (~1 s) est compte comme de la latence.
    Constate au lab le 26/07 : le SYN initial jete par le simulateur de perte
    a produit une latence annoncee de 511 ms sur un lien local — un chiffre
    faux, presente avec aplomb. On n'accepte donc comme reference qu'un
    segment vu EXACTEMENT UNE FOIS de chaque cote, et on cherche au-dela du
    handshake si celui-ci a ete retransmis.

    Retourne (None, None) si aucun couple de references propres n'existe :
    sans reference commune, deviner serait pire que se taire.
    """
    def _references(sens: str):
        """Segments de ce sens, vus une seule fois des deux cotes, du plus
        ancien au plus recent (le plus tot limite la derive d'horloge)."""
        candidats = [c for c, ts in idx_a.items()
                     if c[0] == sens and len(ts) == 1
                     and len(idx_b.get(c, ())) == 1
                     # Un RST n'est pas une reference : il peut etre emis
                     # par un tiers sur le chemin (firewall) et n'aura donc
                     # pas traverse les deux points.
                     and not c[3] & dpkt.tcp.TH_RST]
        return sorted(candidats, key=lambda c: idx_a[c][0])

    aller_refs = _references("c2s")
    retour_refs = _references("s2c")
    if not aller_refs or not retour_refs:
        return (None, None)
    ref_aller, ref_retour = aller_refs[0], retour_refs[0]
    ta_syn, tb_syn = idx_a[ref_aller][0], idx_b[ref_aller][0]
    ta_sa, tb_sa = idx_a[ref_retour][0], idx_b[ref_retour][0]
    aller = tb_syn - ta_syn
    retour = ta_sa - tb_sa
    offset = (aller - retour) / 2.0
    latence_ms = (aller + retour) / 2.0 * 1000.0
    return (offset, latence_ms)


def comparer(chemin_a: str | Path, chemin_b: str | Path,
             lang: str = DEFAULT_LANG) -> tuple[list[ComparaisonFlux], dict]:
    """Compare deux captures du meme trafic. A = point AMONT (cote client).

    Retourne (comparaisons, diagnostic) ou diagnostic porte ce qui concerne
    les fichiers eux-memes (flux communs, suspicion de NAT...).
    """
    cap_a = read_capture(chemin_a, lang)
    cap_b = read_capture(chemin_b, lang)
    flux_a = {CleFlux(f.client, f.cport, f.server, f.sport): f
              for f in build_flows(cap_a)}
    flux_b = {CleFlux(f.client, f.cport, f.server, f.sport): f
              for f in build_flows(cap_b)}

    communs = sorted(set(flux_a) & set(flux_b), key=str)
    diagnostic = {
        "flux_a": len(flux_a), "flux_b": len(flux_b),
        "flux_communs": len(communs),
        # Deux captures pleines de trafic sans AUCUN flux commun : soit un
        # NAT reecrit les adresses entre les deux points, soit les captures
        # ne portent pas sur le meme trafic. Dans les deux cas, un rapport
        # vide serait lu comme « rien a signaler » — on le dit.
        "nat_probable": bool(flux_a and flux_b and not communs),
    }

    resultats: list[ComparaisonFlux] = []
    for cle in communs:
        idx_a = _index_segments(flux_a[cle])
        idx_b = _index_segments(flux_b[cle])
        offset, latence = estimer_horloges(idx_a, idx_b)

        comp = ComparaisonFlux(cle=cle, offset_horloge_s=offset,
                               latence_reseau_ms=latence)
        if offset is None:
            comp.note = t("compare.note_no_handshake", lang)
        elif latence is not None and latence < 0:
            comp.note = t("compare.note_negative_latency", lang)

        for sens, libelle in (("c2s", t("compare.dir_c2s", lang)),
                              ("s2c", t("compare.dir_s2c", lang))):
            # Chaque sens est mesure depuis SON emetteur : les paquets
            # client->serveur sont vus en premier par A, et inversement.
            amont, aval = (idx_a, idx_b) if sens == "c2s" else (idx_b, idx_a)
            envoyes = retrouves = 0
            for c, ts in amont.items():
                if c[0] != sens:
                    continue
                envoyes += len(ts)
                retrouves += min(len(ts), len(aval.get(c, ())))
            if envoyes:
                comp.ecarts.append(Ecart(sens=libelle, segments_amont=envoyes,
                                         segments_aval=retrouves,
                                         perdus=envoyes - retrouves))
        resultats.append(comp)
    return resultats, diagnostic
