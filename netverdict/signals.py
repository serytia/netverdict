"""Calcule les signaux TCP par flux : des FAITS mesures, zero jugement.

C'est le coeur technique de l'outil : la reimplementation du sous-ensemble
d'analyse TCP dont le triage a besoin (ce que tshark appelle tcp.analysis.*).
Les seuils et les verdicts vivent dans les regles YAML, pas ici — meme
separation parse/judge que decoders/rules dans un pack Wazuh.

Chaque champ de FlowSignals est adressable par les regles : c'est une API,
les noms sont stables et courts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .flows import Flow

# --- Arithmetique de numeros de sequence (modulo 2^32) -----------------------
# Une capture qui traverse le wrap (toutes les ~4 Go transferes) casse les
# comparaisons naives ; l'arithmetique signee modulaire est la forme standard.

_MOD = 1 << 32
_HALF = 1 << 31


def seq_le(a: int, b: int) -> bool:
    """a <= b au sens TCP (fenetre de comparaison de 2 Go)."""
    return ((b - a) & (_MOD - 1)) < _HALF


def seq_add(a: int, n: int) -> int:
    return (a + n) & (_MOD - 1)


def _pctl(samples: list[float], q: float) -> Optional[float]:
    if not samples:
        return None
    s = sorted(samples)
    idx = min(len(s) - 1, max(0, round(q * (len(s) - 1))))
    return s[idx]


# Keepalive TCP : segment de 0 ou 1 octet emis a snd_nxt-1. Periodique par
# nature, il matcherait le detecteur de retransmission a chaque emission et
# fabriquerait de la fausse perte sur toute session longue et calme.
_KEEPALIVE_MAX_LEN = 1

# Un segment qui n'avance pas la fenetre mais arrive dans cette fenetre
# apres le dernier octet le plus haut est du REORDONNANCEMENT de capture,
# pas une retransmission (meme heuristique que Wireshark).
_OOO_WINDOW_S = 0.003

# Frontiere des deux familles de latence, mesuree sur les pcaps du lab : tous
# les flux sains y plafonnent a 1,41 ms de p95, tous les flux netem degrades
# demarrent a 29 ms. Meme valeur que les seuils absolus des regles — un
# echantillon au-dessus est un echantillon qui pese sur un verdict.
_LATENCE_HAUTE_MS = 20.0

# Denominateur plancher des rapports de latence. Sur un LAN le minimum est
# sub-microseconde : diviser par lui fabrique des « x46398 » a cinq chiffres
# significatifs a partir de deux mesures dont l'une est sous la resolution
# utile. Meme plancher, meme raison que pour rtt_ratio_p95_p50.
_RATIO_PLANCHER_MS = 1.0

# Une fenetre de reception est dite EFFONDREE quand elle tombe au quart ou
# moins du maximum que ce meme cote a annonce dans la capture. La mesure est
# RELATIVE parce que p.win est le champ brut : sans l'option window scale du
# SYN (souvent hors capture, toujours hors de portee d'une capture demarree en
# cours de session), 502 peut valoir 502 ou 64 ko. Le RAPPORT d'un cote a
# lui-meme, lui, ne depend pas de l'echelle.
_FENETRE_EFFONDREE_FRACTION = 4


@dataclass
class FlowSignals:
    # Identite / contexte
    client: str = ""
    server: str = ""
    cport: int = 0
    sport: int = 0
    direction_confident: bool = True
    started_midstream: bool = False
    t_first: float = 0.0             # epoch du premier paquet du flux
    duration_s: float = 0.0
    pkts_total: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    data_pkts_c2s: int = 0
    data_pkts_s2c: int = 0

    # Handshake
    syn_count: int = 0
    synack_seen: bool = False
    handshake_complete: bool = False
    # La capture PROUVE que le serveur a accepte la connexion, meme quand le
    # SYN/ACK ne s'y trouve pas (chemin de retour asymetrique, tap sur un seul
    # brin, capture demarree une fraction de seconde trop tard). Trois preuves,
    # chacune un acte POSITIF du serveur : le SYN/ACK vu, des donnees serveur,
    # ou un ACK du serveur couvrant des octets applicatifs du client — on
    # n'acquitte pas 400 octets sur un port ou personne n'ecoute.
    # Distinct de handshake_complete, qui exige d'avoir VU les trois paquets :
    # sans ce champ, un RST tardif sur une telle session sortait « rien
    # n'ecoute sur ce port », APP, confiance haute (durcissement du 08/08/2026).
    established_seen: bool = False
    handshake_rtt_ms: Optional[float] = None
    syn_span_s: float = 0.0          # etalement des SYN retransmis
    rst_to_syn: bool = False         # RST en reponse directe au SYN
    rst_to_syn_ms: Optional[float] = None

    # Perte / retransmissions
    retrans_c2s: int = 0
    retrans_s2c: int = 0
    retrans_total: int = 0
    retrans_rate: float = 0.0        # retrans / (data pkts + retrans)
    # DENOMINATEUR EXACT de retrans_rate. La preuve affichait « {retrans_total}
    # retransmissions sur {pkts_total} paquets ({retrans_rate:.1%}) » : trois
    # nombres dont les deux premiers ne donnent pas le troisieme (73 sur 1532 =
    # 4,8 %, pas les 8,2 % affiches). Un admin verifie ce calcul avant de
    # recopier le taux dans un ticket (durcissement du 08/08/2026).
    retrans_base: int = 0
    dup_ack_bursts_from_client: int = 0   # le RECEPTEUR emet les dup acks
    dup_ack_bursts_from_server: int = 0
    # EPISODES de perte, et non segments perdus. Une seule file qui deborde
    # emporte toute la fenetre en vol : sept segments repartis ensemble au RTO
    # sont UNE mesure du chemin, pas sept. Le plancher « retrans_total >= 5 »
    # voulait deja ecarter « une perte isolee » (son commentaire le dit) mais
    # comptait des segments — donc laissait passer, en RESEAU/confiance haute,
    # un taux a la decimale tire d'un unique hoquet (durcissement du
    # 08/08/2026). Un episode se ferme des que l'emetteur reprend sa
    # progression : des renvois separes par des donnees NEUVES sont des
    # evenements distincts.
    retrans_events: int = 0
    perte_evenement_unique: bool = False
    # LA CAPTURE MONTRE-T-ELLE QUE LA SESSION S'EN EST REMISE ? Vrai seulement
    # si, APRES le dernier renvoi de chaque sens qui a retransmis, le pair a
    # acquitte des octets qu'il n'avait pas encore acquittes a cet instant : le
    # flux a AVANCE. Emettre a nouveau ne prouve rien — c'est l'acquittement qui
    # prouve, et c'est le seul fait qui separe un hoquet dont TCP est sorti d'un
    # chemin ou plus rien ne passe. Sans ce champ,
    # perte_evenement_unique se contentait de compter UN episode, et un episode
    # qui ne se referme jamais (renvois en backoff RTO jusqu'a la fin de la
    # capture, trou noir de MTU) en est un : l'outil rendait alors
    # perte-rafale-unique, « la session s'en est remise », confiance faible, sur
    # un chemin MORT (revue adverse du 08/08/2026).
    reprise_apres_perte: bool = False
    # Le MEME segment renvoye N fois, l'etalement de ces renvois, et le fait que
    # le pair ne les ait jamais acquittes : la signature du backoff RTO. Elle
    # separe un fast retransmit (memes octets, quelques ms, acquittes juste
    # apres) d'un emetteur qui parle dans le vide pendant des dizaines de
    # secondes.
    retrans_meme_segment_max: int = 0
    retrans_meme_segment_span_s: float = 0.0
    retrans_meme_segment_jamais_acquitte: bool = False
    # Retransmissions dont le recepteur avait DEJA acquitte les octets au
    # moment du renvoi. La capture prouve alors que le sens aller a livre : la
    # perte, s'il y en a une, est sur le chemin de RETOUR (acquittement perdu,
    # routage asymetrique) ou n'existe pas (RTO trop court apres un pic de
    # latence, timeout spurieux RFC 3522). Sans ce compte, la remediation fait
    # lire le sens des retransmissions comme l'endroit de la perte, et designe
    # le mauvais cote du reseau.
    retrans_deja_acquittees: int = 0

    # Latence
    rtt_ms_min: Optional[float] = None
    rtt_ms_p50: Optional[float] = None
    rtt_ms_p95: Optional[float] = None
    # Nombre d'echantillons de RTT. La preuve annoncait « sur {pkts_total}
    # paquets » : un flux de 25 paquets peut ne porter que 4 mesures, et c'est
    # le cas de tous les flux du lab. Le nombre de mesures est ce qui dit ce
    # que vaut le percentile affiche.
    rtt_samples: int = 0
    # VRAI quand toutes les mesures au-dessus de 20 ms sont portees par des ACK
    # PURS — un acquittement qui ne transporte aucun octet. C'est la signature
    # du delayed ACK : le recepteur n'avait rien a repondre, sa pile a arme un
    # timer (40 ms sous Linux, jusqu'a 200 ms sous Windows) et le chemin n'y est
    # pour rien. Une gigue reelle, elle, retarde AUSSI les segments de donnees —
    # verifie flux par flux sur jitter.pcap (netem, vrai kernel), ou chaque flux
    # degrade a au moins une mesure haute portee par des donnees.
    # Sans ce champ, un simple abonnement (MQTT, tail de logs, flux de
    # cotations) sur un LAN a 0,4 ms sortait « Latence instable : gigue forte
    # (congestion probable) », RESEAU — et la meme ligne s'imprimait sous le
    # verdict HOTE de zero_window.pcap, la capture de validation de l'outil
    # (durcissement du 08/08/2026).
    rtt_haut_porte_par_ack_purs: bool = False
    # LA PLUS GRANDE des mesures hautes. « Porte par des ACK purs » n'a aucune
    # borne de grandeur : un delayed ACK est un TIMER — 40 ms sous Linux,
    # jusqu'a 200 ms sous Windows — et rien dans une pile TCP ne retient un
    # acquittement une seconde. Au-dela, la duree ne peut plus venir du timer,
    # elle vient du chemin ; l'inhibition doit s'arreter la (revue adverse du
    # 08/08/2026).
    rtt_haut_max_ms: Optional[float] = None
    # Chaque mesure haute acquittait-elle un segment SEUL en vol ? C'est la
    # condition d'existence du delayed ACK : la RFC 1122 impose au recepteur
    # d'acquitter immediatement des qu'il a deux segments pleins non acquittes.
    # Un acquittement qui en couvre deux ou plus n'a donc PAS attendu un timer.
    #
    # Sans ce champ, « toutes les mesures hautes sont des ACK purs » etait vrai
    # de TOUT transfert unidirectionnel — un telechargement, une sauvegarde, un
    # upload : le recepteur n'a jamais rien a piggybacker, donc ses ACK sont
    # tous purs, par construction et non par choix. L'inhibition s'armait sur
    # 100 % des telechargements et une congestion reelle ressortait « transport
    # sain », confiance haute (revue adverse du 08/08/2026).
    rtt_haut_sur_segment_isole: bool = False
    # AUTRE explication mesurable du meme plateau, et elle n'a rien d'un
    # timer : sur chacune des mesures hautes, le recepteur annoncait une
    # fenetre effondree (au quart ou moins de son propre maximum, voir
    # _FENETRE_EFFONDREE_FRACTION). Un recepteur dont le tampon est plein ne
    # peut pas acquitter ce qu'il ne peut pas accepter — le delai mesure est
    # celui de son application, pas celui du chemin. C'est ce que montre
    # zero_window.pcap, la capture de validation de l'outil : la fenetre du
    # serveur descend de 8688 a 1448 puis a 0, et les « 44 ms de RTT » sont sa
    # saturation, pas de la gigue.
    rtt_haut_sous_fenetre_saturee: bool = False
    # Dispersion p95/min : mesure de gigue SANS baseline externe — la
    # reference est le meilleur RTT observe dans la capture elle-meme.
    rtt_ratio_p95_min: Optional[float] = None

    # Dispersion du RTT sur la MEDIANE et non le p95. Le p95 est pollue par les
    # delayed ACK (~40-200 ms) : sur un flux applicatif lent, une poignee
    # d'echantillons suffisait a faire conclure « latence instable » et a rendre
    # un verdict RESEAU sur un probleme purement applicatif. La mediane resiste
    # a ces valeurs isolees — le README declare deja min et p50 fiables.
    rtt_ratio_p50_min: Optional[float] = None

    # FORME DE LA QUEUE : p95 rapporte a la MEDIANE, et non au minimum. Repond a
    # « la latence a-t-elle des pics ? » alors que les deux ratios ci-dessus
    # repondent « la latence s'ecarte-t-elle du meilleur cas ? » — question a
    # laquelle un LAN repond toujours oui (minimum sub-milliseconde).
    # Distingue un WAN stable a 80 ms (p95/p50 ~ 1) d'un lien qui pique
    # (p95/p50 de 400 mesure sur un flux netem du lab). Sans lui, aucune regle
    # ne pouvait separer les deux, et un flux a p50 15 ms / p95 400 ms sortait
    # « transport sain » (mesure du 25/07/2026).
    rtt_ratio_p95_p50: Optional[float] = None
    # Combien de fois la reponse applicative est plus lente que l'acquittement
    # TCP de la requete. C'EST la preuve que le delai est dans le serveur, et
    # elle ne depend pas d'un seuil absolu : un ACK a 60 ms face a une reponse
    # a 900 ms prouve exactement la meme chose qu'un ACK a 5 ms face a 500 ms.
    ttfb_over_ack_ratio: Optional[float] = None

    # Zero window (recepteur sature : l'app ne lit pas sa socket)
    zw_from_client: int = 0
    zw_from_server: int = 0
    # Agregats des DEUX sens : vue d'ensemble seulement. Une regle qui accuse
    # un hote PRECIS ne doit jamais s'en servir — voir les champs par sens.
    zw_max_ms: float = 0.0
    zw_total_ms: float = 0.0
    # Durees PAR SENS. Sans elles, quand client ET serveur annoncent du
    # zero-window, zero-window-server s'attribuait la duree du CLIENT et
    # accusait le mauvais hote avec une preuve fausse (revue du 25/07/2026).
    zw_max_ms_from_client: float = 0.0
    zw_total_ms_from_client: float = 0.0
    zw_max_ms_from_server: float = 0.0
    zw_total_ms_from_server: float = 0.0
    # POSITION TEMPORELLE de la fenetre fermee du client, rapportee a ce qu'elle
    # est censee expliquer : l'attente d'une reponse. Les champs ci-dessus ne
    # portent que des DUREES — combien de temps la fenetre est restee fermee,
    # jamais QUAND. Une regle qui s'en sert pour retirer un verdict applicatif
    # affirme que la fenetre fermee explique le delai, ce qu'un maximum de
    # durees ne peut pas dire : un hoquet de 150 ms survenu entre deux requetes,
    # ou pendant que le serveur travaillait deja depuis 800 ms, n'explique rien
    # du tout (revue adverse du 08/08/2026).
    #
    #   attente_totale_ms          : somme des attentes requete -> reponse
    #                                (le denominateur du TTFB, en clair)
    #   zw_client_attente_ms       : part de ces attentes RECOUVERTE par une
    #                                fenetre fermee annoncee par le client
    #   zw_client_part_attente     : le rapport des deux, 0 a 1
    attente_totale_ms: float = 0.0
    zw_client_attente_ms: float = 0.0
    zw_client_part_attente: Optional[float] = None

    # Comportement applicatif
    exchanges: int = 0
    ttfb_ms_p50: Optional[float] = None
    ttfb_ms_p95: Optional[float] = None
    ttfb_ms_max: Optional[float] = None
    # Delai entre la fin de la requete et l'ACK PUR du serveur : si l'ACK est
    # rapide mais la reponse lente, la pile TCP serveur a recu — c'est l'app
    # qui traine. Signal discriminant n°1 du verdict APPLICATIF.
    server_ack_delay_ms_p95: Optional[float] = None

    # Cloture
    closed_by: str = "none"          # fin | rst_client | rst_server | none
    rst_midstream: bool = False
    rst_emitter: str = ""            # IP de l'emetteur du RST (pour la preuve)

    # ICMP rattache
    icmp_admin_prohibited: bool = False
    icmp_admin_prohibited_from: Optional[str] = None
    icmp_frag_needed: bool = False
    icmp_unreach_count: int = 0
    # Plus gros segment de donnees emis par le cote FAUTIF, avant et apres le
    # premier 'fragmentation needed'. C'est la mesure qui separe les deux
    # situations que l'ICMP seul confond :
    #   - l'emetteur REDUIT son calibre (1460 -> 1400) : la decouverte de MTU a
    #     fonctionne, le transfert passe, il n'y a rien a corriger en urgence ;
    #   - il continue au meme calibre : rien ne passera jamais, c'est le trou
    #     noir, et le clamp de MSS est le bon geste.
    # Sans elle, un site derriere un tunnel voyait TOUS ses flux sortir
    # « RESEAU, confiance haute, priorite 86 » (durcissement du 08/08/2026).
    seg_max_before_frag_needed: int = 0
    seg_max_after_frag_needed: int = 0
    # ... et la PREUVE que le calibre reduit passe : le pair a acquitte les
    # octets emis apres l'erreur. Reduire n'est pas livrer. Un emetteur qui
    # descend de 1460 a 1400 derriere un lien a 1300 a « honore » l'ICMP et
    # reste dans le trou noir ; l'outil rendait alors « MTU reduite absorbee par
    # la decouverte automatique — RIEN A CORRIGER SUR CE FLUX » et affichait
    # « la session a poursuivi » sur une session qui n'a plus rien livre du tout
    # (revue adverse du 08/08/2026).
    progres_apres_frag_needed: bool = False
    # Vrai tant que la capture ne PROUVE pas la reduction : meme calibre apres,
    # ou plus rien d'emis du tout. Le doute profite au diagnostic de panne —
    # ne pas voir l'emetteur s'adapter n'est pas le voir s'adapter.
    frag_needed_ignored: bool = False

    # Divers
    dup_capture_skipped: int = 0

    def as_dict(self) -> dict:
        from dataclasses import asdict
        return asdict(self)


def _add_zw(sig: "FlowSignals", from_client: bool, dur_ms: float) -> None:
    """Comptabilise une periode de fenetre fermee, dans l'agregat ET dans le
    sens qui l'a annoncee. Le zero-window est emis par le RECEPTEUR : c'est
    donc lui qui ne lit pas sa socket, et c'est lui qu'une regle doit accuser.
    """
    sig.zw_total_ms += dur_ms
    sig.zw_max_ms = max(sig.zw_max_ms, dur_ms)
    if from_client:
        sig.zw_total_ms_from_client += dur_ms
        sig.zw_max_ms_from_client = max(sig.zw_max_ms_from_client, dur_ms)
    else:
        sig.zw_total_ms_from_server += dur_ms
        sig.zw_max_ms_from_server = max(sig.zw_max_ms_from_server, dur_ms)


def compute_signals(fl: Flow) -> FlowSignals:
    sig = FlowSignals(client=fl.client, server=fl.server,
                      cport=fl.cport, sport=fl.sport,
                      direction_confident=fl.direction_confident,
                      dup_capture_skipped=fl.dup_capture_skipped)
    pkts = fl.pkts
    if not pkts:
        return sig

    sig.pkts_total = len(pkts)
    sig.t_first = pkts[0].pkt.ts
    sig.duration_s = pkts[-1].pkt.ts - pkts[0].pkt.ts
    first = pkts[0].pkt
    sig.started_midstream = not (first.syn)

    rtt_vals: list[float] = []
    # Trois listes de meme longueur que rtt_vals, decrivant l'ACQUITTEMENT qui a
    # produit chaque mesure : etait-il un ACK PUR (aucun octet transporte),
    # couvrait-il un segment SEUL en vol, et le cote qui l'a emis annoncait-il
    # une fenetre effondree ? Voir les champs rtt_haut_* de FlowSignals : ce
    # sont ces trois faits, et non le seul « ACK pur », qui disent si le plateau
    # de latence a une explication autre que le chemin.
    rtt_ack_pur: list[bool] = []
    rtt_segment_isole: list[bool] = []
    rtt_fenetre_effondree: list[bool] = []
    ttfb_samples: list[float] = []
    # Bornes (debut, fin) de chaque attente requete -> reponse, dans le meme
    # ordre que ttfb_samples : c'est la POSITION de l'attente, celle qu'aucun
    # champ ne portait (voir zw_client_attente_ms).
    attentes: list[tuple[float, float]] = []
    ack_delay_samples: list[float] = []

    # Fenetre maximale annoncee par chaque cote, hors SYN et RST ou le champ ne
    # veut rien dire. Sert de reference RELATIVE a « fenetre effondree » : le
    # champ brut n'est comparable qu'a lui-meme (voir
    # _FENETRE_EFFONDREE_FRACTION).
    win_max_c2s = win_max_s2c = 0
    for op in pkts:
        if op.pkt.rst or op.pkt.syn:
            continue
        if op.from_client:
            win_max_c2s = max(win_max_c2s, op.pkt.win)
        else:
            win_max_s2c = max(win_max_s2c, op.pkt.win)

    # Premier 'fragmentation needed' rattache au flux, et le sens qu'il vise :
    # l'ICMP cite le paquet fautif, donc son emetteur est celui dont il faut
    # surveiller la taille des segments. Lu AVANT la boucle parce que la mesure
    # se fait pendant (voir seg_max_*_frag_needed).
    frag_ts: Optional[float] = None
    frag_from_client = True
    for ev in fl.icmp:
        if ev.is_frag_needed and (frag_ts is None or ev.ts < frag_ts):
            frag_ts = ev.ts
            frag_from_client = (ev.orig_src == fl.client)
    seg_max_before_frag = 0
    seg_max_after_frag = 0
    # Fin de sequence de la PREMIERE emission du cote fautif apres l'erreur :
    # si le pair finit par l'acquitter, la capture prouve que le calibre reduit
    # passe (voir progres_apres_frag_needed).
    premier_seq_end_apres_frag: Optional[int] = None

    # Etat handshake
    syn_times: list[float] = []
    synack_times: list[float] = []

    # Etat retrans/rtt par sens. La detection de retransmission suit la
    # FENETRE (max_seq_end), pas l'identite (seq,len) des segments : avec
    # TSO/GSO l'original part en mega-segment et la retransmission revient
    # re-decoupee en segments MSS — une comparaison exacte ne revoit jamais
    # le meme couple et rate 100 % des pertes (constate sur capture kernel
    # au lab, 2026-07-24). Regle : un segment de donnees qui n'avance pas
    # max_seq_end transporte des octets deja emis -> retransmission, sauf
    # arrivee dans la fenetre de reordonnancement (_OOO_WINDOW_S).
    class _Dir:
        def __init__(self):
            self.pending: dict[int, float] = {}      # seq_end -> ts (RTT)
            self.max_seq_end: Optional[int] = None
            self.t_max_seq: float = 0.0              # ts du plus haut octet emis
            # Le pair a-t-il deja reclame une retransmission par dup-ACK ?
            # Passe a True des la 3e dup-ACK du sens oppose : ensuite, un
            # renvoi rapide de CE sens est un fast retransmit, pas un
            # reordonnancement de capture.
            self.dup_ack_reclame: bool = False
            self.last_ack: Optional[int] = None
            self.last_win: Optional[int] = None
            self.dup_run = 0
            self.zw_open_ts: Optional[float] = None
            self.fin_ts: Optional[float] = None
            # Plus haut acquittement EMIS par ce sens. Sert au sens oppose :
            # une retransmission dont les octets sont deja couverts par cette
            # valeur porte des donnees dont la capture prouve l'arrivee.
            self.ack_max: Optional[int] = None
            # Un episode de perte est-il en cours dans ce sens ? Il s'ouvre a
            # la premiere retransmission et se referme des que ce sens emet a
            # nouveau des donnees NEUVES (voir retrans_events).
            self.retrans_open: bool = False
            # Zone de recouvrement (debut, fin) de chaque periode de fenetre
            # fermee annoncee par ce sens.
            self.zw_periods: list[tuple[float, float]] = []
            # Renvois du MEME segment : seq_end -> horodatages. Signature du
            # backoff RTO (voir retrans_meme_segment_max).
            self.retrans_par_seq: dict[int, list[float]] = {}
            # PREUVE DE REPRISE. A chaque retransmission de CE sens on note ou
            # en etait l'acquittement du pair ; la reprise n'est acquise que
            # lorsqu'un acquittement ulterieur DEPASSE ce point. Reemettre ne
            # prouve rien, seul l'acquittement prouve (reprise_apres_perte).
            # `repere_pose` distingue « aucun renvoi » de « renvoi alors que le
            # pair n'avait encore rien acquitte » (repere a None).
            self.repere_pose: bool = False
            self.repere_reprise: Optional[int] = None
            self.reprise: bool = False

    c2s, s2c = _Dir(), _Dir()

    # Machine a etats requete/reponse pour le TTFB applicatif.
    talk_state: Optional[str] = None   # None | "client" | "server"
    last_c2s_data_ts: Optional[float] = None
    last_c2s_seq_end: Optional[int] = None
    block_ack_measured = False

    data_bidir_seen_c2s = False
    data_bidir_seen_s2c = False
    # Voir FlowSignals.established_seen. Variable locale parce qu'elle doit
    # etre lue AVANT la fin du parcours : c'est elle qui decide si un RST est
    # une reponse au SYN ou l'assassinat d'une session vivante.
    established_seen = False
    first_c2s_seq_end: Optional[int] = None
    rst_info: Optional[tuple[bool, float, bool]] = None  # (from_client, ts, data_before)

    for op in pkts:
        p = op.pkt
        me, other = (c2s, s2c) if op.from_client else (s2c, c2s)

        # ---- Handshake -------------------------------------------------------
        if p.syn and not p.ack_flag and op.from_client:
            syn_times.append(p.ts)
        if p.syn and p.ack_flag and not op.from_client:
            synack_times.append(p.ts)
            sig.synack_seen = True
            established_seen = True
            # RTT du handshake : dernier SYN emis avant ce SYN/ACK.
            prev_syns = [t for t in syn_times if t <= p.ts]
            if prev_syns and sig.handshake_rtt_ms is None:
                sig.handshake_rtt_ms = (p.ts - prev_syns[-1]) * 1000.0
                rtt_vals.append(sig.handshake_rtt_ms)
                # Un SYN/ACK n'est pas un ACK pur : aucun timer de delayed ACK
                # ne le retarde, c'est une mesure franche du chemin. Le SYN
                # etait bien seul en vol ; la fenetre annoncee dans un SYN/ACK
                # n'est pas comparable aux suivantes (l'echelle ne s'applique
                # pas encore), on ne la declare donc jamais effondree. Les
                # quatre listes avancent ENSEMBLE — un zip() tronque a la plus
                # courte perdrait silencieusement la derniere mesure.
                rtt_ack_pur.append(False)
                rtt_segment_isole.append(True)
                rtt_fenetre_effondree.append(False)
        # « RST en reponse au SYN » ne se lit QUE sur une connexion dont rien
        # ne prouve qu'elle a vecu. Sans le garde `established_seen`, un RST
        # tombant 31 s apres le SYN sur une session dont le serveur avait
        # acquitte 400 octets sortait « rien n'ecoute sur ce port » — et la
        # preuve imprimee, « RST recu 31000.0 ms apres le SYN », se contredisait
        # elle-meme (durcissement du 08/08/2026).
        if p.rst and not op.from_client and syn_times and not sig.synack_seen \
                and not data_bidir_seen_s2c and not established_seen:
            sig.rst_to_syn = True
            if sig.rst_to_syn_ms is None:
                sig.rst_to_syn_ms = (p.ts - syn_times[-1]) * 1000.0

        # ---- Zero window -----------------------------------------------------
        # win==0 annonce est un zero window quel que soit le window scale
        # (0 * 2^n = 0) ; on exclut RST/SYN ou la fenetre n'a pas de sens.
        if not p.rst and not p.syn:
            if p.win == 0:
                if op.from_client:
                    sig.zw_from_client += 1
                else:
                    sig.zw_from_server += 1
                if me.zw_open_ts is None:
                    me.zw_open_ts = p.ts
            elif me.zw_open_ts is not None:
                _add_zw(sig, op.from_client, (p.ts - me.zw_open_ts) * 1000.0)
                me.zw_periods.append((me.zw_open_ts, p.ts))
                me.zw_open_ts = None

        # ---- Donnees : retransmissions, RTT, volumes, TTFB -------------------
        if p.payload_len > 0:
            # Taille des segments du cote vise par le frag-needed, de part et
            # d'autre de l'erreur. Toutes les emissions comptent, y compris les
            # retransmissions : reemettre le MEME calibre est precisement le
            # symptome du trou noir.
            if frag_ts is not None and op.from_client == frag_from_client:
                if p.ts <= frag_ts:
                    seg_max_before_frag = max(seg_max_before_frag, p.payload_len)
                else:
                    seg_max_after_frag = max(seg_max_after_frag, p.payload_len)
            seq_end = seq_add(p.seq, p.payload_len)
            if (frag_ts is not None and op.from_client == frag_from_client
                    and p.ts > frag_ts and premier_seq_end_apres_frag is None):
                premier_seq_end_apres_frag = seq_end
            is_keepalive = (p.payload_len <= _KEEPALIVE_MAX_LEN
                            and me.max_seq_end is not None
                            and seq_end == me.max_seq_end)
            is_old_data = (me.max_seq_end is not None
                           and seq_le(seq_end, me.max_seq_end))
            if is_keepalive:
                pass
            elif is_old_data:
                # Retransmission si l'arrivee est hors fenetre de
                # reordonnancement, OU si le pair a deja reclame par dup-ACK :
                # dans ce second cas, un renvoi rapide est un FAST RETRANSMIT,
                # pas un paquet remis dans l'ordre par la capture.
                if ((p.ts - me.t_max_seq) >= _OOO_WINDOW_S
                        or me.dup_ack_reclame):
                    if op.from_client:
                        sig.retrans_c2s += 1
                    else:
                        sig.retrans_s2c += 1
                    # Un episode de perte par SALVE, pas par segment : tant que
                    # ce sens n'a pas repris sa progression, les renvois qui
                    # s'enchainent viennent du meme evenement.
                    if not me.retrans_open:
                        sig.retrans_events += 1
                        me.retrans_open = True
                    me.retrans_par_seq.setdefault(seq_end, []).append(p.ts)
                    # La reprise est a reprouver a chaque renvoi : elle sera
                    # acquise quand le pair acquittera au-dela d'ou il en etait
                    # A CET INSTANT — et pas avant.
                    me.repere_pose = True
                    me.repere_reprise = other.ack_max
                    me.reprise = False
                    # Le pair avait-il deja acquitte ces octets ? Alors la
                    # capture prouve qu'ils etaient arrives.
                    if (other.ack_max is not None
                            and seq_le(seq_end, other.ack_max)):
                        sig.retrans_deja_acquittees += 1
                    # Karn : tout echantillon RTT contenant des octets
                    # retransmis devient inutilisable (on ne saura pas quel
                    # exemplaire l'ACK acquitte).
                    first_retrans_byte = seq_add(p.seq, 1)
                    for se in [se for se in me.pending
                               if seq_le(first_retrans_byte, se)]:
                        me.pending.pop(se, None)
                # sinon : reordonnancement de capture, pas une perte
            else:
                if op.from_client:
                    sig.data_pkts_c2s += 1
                    sig.bytes_c2s += p.payload_len
                else:
                    sig.data_pkts_s2c += 1
                    sig.bytes_s2c += p.payload_len
                me.pending[seq_end] = p.ts
                me.max_seq_end = seq_end
                me.t_max_seq = p.ts
                # Progression reprise : l'episode de perte en cours est clos.
                # ATTENTION a ce que ce compteur dit et ne dit pas — il compte
                # des EPISODES, il ne certifie aucun retablissement. Emettre des
                # donnees neuves referme un episode ; cela ne prouve pas
                # qu'elles arrivent, et un episode qui reste ouvert jusqu'au
                # dernier paquet de la capture reste, ici, « un » episode. La
                # preuve du retablissement se prend a l'ACQUITTEMENT et nulle
                # part ailleurs : voir reprise_apres_perte.
                me.retrans_open = False

            if not is_keepalive:
                if op.from_client:
                    data_bidir_seen_c2s = True
                    if talk_state != "client":
                        talk_state = "client"
                        block_ack_measured = False
                    last_c2s_data_ts = p.ts
                    last_c2s_seq_end = seq_end
                    if first_c2s_seq_end is None:
                        first_c2s_seq_end = seq_end
                else:
                    data_bidir_seen_s2c = True
                    # Le serveur emet des donnees : une socket existe.
                    established_seen = True
                    if talk_state == "client" and last_c2s_data_ts is not None:
                        ttfb_samples.append((p.ts - last_c2s_data_ts) * 1000.0)
                        attentes.append((last_c2s_data_ts, p.ts))
                    talk_state = "server"

        # ---- ACKs : echantillons RTT, dup acks, ack-delay serveur ------------
        if p.ack_flag and not p.syn and not p.rst:
            # Plus haut acquittement emis par ce sens (voir _Dir.ack_max).
            if me.ack_max is None or not seq_le(p.ack, me.ack_max):
                me.ack_max = p.ack

            # PREUVE DE REPRISE : cet acquittement va-t-il PLUS LOIN que la ou
            # en etait le pair quand l'autre cote a renvoye pour la derniere
            # fois ? Alors le flux a avance apres le renvoi.
            if other.repere_pose and (other.repere_reprise is None
                                      or not seq_le(p.ack,
                                                    other.repere_reprise)):
                other.reprise = True

            # RTT : cet ACK couvre-t-il des segments en attente du sens oppose ?
            covered = [se for se in other.pending if seq_le(se, p.ack)]
            # Un ACK PUR ne transporte aucun octet : c'est lui, et lui seul, que
            # le timer de delayed ACK du recepteur peut retarder.
            ack_pur = p.payload_len == 0 and not p.fin
            # ... et le timer ne PEUT s'armer que si le pair n'avait qu'un seul
            # segment en vol : deux segments pleins non acquittes obligent la
            # RFC 1122 a acquitter immediatement. Un ACK qui en couvre deux n'a
            # donc pas attendu de timer, quoi qu'il transporte.
            segment_isole = len(covered) == 1 and len(other.pending) == 1
            # Autre explication mesurable : le tampon de reception de CE cote
            # etait effondre, il ne pouvait plus rien accepter ni acquitter.
            win_max_me = win_max_c2s if op.from_client else win_max_s2c
            fenetre_effondree = (win_max_me > 0
                                 and p.win * _FENETRE_EFFONDREE_FRACTION
                                 <= win_max_me)
            for se in covered:
                rtt_vals.append((p.ts - other.pending.pop(se)) * 1000.0)
                rtt_ack_pur.append(ack_pur)
                rtt_segment_isole.append(segment_isole)
                rtt_fenetre_effondree.append(fenetre_effondree)

            # Etablissement prouve sans SYN/ACK : le serveur acquitte des
            # OCTETS APPLICATIFS du client. Compare au premier seq_end de
            # donnees c2s, pas au dernier : un ACK partiel prouve deja qu'une
            # socket a lu. Un ACK qui ne couvrirait que le SYN (cseq+1) reste
            # en dessous et ne prouve rien.
            if (not op.from_client and first_c2s_seq_end is not None
                    and seq_le(first_c2s_seq_end, p.ack)):
                established_seen = True

            if p.payload_len == 0 and not p.fin:
                # Dup ACK : meme ack ET meme fenetre que le precedent ACK pur
                # du meme sens. Une fenetre differente = window update, pas un
                # dup ack (l'erreur classique des detecteurs naifs).
                if me.last_ack is not None and p.ack == me.last_ack \
                        and p.win == me.last_win:
                    me.dup_run += 1
                    if me.dup_run == 3:
                        if op.from_client:
                            sig.dup_ack_bursts_from_client += 1
                        else:
                            sig.dup_ack_bursts_from_server += 1
                        # Le PAIR vient de reclamer une retransmission. Tout
                        # renvoi de sa part sera une retransmission, meme
                        # arrivee en moins de _OOO_WINDOW_S : sur un LAN, un
                        # fast retransmit est plus rapide que la fenetre de
                        # reordonnancement, et le flux perdait alors TOUTES
                        # ses retransmissions (revue du 25/07/2026).
                        other.dup_ack_reclame = True
                else:
                    me.dup_run = 0
                me.last_ack, me.last_win = p.ack, p.win

                # Ack-delay serveur : ACK pur qui couvre la fin de la requete,
                # AVANT que la reponse ne parte. Mesure une fois par bloc.
                if (not op.from_client and talk_state == "client"
                        and not block_ack_measured
                        and last_c2s_seq_end is not None
                        and last_c2s_data_ts is not None
                        and seq_le(last_c2s_seq_end, p.ack)):
                    ack_delay_samples.append((p.ts - last_c2s_data_ts) * 1000.0)
                    block_ack_measured = True

        # ---- Cloture ---------------------------------------------------------
        if p.fin:
            me.fin_ts = me.fin_ts or p.ts
        if p.rst and rst_info is None:
            # « En plein travail » = la session etait etablie ET du trafic
            # applicatif circulait, dans UN sens au moins. Exiger des donnees
            # dans les deux sens ecartait tout collecteur (syslog/TCP,
            # metriques, MQTT publish) dont le serveur ne repond rien : ces
            # sessions-la tombaient sans aucun verdict (durcissement du
            # 08/08/2026).
            data_before = established_seen and (data_bidir_seen_c2s
                                                or data_bidir_seen_s2c)
            rst_info = (op.from_client, p.ts, data_before)

    # ---- Consolidation -------------------------------------------------------
    sig.syn_count = len(syn_times)
    if len(syn_times) >= 2:
        sig.syn_span_s = syn_times[-1] - syn_times[0]
    sig.established_seen = established_seen
    sig.handshake_complete = sig.synack_seen and (
        data_bidir_seen_c2s or data_bidir_seen_s2c
        or any(op.from_client and op.pkt.ack_flag and not op.pkt.syn
               for op in pkts))

    sig.retrans_total = sig.retrans_c2s + sig.retrans_s2c
    data_total = sig.data_pkts_c2s + sig.data_pkts_s2c
    sig.retrans_base = data_total + sig.retrans_total
    if sig.retrans_base > 0:
        sig.retrans_rate = sig.retrans_total / sig.retrans_base
    # La capture montre-t-elle un retablissement ? Chaque sens qui a retransmis
    # doit avoir vu le pair acquitter tout ce qu'il avait emis au moment de son
    # dernier renvoi. Sans renvoi, il n'y a rien a se remettre : le champ reste
    # faux et aucune regle ne s'en sert alors.
    sens_en_perte = [d for d in (c2s, s2c) if d.repere_pose]
    sig.reprise_apres_perte = bool(sens_en_perte) and all(d.reprise
                                                          for d in sens_en_perte)
    # Signature du backoff RTO : le segment le plus renvoye, l'etalement de ses
    # renvois, et le fait que le pair ne l'ait jamais acquitte.
    for d, pair in ((c2s, s2c), (s2c, c2s)):
        for se, ts_list in d.retrans_par_seq.items():
            if len(ts_list) > sig.retrans_meme_segment_max:
                sig.retrans_meme_segment_max = len(ts_list)
                sig.retrans_meme_segment_span_s = ts_list[-1] - ts_list[0]
                sig.retrans_meme_segment_jamais_acquitte = (
                    pair.ack_max is None or not seq_le(se, pair.ack_max))

    # « Tout ce qui a ete compte vient du meme hoquet. » Le seuil de 2 evite de
    # qualifier d'evenement unique la retransmission isolee, qu'aucune regle de
    # perte ne regarde de toute facon.
    #
    # Ce champ ne dit RIEN d'un retablissement, et il ne doit pas : l'argument
    # qu'il porte — un pourcentage tire d'un evenement unique n'a pas
    # d'intervalle de confiance — vaut que la session s'en soit remise ou non. Y
    # melanger la reprise rendrait le TAUX et la confiance haute a tous les
    # episodes uniques non repris, c'est-a-dire defaire le durcissement 2. Le
    # retablissement se lit sur reprise_apres_perte, et c'est la regle qui
    # l'AFFIRME qui doit l'exiger.
    sig.perte_evenement_unique = (sig.retrans_events == 1
                                  and sig.retrans_total >= 2)

    sig.rtt_samples = len(rtt_vals)
    sig.rtt_ms_min = min(rtt_vals) if rtt_vals else None
    sig.rtt_ms_p50 = _pctl(rtt_vals, 0.50)
    # p95 pollue par les delayed ACK (~40-200 ms ajoutes sur les ACK differes) :
    # c'est connu et assume. La mediane, elle, ne l'est que sur un flux ou les
    # ACK purs sont MAJORITAIRES — d'ou rtt_haut_porte_par_ack_purs ci-dessous,
    # qui mesure le cas au lieu de le supposer absent.
    sig.rtt_ms_p95 = _pctl(rtt_vals, 0.95)
    # Les rapports se lisent contre un plancher de 1 ms (_RATIO_PLANCHER_MS) :
    # sous la milliseconde, un rapport n'a aucun sens et fabriquerait des
    # multiplicateurs a cinq chiffres. Cela n'enleve rien aux vrais ecarts —
    # 44 ms contre 1 ms sortent toujours a x44.
    if sig.rtt_ms_min and sig.rtt_ms_p95 and sig.rtt_ms_min > 0:
        sig.rtt_ratio_p95_min = sig.rtt_ms_p95 / max(_RATIO_PLANCHER_MS,
                                                     sig.rtt_ms_min)
    # Meme dispersion, mesuree sur la mediane : insensible aux delayed ACK
    # isoles, c'est celle sur laquelle une regle peut juger sans risquer un faux
    # verdict RESEAU (voir le champ dans FlowSignals).
    if sig.rtt_ms_min and sig.rtt_ms_p50 and sig.rtt_ms_min > 0:
        sig.rtt_ratio_p50_min = sig.rtt_ms_p50 / max(_RATIO_PLANCHER_MS,
                                                     sig.rtt_ms_min)
    # Les mesures qui font basculer un verdict de latence sont-elles TOUTES
    # portees par des ACK purs ? Alors la capture ne distingue plus la gigue du
    # chemin du timer d'acquittement du recepteur.
    # ... et, quand c'est le cas, les DEUX autres faits sans lesquels « ACK
    # pur » ne veut rien dire : la grandeur de ces mesures, et ce qui permet de
    # dire qu'un ACK pur est un ACK DIFFERE plutot qu'un ACK qui ne pouvait rien
    # transporter. Les regles combinent les trois ; aucune ne juge sur le
    # premier seul.
    hauts = [(v, pur, iso, eff)
             for v, pur, iso, eff in zip(rtt_vals, rtt_ack_pur,
                                         rtt_segment_isole,
                                         rtt_fenetre_effondree)
             if v >= _LATENCE_HAUTE_MS]
    sig.rtt_haut_porte_par_ack_purs = bool(hauts) and all(h[1] for h in hauts)
    sig.rtt_haut_max_ms = max((h[0] for h in hauts), default=None)
    sig.rtt_haut_sur_segment_isole = bool(hauts) and all(h[2] for h in hauts)
    sig.rtt_haut_sous_fenetre_saturee = bool(hauts) and all(h[3] for h in hauts)
    # Forme de la queue. Plancher de 1 ms au denominateur, meme raison que pour
    # ttfb_over_ack_ratio : une mediane de 0,01 ms sur un LAN fabriquerait un
    # rapport de plusieurs milliers a partir d'une queue de 0,03 ms. Sous la
    # milliseconde, la queue se juge contre 1 ms — cela n'enleve rien aux vrais
    # pics (52 ms sortent a x52) et supprime la fausse precision.
    if sig.rtt_ms_p95 is not None and sig.rtt_ms_p50 is not None:
        sig.rtt_ratio_p95_p50 = sig.rtt_ms_p95 / max(1.0, sig.rtt_ms_p50)

    sig.exchanges = len(ttfb_samples)
    sig.ttfb_ms_p50 = _pctl(ttfb_samples, 0.50)
    sig.ttfb_ms_p95 = _pctl(ttfb_samples, 0.95)
    sig.ttfb_ms_max = max(ttfb_samples) if ttfb_samples else None
    sig.server_ack_delay_ms_p95 = _pctl(ack_delay_samples, 0.95)
    # Rapport reponse/acquittement : la vraie preuve que le delai est dans le
    # serveur. Un plancher de 1 ms evite de diviser par une mesure sous la
    # resolution utile et de fabriquer un rapport astronomique.
    if sig.ttfb_ms_p95 is not None and sig.server_ack_delay_ms_p95 is not None:
        sig.ttfb_over_ack_ratio = (sig.ttfb_ms_p95
                                   / max(1.0, sig.server_ack_delay_ms_p95))


    # Periode zero-window jamais refermee : compter jusqu'a la fin du flux,
    # dans le bon sens (c2s = annoncee par le client, s2c = par le serveur).
    for d, from_client in ((c2s, True), (s2c, False)):
        if d.zw_open_ts is not None:
            _add_zw(sig, from_client,
                    (pkts[-1].pkt.ts - d.zw_open_ts) * 1000.0)
            d.zw_periods.append((d.zw_open_ts, pkts[-1].pkt.ts))

    # RECOUVREMENT fenetre fermee du client / attente d'une reponse. Les deux
    # familles d'intervalles sont disjointes chacune de son cote (une attente
    # finit quand la reponse arrive, une periode de fenetre fermee quand la
    # fenetre rouvre) : la somme des intersections ne compte donc rien deux
    # fois.
    sig.attente_totale_ms = sum(fin - deb for deb, fin in attentes) * 1000.0
    recouvrement_s = sum(max(0.0, min(fin, zf) - max(deb, zd))
                         for deb, fin in attentes
                         for zd, zf in c2s.zw_periods)
    sig.zw_client_attente_ms = recouvrement_s * 1000.0
    if sig.attente_totale_ms > 0:
        sig.zw_client_part_attente = (sig.zw_client_attente_ms
                                      / sig.attente_totale_ms)

    if rst_info is not None:
        from_client, rst_ts, data_before = rst_info
        fin_before = any(d.fin_ts is not None and d.fin_ts <= rst_ts
                         for d in (c2s, s2c))
        sig.closed_by = "rst_client" if from_client else "rst_server"
        sig.rst_emitter = fl.client if from_client else fl.server
        # Un RST apres FIN est une fermeture expeditive banale ; le signal
        # interessant est le RST qui interrompt une session qui travaillait.
        sig.rst_midstream = data_before and not fin_before
    elif c2s.fin_ts or s2c.fin_ts:
        sig.closed_by = "fin"

    for ev in fl.icmp:
        sig.icmp_unreach_count += 1
        if ev.is_admin_prohibited:
            sig.icmp_admin_prohibited = True
            sig.icmp_admin_prohibited_from = ev.icmp_src
        if ev.is_frag_needed:
            sig.icmp_frag_needed = True

    sig.seg_max_before_frag_needed = seg_max_before_frag
    sig.seg_max_after_frag_needed = seg_max_after_frag
    # Le pair a-t-il acquitte la premiere emission posterieure a l'erreur ?
    pair_ack_max = (s2c if frag_from_client else c2s).ack_max
    sig.progres_apres_frag_needed = (frag_ts is not None
                                     and premier_seq_end_apres_frag is not None
                                     and pair_ack_max is not None
                                     and seq_le(premier_seq_end_apres_frag,
                                                pair_ack_max))
    # « Honore » exige une PREUVE, et elle est en DEUX temps : des segments emis
    # apres l'erreur et plus petits qu'avant (l'emetteur a ecoute), ET un
    # acquittement du pair sur ces octets-la (le calibre reduit passe).
    # Sans le second, un emetteur qui descend de 1460 a 1400 derriere un lien a
    # 1300 sortait « decouverte de MTU reussie, rien a corriger » alors que plus
    # rien ne traversait. Toute autre situation — meme calibre, plus rien
    # d'emis, ou rien d'acquitte — laisse le diagnostic de trou noir en place.
    frag_honore = (frag_ts is not None and seg_max_before_frag > 0
                   and 0 < seg_max_after_frag < seg_max_before_frag
                   and sig.progres_apres_frag_needed)
    sig.frag_needed_ignored = frag_ts is not None and not frag_honore

    return sig
