"""Parseur auditd Linux (/var/log/audit/audit.log) -> TimelineEvent (v1.2).

Parite Linux de sources/evtx.py : la ou Sysmon Event ID 3 (NetworkConnect)
livre la jointure process<->flux sur Windows, le noyau Linux la livre via
auditd quand une regle surveille le syscall connect(). Meme contrat
(timeline.py), meme etage "decoder" (on parse et on categorise, on ne juge
pas la pertinence), meme discipline (un champ secondaire pourri degrade,
jamais un crash).

FORMAT D'ENTREE
---------------
Un fichier audit.log texte, une ligne par record. Deux types de records nous
concernent, et il faut TOUJOURS les deux pour obtenir une connexion :

  type=SYSCALL msg=audit(1785018155.501:12345): arch=c000003e syscall=42 \
      success=yes exit=0 ... ppid=1234 pid=11900 auid=1000 uid=1000 ... \
      comm="curl" exe="/usr/bin/curl" key="netverdict_connect"
  type=SOCKADDR msg=audit(1785018155.501:12345): saddr=02000050AC10000A...

Le nombre apres ':' dans msg=audit(TIMESTAMP:SERIAL) est le SERIAL : c'est
LA cle de jointure entre les deux records d'un meme appel systeme. En
pratique les deux lignes sont adjacentes (le noyau les ecrit dos a dos) mais
RIEN NE LE GARANTIT (un autre thread/process peut ecrire un record entre les
deux, auditd peut aussi reordonner sous charge) : on indexe par serial,
jamais par position.

PIEGE (documente, verifie a la main) : syscall=42 n'est "connect" QUE sur
x86_64 (arch=c000003e). Sur aarch64/arm64 connect() est le syscall 203, sur
i386 le 362 -- un filtre `syscall == 42` louperait silencieusement 100% des
connexions sur ARM. On NE FILTRE PAS sur le numero : le vrai critere est
semantique, "un SYSCALL avec succes qui a un SOCKADDR associe" (seuls les
appels prenant une adresse socket en emettent un, et le seul qu'on demande
d'auditer via la regle recommandee plus bas est connect()). Le dict ci-dessous
n'est donc que de la documentation, jamais un test dans le code.

DECODAGE DE saddr (struct sockaddr en hexadecimal, verifie a la main) :
  - 2 premiers octets = sa_family, en ordre HOTE (little-endian sur toute
    architecture visee par ce parseur) : "0200" -> family=2 (AF_INET).
  - IPv4 (family=2) : 2 octets de port en ordre RESEAU (big-endian), puis 4
    octets d'adresse.
    Exemple : saddr=02000050AC10000A -> family=AF_INET, port=0x0050=80,
    ip=AC.10.00.0A=172.16.0.10 (verifie a la main).
  - IPv6 (family=10, "0A00") : 2 octets de port (big-endian), 4 octets de
    flowinfo, 16 octets d'adresse.
  - Toute autre famille (AF_UNIX="0100" et le reste) : pas une connexion
    reseau -> IGNORER. C'est un record VALIDE qui ne nous concerne pas, donc
    il ne compte PAS en unparsed (distinction importante : unparsed est
    reserve au hex casse/tronque, jamais a "hors sujet").
  - hex de longueur impaire, non-hexadecimal, ou trop court pour la famille
    annoncee -> le record SOCKADDR est compte en unparsed.

CHAMPS -> ConnectionInfo :
  - src_ip/src_port : INCONNUS. connect() ne donne que la DESTINATION ; le
    port source choisi par le noyau n'apparait dans aucun des deux records.
    Mis a "" / 0.
  - dst_ip/dst_port : decodes depuis saddr.
  - protocol : "tcp" en dur. HYPOTHESE ASSUMEE : connect() est aussi valide
    sur un socket UDP (pour en fixer le pair par defaut), et rien dans
    SYSCALL/SOCKADDR ne distingue le type de socket -- il faudrait le fd et
    un getsockopt(SO_TYPE) qu'auditd ne journalise pas. "tcp" est le cas
    trente fois plus frequent en pratique (UDP connect() est rare) et c'est
    la valeur que correlate.attribution_for() sait deja filtrer (elle
    ignore tout ce qui n'est pas "tcp").
  - pid : SYSCALL.pid. image : SYSCALL.exe (chemin complet) ; a defaut,
    SYSCALL.comm (nom court, pas de chemin). user : SYSCALL.uid (uid reel,
    numerique) ; SYSCALL.auid (login uid) seulement si uid absent -- uid
    est CELUI DU PROCESS au moment de l'appel, auid celui de la session de
    connexion initiale (peut dater d'un `su`/service avec un autre uid
    reel) : uid colle mieux au process qu'on veut identifier.
  - initiated : True -- connect() est par construction une connexion
    SORTANTE.

POINT D'INTEGRATION (src_ip/src_port vides) : correlate._side_of (v1.2) sait
gerer une source vide -- c'est le fallback "destination seule" ajoute
precisement pour ce cas (connect() ne donne jamais la source). Il accepte le
match si le dst du ConnectionInfo colle a une des deux extremites du flux, et
marque alors l'attribution non EXACTE (ProcessAttribution.exact=False) :
plusieurs process contactant le meme serveur:port dans la fenetre seraient
indiscernables, et le rapport le dit. Verifie par
tests/test_source_auditd.py::TestIntegrationCorrelate (integration complete
auditd.parse() -> correlate.attribution_for()).

GARDE-FOU (meme raison que evtx.py) : `auditd` peut tourner sans qu'aucune
regle ne surveille connect() -- les records existent (execve, chemins de
fichiers...) mais aucun SYSCALL+SOCKADDR de connexion n'apparait jamais, et
rien ne le dit. Critere SEMANTIQUE (zero connexion produite malgre des
records valides lus), pas syntaxique.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Optional

from ..timeline import ConnectionInfo, SourceStats, TimelineEvent

# Documentation uniquement (voir piege plus haut) : jamais utilise comme
# filtre, le vrai critere est "SYSCALL reussi + SOCKADDR associe".
_CONNECT_SYSCALL_NR = {
    "c000003e": 42,   # x86_64
    "c00000b7": 203,  # aarch64/arm64 (meme bit __X32_SYSCALL_BIT que ci-dessus)
    "40000003": 362,  # i386
}

_AF_INET = 2
_AF_INET6 = 10

# "type=SYSCALL msg=audit(1785018155.501:12345): arch=... ...". Le prefixe
# node=<hote> optionnel apparait sur les journaux centralises/multi-hotes
# (log_format ENRICHED ou remote logging) -- tolere sans etre exige.
_RECORD_RE = re.compile(
    r'^(?:node=\S+\s+)?type=(?P<type>\S+)\s+'
    r'msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<serial>\d+)\):\s?(?P<rest>.*)$'
)

# key=value, valeur nue (\S+) ou entre guillemets ("...", peut contenir des
# espaces : comm="node exporter"). Fonctionne aussi si un champ ENRICHED
# est accole sans espace apres un guillemet fermant (cas reel constate),
# puisque chaque match ne depend que du prochain "cle=" trouve.
_KV_RE = re.compile(r'(?P<key>[A-Za-z0-9_]+)=(?:"(?P<qval>[^"]*)"|(?P<val>\S+))')

_HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')


class _NotIpFamily(Exception):
    """saddr valide mais famille non IP (AF_UNIX...) : ignorer sans compter
    en unparsed, ce n'est pas un record casse, juste hors sujet."""


def _parse_fields(rest: str) -> dict[str, str]:
    return {m.group("key"): (m.group("qval") if m.group("qval") is not None
                              else m.group("val"))
            for m in _KV_RE.finditer(rest)}


def _decode_saddr(saddr_hex: str) -> tuple[str, int]:
    """struct sockaddr en hexadecimal -> (ip, port).

    Leve ValueError si le hex est invalide/tronque (record casse, compte en
    unparsed cote appelant) ; leve _NotIpFamily si la famille decodee n'est
    ni AF_INET ni AF_INET6 (record valide, hors sujet -- PAS unparsed).
    """
    # auditd ecrit par DEFAUT en `log_format=ENRICHED` sur Debian/RHEL
    # modernes (confirme au lab : DAEMON_START ... format=enriched, auditd
    # 4.0.2). Ce n'est donc pas un artefact d'ausearch : le fichier
    # /var/log/audit/audit.log lui-meme colle la version interpretee du champ
    # DIRECTEMENT derriere la valeur, sans separateur —
    #   saddr=02001F907F0000010000000000000000SADDR={ saddr_fam=inet ... }
    # Un decoupage sur l'espace ramene donc l'hex + "SADDR={", non
    # hexadecimal, et TOUT record reel finissait en unparsed (constate au lab
    # kernel le 26/07 : 78 unparsed sur 224, zero connexion retrouvee).
    # On tronque au premier caractere non hexadecimal : robuste pour le
    # format brut comme pour l'enrichi.
    m = re.match(r'[0-9A-Fa-f]*', saddr_hex or "")
    saddr_hex = m.group(0) if m else ""
    # Longueur impaire = octet coupe en deux : on retire le demi-octet
    # orphelin plutot que de jeter le record (les champs utiles — famille,
    # port, adresse — sont en tete de la structure).
    if len(saddr_hex) % 2:
        saddr_hex = saddr_hex[:-1]
    if not saddr_hex:
        raise ValueError("saddr vide ou non hexadecimal")
    raw = bytes.fromhex(saddr_hex)
    if len(raw) < 4:
        raise ValueError("saddr trop court pour porter une famille+port")

    # sa_family : ordre HOTE (little-endian sur x86_64/aarch64/i386).
    family = int.from_bytes(raw[0:2], "little")
    # sin_port/sin6_port : ordre RESEAU (big-endian), toujours.
    port = int.from_bytes(raw[2:4], "big")

    if family == _AF_INET:
        if len(raw) < 8:
            raise ValueError("saddr AF_INET tronque (adresse manquante)")
        return socket.inet_ntoa(raw[4:8]), port

    if family == _AF_INET6:
        # family(2) + port(2) + flowinfo(4) + addr(16) = 24 octets minimum ;
        # scope_id (4 octets de plus) n'est pas necessaire pour l'adresse.
        if len(raw) < 24:
            raise ValueError("saddr AF_INET6 tronque (adresse manquante)")
        return socket.inet_ntop(socket.AF_INET6, raw[8:24]), port

    raise _NotIpFamily(f"famille sockaddr {family} non IP (AF_UNIX ou autre)")


def _connection_from(fields: dict[str, str], dst_ip: str, dst_port: int) -> ConnectionInfo:
    image = fields.get("exe") or fields.get("comm") or ""
    # uid prime sur auid : uid est celui du PROCESS au moment de l'appel,
    # auid celui de la session de connexion initiale (peut etre un autre
    # compte si le process a change d'uid depuis -- su, service...).
    user = fields.get("uid") if "uid" in fields else fields.get("auid", "")
    pid_raw = fields.get("pid")
    try:
        pid = int(pid_raw) if pid_raw is not None else None
    except ValueError:
        pid = None

    return ConnectionInfo(
        src_ip="",       # connect() ne donne jamais la source (voir docstring).
        src_port=0,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",  # hypothese assumee, documentee plus haut.
        pid=pid,
        image=image,
        user=user or "",
        initiated=True,  # connect() est par construction sortant.
    )


def parse(path: str | Path) -> tuple[list[TimelineEvent], SourceStats]:
    """Point d'entree du contrat sources/*.py (voir timeline.py).

    Deux passes sur le fichier : la premiere indexe chaque record SYSCALL et
    SOCKADDR par son serial (msg=audit(...:SERIAL)) sans supposer qu'ils sont
    adjacents ; la seconde joint les deux par serial et n'emet une
    connexion que si le SYSCALL a reussi ET qu'un SOCKADDR (IPv4/IPv6) lui
    correspond. Trie par ts croissant avant de retourner.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ValueError(
            f"audit.log illisible ({p}) : {exc}. Verifier le chemin et les "
            "permissions (souvent 0640 root:adm sur /var/log/audit/audit.log)."
        ) from exc

    stats = SourceStats()
    saw_valid_record = False

    # serial -> (ts, fields) pour SYSCALL ; serial -> (dst_ip, dst_port) pour
    # les SOCKADDR IP valides. Un serial peut n'apparaitre que d'un cote (pas
    # de crash, juste pas de connexion produite).
    syscalls: dict[int, tuple[float, dict[str, str]]] = {}
    sockaddrs: dict[int, tuple[str, int]] = {}

    for line in text.splitlines():
        stats.total_lines += 1
        m = _RECORD_RE.match(line)
        if not m:
            stats.unparsed += 1
            continue
        saw_valid_record = True
        rtype = m.group("type")
        serial = int(m.group("serial"))

        if rtype == "SYSCALL":
            ts = float(m.group("ts"))
            syscalls[serial] = (ts, _parse_fields(m.group("rest")))
        elif rtype == "SOCKADDR":
            fields = _parse_fields(m.group("rest"))
            saddr_hex = fields.get("saddr")
            if saddr_hex is None:
                # SOCKADDR sans le champ saddr lui-meme : record casse.
                stats.unparsed += 1
                continue
            try:
                sockaddrs[serial] = _decode_saddr(saddr_hex)
            except _NotIpFamily:
                pass  # valide, hors sujet (AF_UNIX...) : pas unparsed.
            except ValueError:
                stats.unparsed += 1
        # Tout autre type=... (CWD, PATH, PROCTITLE, EOE...) : record valide,
        # hors sujet pour ce parseur -- ni parsed ni unparsed.

    events: list[TimelineEvent] = []
    for serial, (ts, fields) in syscalls.items():
        # ON NE FILTRE PAS SUR success. Deux raisons, les deux verifiees sur
        # un journal reel (lab kernel, 26/07) :
        #
        # 1. Les clients modernes utilisent des sockets NON BLOQUANTES :
        #    connect() rend la main immediatement avec EINPROGRESS, journalise
        #    `success=no exit=-115`, et la connexion s'etablit ensuite tres
        #    normalement. curl, les navigateurs et tout client async sont dans
        #    ce cas — exiger success=yes rejetait 100 % de leurs connexions.
        # 2. Un connect() qui echoue VRAIMENT (ECONNREFUSED, ETIMEDOUT) est
        #    precisement ce que cet outil diagnostique : le flux existe dans
        #    le pcap (SYN sans reponse, RST) et l'admin veut savoir QUI a
        #    tente. Jeter ces records nous priverait des cas les plus utiles.
        #
        # Le garde-fou contre les faux positifs reste la famille d'adresse
        # (AF_UNIX et consorts sont deja ecartes au decodage) et la jointure
        # elle-meme, qui exige une correspondance de destination.
        dst = sockaddrs.get(serial)
        if dst is None:
            continue  # SYSCALL sans SOCKADDR correspondant : rien a joindre.
        dst_ip, dst_port = dst
        c = _connection_from(fields, dst_ip, dst_port)
        message = (f"auditd: connexion reseau : {c.process_label()} -> "
                   f"{c.dst_ip}:{c.dst_port} (tcp)")
        events.append(TimelineEvent(
            ts=ts,
            source="auditd",
            host="",  # audit.log ne porte pas le hostname (pas de champ pour ca).
            category="info",   # OBSERVATION, jamais un changement d'infra (cf. timeline.py).
            severity=0,
            ident="connect",
            message=message,
            tz_known=True,
            connection=c,
        ))
        stats.parsed += 1

    # Garde-fou : des records auditd valides existent mais AUCUNE connexion
    # n'en est sortie -- cas reel ou auditd tourne sans regle sur connect().
    # Critere semantique (zero event produit), jamais syntaxique.
    if saw_valid_record and not events:
        stats.note = (
            "records auditd lus mais aucune connexion reseau (SYSCALL "
            "connect() + SOCKADDR) : la regle d'audit n'est probablement "
            "pas chargee. Activer : auditctl -a always,exit -F arch=b64 "
            "-S connect -k netverdict_connect  (a rendre persistant dans "
            "/etc/audit/rules.d/, sinon la regle disparait au redemarrage)")

    events.sort(key=lambda e: e.ts)
    return events, stats
