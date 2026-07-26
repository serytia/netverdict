"""Parseur d'evenements Windows (Event Log) -> TimelineEvent (v1.1).

Le pcap raconte ce qui a bouge SUR LE FIL ; ce module raconte ce qui a
bouge SUR L'HOTE juste avant -- service installe, bascule secteur/batterie,
lien reseau qui tombe, arret inattendu. C'est le premier parseur de
sources/ (voir timeline.py pour le contrat que ce fichier respecte).

Etage "decoder" au sens Wazuh, comme pcap.py : on parse et on categorise
par une table documentee, on ne juge pas la pertinence (ca vit dans
timeline.Timeline.window()).

Deux formats d'entree, une seule fonction publique (parse) :

  a) XML produit par `wevtutil qe <canal> /f:xml` -- TOUJOURS supporte,
     zero dependance (stdlib uniquement). wevtutil emet par defaut une
     SEQUENCE de <Event> SANS racine commune (document non bien forme au
     sens XML strict) ; on l'enveloppe nous-memes avant de parser. Le
     format avec racine <Events> (autres outils/exports) est aussi accepte,
     de la meme maniere.

  b) .evtx binaire, via l'extra optionnel python-evtx (import paresseux,
     jamais charge si le fichier est du XML -- la dependance n'existe pour
     de vrai qu'au moment ou on en a besoin). Absent -> ValueError avec la
     commande d'export XML a lancer : aucun admin ne doit rester bloque
     faute d'avoir installe un extra pip.

Choix assumes :
- Un seul champ est un echec dur pour un record : le timestamp. Provider/
  Computer/Level/EventID absents degradent en valeurs par defaut (compter,
  jamais sacrifier tout l'evenement pour un champ secondaire manquant).
- Le document XML est parse EN UNE FOIS (apres enveloppe synthetique) :
  un record vraiment mal forme XML-wise (balise non fermee, par exemple)
  casse tout le document -> ValueError (rare : export wevtutil interrompu
  en plein milieu de l'ecriture). Le cas courant de donnee pourrie -- un
  champ absent sur un record par ailleurs bien forme (pas de TimeCreated,
  par exemple) -- reste, lui, compte en unparsed sans jamais faire
  echouer les autres records du meme fichier.
- Le format binaire .evtx est lu recor par record (python-evtx isole
  chaque record), donc plus resistant qu'un flux XML concatene a la
  corruption d'un seul record.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..timeline import ConnectionInfo, SourceStats, TimelineEvent

# Sysmon est livre AVEC Windows 11 24H2 (C:\Windows\System32\sysmon.exe,
# ProductName "Sysmon Sysinternals", signe CN=Microsoft Windows) : aucun
# telechargement, mais il faut `sysmon -i <config>` en administrateur pour
# installer le driver, le service et le canal de journal.
_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
# Event ID 3 = NetworkConnect. DESACTIVE par defaut : il faut une config
# (voir netverdict/capture/sysmon-netverdict.xml, qui n'active que celui-la).
_SYSMON_NETWORK_CONNECT = "3"

# WFP (Windows Filtering Platform) : audit NATIF de Windows, zero
# installation -- la ou Sysmon exige d'installer un agent (`sysmon -i`),
# WFP s'active par `auditpol` ou GPO sur n'importe quel Windows sans rien
# deployer. Meme argument que Sysmon EID 3 pour la jointure process<->flux,
# sans le prealable d'installation.
#
# Le canal Security n'a QU'UN SEUL provider pour tout son audit (logons,
# privileges, WFP...) : (Provider, EventID) reste la bonne cle, l'EventID
# fait tout le travail de discrimination ici.
_WFP_PROVIDER = "Microsoft-Windows-Security-Auditing"
# EID 5156 : "The Windows Filtering Platform has permitted a connection" --
# LE cas utile courant, l'equivalent WFP de Sysmon EID 3.
_WFP_EID_ALLOW = "5156"
# EID 5157 : "The Windows Filtering Platform has blocked a connection" --
# aussi precieux que 5156 pour cet outil : un flux qui n'aboutit pas (SYN
# sans reponse dans le pcap) trouve ici son explication ET son process, la
# ou Sysmon (qui n'observe QUE les connexions etablies) resterait muet.
_WFP_EID_BLOCK = "5157"

# Namespace XML de tous les evenements Windows modernes (journal "Crimson").
_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Signature binaire d'un fichier .evtx (8 premiers octets du fichier) --
# on identifie le format par le CONTENU, jamais par l'extension : meme
# discipline que pcap._open_reader, les admins renomment les fichiers.
_EVTX_MAGIC = b"ElfFile\x00"

# TimeCreated/@SystemTime : wevtutil rend "2026-07-24T14:03:22.1234567Z"
# (fraction jusqu'a 7 chiffres = ticks Windows de 100ns, suffixe Z) MAIS
# python-evtx rend "2026-07-24 14:03:22.123456" -- separateur ESPACE, pas
# de Z (datetime.isoformat(" ") dans Evtx/Nodes.py). Les deux sont de
# l'UTC ; accepter les deux formes, sinon le chemin .evtx binaire compte
# 100 % des records en unparsed (constate en revue).
_TS_RE = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})"
    r"[T ](?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d+))?"
    r"Z?$"
)

# Declaration XML (<?xml ... ?>) : on la retire avant d'envelopper/reparser,
# une seule est autorisee par document XML et seulement en tete.
_XML_DECL_RE = re.compile(r"<\?xml[^>]*\?>")


# ---------------------------------------------------------------------------
# Categorisation (Provider, EventID) -> (category, severity, description).
# Chaque ligne documente ce que l'evenement SIGNIFIE : c'est cette table qui
# transforme un ID Windows opaque en changement d'infra actionnable pour la
# correlation avec le pcap. category doit venir de timeline.CATEGORIES.
# ---------------------------------------------------------------------------
_EVENT_TABLE: dict[tuple[str, str], tuple[str, int, str]] = {
    # Bascule de source d'alimentation (secteur <-> batterie) : LE cas
    # laptop qui se met a couper des connexions en passant sur batterie
    # (throttle CPU, wifi power-save agressif).
    ("Microsoft-Windows-Kernel-Power", "105"):
        ("power", 1, "changement de source d'alimentation"),

    # Mise en veille (sommeil/veille prolongee) : le reseau tombe pendant
    # le sommeil, ce qui suit au reveil est une renegociation, pas une panne.
    ("Microsoft-Windows-Kernel-Power", "42"):
        ("power", 1, "mise en veille"),

    # Reprise apres veille : les connexions etablies avant le sommeil sont
    # mortes, les erreurs juste apres sont attendues.
    ("Microsoft-Windows-Kernel-Power", "107"):
        ("power", 1, "reprise apres veille"),

    # Arret inattendu : le noyau n'a pas eu le temps d'ecrire l'evenement
    # d'arret propre avant le prochain demarrage -- coupure secteur, crash,
    # reset materiel. Le plus grave des evenements power/reboot.
    ("Microsoft-Windows-Kernel-Power", "41"):
        ("reboot", 3, "arret inattendu (dirty shutdown)"),

    # Arret ou redemarrage demande explicitement (utilisateur, Windows
    # Update, GPO) : moins suspect qu'un 41 mais reste un changement
    # d'etat majeur de l'hote.
    ("User32", "1074"):
        ("reboot", 2, "arret ou redemarrage initie"),

    # Le service EventLog demarre : litteralement l'un des tout premiers
    # evenements ecrits au boot -- le systeme vient de (re)demarrer.
    ("EventLog", "6005"):
        ("reboot", 1, "demarrage du systeme"),

    # Le service EventLog s'arrete proprement : arret du systeme en cours.
    ("EventLog", "6006"):
        ("reboot", 1, "arret du systeme"),

    # Nouveau service installe : le suspect n 1 des changements de
    # comportement (nouvel agent, nouvelle appli qui ouvre un port, backdoor
    # persistee en service). Merite d'etre mis en avant.
    ("Service Control Manager", "7045"):
        ("change", 2, "nouveau service installe"),

    # Un service a change d'etat (running <-> stopped) : tres frequent et
    # normal (redemarrages planifies, mises a jour) -- severite basse par
    # defaut, mais categorise "service" pour rester filtrable.
    ("Service Control Manager", "7036"):
        ("service", 0, "service : changement d'etat running/stopped"),

    # Le service n'a pas reussi a demarrer : echec net.
    ("Service Control Manager", "7000"):
        ("service", 3, "echec du demarrage d'un service"),

    # Le service s'est arrete de facon inattendue (crash).
    ("Service Control Manager", "7031"):
        ("service", 3, "arret inattendu d'un service (crash)"),

    # Le service s'est arrete de facon inattendue, meme gravite que 7031
    # (variante emise selon la config de recuperation du service).
    ("Service Control Manager", "7034"):
        ("service", 3, "arret inattendu d'un service (crash)"),

    # Mise a jour Windows installee : un patch peut changer un comportement
    # reseau (pile TCP, pilote, regles firewall) du jour au lendemain --
    # le suspect n 1 apres un service nouvellement installe.
    ("Microsoft-Windows-WindowsUpdateClient", "19"):
        ("change", 2, "mise a jour installee"),

    # Sysmon : connexion reseau observee, avec le process qui la detient.
    # Categorie "info" et severite 0 A DESSEIN : c'est une OBSERVATION, pas un
    # changement d'infra. La mettre dans CHANGE_CATEGORIES noierait la section
    # « changements » sous chaque connexion de la machine. Sa valeur est
    # ailleurs : le champ `connection`, qui porte la jointure process<->flux.
    (_SYSMON_PROVIDER, _SYSMON_NETWORK_CONNECT):
        ("info", 0, "connexion reseau"),

    # WFP : connexion PERMISE par une regle de filtrage, avec le process qui
    # la detient. Meme raisonnement que Sysmon EID 3 ci-dessus : "info"/0 A
    # DESSEIN, c'est une OBSERVATION -- la jointure vit dans `connection`,
    # pas dans la categorie (cf. commentaire Sysmon et TimelineEvent.connection
    # dans timeline.py).
    (_WFP_PROVIDER, _WFP_EID_ALLOW):
        ("info", 0, "connexion WFP permise"),

    # WFP : connexion BLOQUEE par une regle de filtrage. Severite 1 (un
    # signal a regarder), pas une "error" : c'est le pare-feu qui fait son
    # travail, pas une panne de l'hote. Categorie "info" pour la meme raison
    # que ci-dessus -- le message le dit explicitement (voir plus bas).
    (_WFP_PROVIDER, _WFP_EID_BLOCK):
        ("info", 1, "connexion WFP bloquee"),

    # Connexion a un profil reseau : l'hote vient de rejoindre un reseau
    # (cable branche, wifi associe, VPN monte).
    ("Microsoft-Windows-NetworkProfile", "10000"):
        ("network", 1, "connexion a un reseau"),

    # Deconnexion d'un profil reseau : le lien vient de tomber.
    ("Microsoft-Windows-NetworkProfile", "10001"):
        ("network", 1, "deconnexion d'un reseau"),
}

# Categorisation par defaut quand (Provider, EventID) n'est pas dans la
# table ci-dessus : on retombe sur le Level Windows, seul signal de
# gravite universel garanti present sur a peu pres n'importe quel
# evenement (Critical/Error/Warning -- le reste range en info).
_LEVEL_DEFAULT: dict[str, tuple[str, int]] = {
    "1": ("error", 3),   # Critical
    "2": ("error", 2),   # Error
    "3": ("error", 1),   # Warning
}
# Level 0 (LogAlways/non specifie), 4 (Information), 5 (Verbose), ou Level
# absent : categorie "info", severite 0 -- jamais mis en avant par le
# rapport (cf. _LEVEL_DEFAULT.get(level, ("info", 0)) plus bas).


def _read_text(path: Path) -> str:
    """Lit le fichier XML en detectant l'encodage par BOM plutot que par
    extension : wevtutil suit l'encodage de sortie de la console qui l'a
    lance (une redirection PowerShell peut ecrire en UTF-16), le BOM est
    le seul indice fiable, comme utf-8-sig pour le JSON dans hostsnap.py.
    """
    raw = path.read_bytes()
    try:
        if raw.startswith(b"\xff\xfe"):
            return raw.decode("utf-16-le")
        if raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16-be")
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        # Export interrompu en pleine ecriture (longueur impaire en UTF-16) :
        # transformer le crash de codec en consigne actionnable.
        raise ValueError(
            f"Export XML tronque ou encodage incoherent ({path}) : "
            "regenerer avec  wevtutil qe System /f:xml > events.xml"
        ) from exc
    return raw.decode("utf-8", errors="replace")


def _strip_decl(text: str) -> str:
    return _XML_DECL_RE.sub("", text).strip()


def _parse_system_time(value: str) -> Optional[float]:
    """TimeCreated/@SystemTime : ISO8601 UTC, fraction de seconde optionnelle
    (jusqu'a 7 chiffres -- ticks Windows de 100ns) et suffixe Z obligatoire.

    Parse a la main plutot que via datetime.fromisoformat : on garde un
    controle total sur l'echec (jamais une exception qui remonte, juste un
    None qui fait compter le record en unparsed cote appelant) sans
    dependre du support exact du 'Z' ou des fractions >6 chiffres par la
    version de Python qui execute ce code.
    """
    m = _TS_RE.match(value.strip())
    if not m:
        return None
    try:
        frac = m.group("frac") or "0"
        # Complete/tronque a 6 chiffres (microseconde) : les chiffres
        # au-dela sont une precision qu'un epoch float ne restituerait de
        # toute facon pas.
        microsecond = int((frac + "000000")[:6])
        dt = datetime(
            int(m.group("y")), int(m.group("mo")), int(m.group("d")),
            int(m.group("h")), int(m.group("mi")), int(m.group("s")),
            microsecond, tzinfo=timezone.utc,
        )
        return dt.timestamp()
    except ValueError:
        return None


def _ns_of(elem: ET.Element) -> str:
    """Namespace effectivement en vigueur pour cet element (heritee ou
    propre), lu directement sur le tag deja resolu par ElementTree --
    fonctionne que le xmlns soit declare sur <Event> lui-meme (cas normal
    wevtutil/python-evtx) ou sur un <Events> ancetre (wrapper qui
    factoriserait le xmlns). Chaine vide si aucun namespace (XML bricole
    a la main sans xmlns)."""
    if elem.tag.startswith("{"):
        return elem.tag[1:elem.tag.index("}")]
    return ""


def _wrap_and_parse(text: str) -> ET.Element:
    """wevtutil qe /f:xml emet par defaut une SEQUENCE de <Event> sans
    racine unique (document non bien forme au sens XML) ; d'autres exports
    l'enveloppent dans <Events>. On force un document bien forme en
    enveloppant TOUJOURS dans une racine synthetique : ca absorbe les deux
    cas identiquement (envelopper un <Events> deja present ne fait
    qu'ajouter un niveau, sans effet sur la recherche des <Event> qui
    descend a toute profondeur via './/').

    PROPRIETE DE SECURITE (a preserver, testee) : envelopper TOUJOURS met
    tout DOCTYPE du fichier source A L'INTERIEUR de la racine synthetique,
    ou il est mal forme -> ValueError propre. C'est ce qui neutralise les
    entites externes/XXE et les bombes d'entites sur ElementTree. Un
    refactor "n'envelopper que si necessaire" rouvrirait la breche."""
    body = _strip_decl(text)
    return ET.fromstring(f"<EvtxNetverdictRoot>{body}</EvtxNetverdictRoot>")


def _find_events(root: ET.Element) -> list[ET.Element]:
    # Les DEUX formes, toujours : un fichier issu d'une concatenation
    # d'exports peut melanger <Event> namespaces et bruts -- un if/else
    # perdrait silencieusement la seconde famille (ni parsee ni comptee).
    return (root.findall(f".//{{{_EVENT_NS}}}Event")
            + root.findall(".//Event"))


def _simple_eventdata(ev: ET.Element, ns_prefix: str) -> str:
    """Extrait au plus 2 champs <Data> courts et mono-ligne de EventData
    pour enrichir le resume. Un champ vide, multi-ligne ou trop long est
    ignore plutot que de casser la regle "une ligne propre" du contrat --
    mieux vaut un resume plus court qu'un resume qui deborde."""
    data_parent = ev.find(f"{ns_prefix}EventData")
    if data_parent is None:
        return ""
    parts: list[str] = []
    for d in data_parent.findall(f"{ns_prefix}Data"):
        text = (d.text or "").strip()
        if not text or "\n" in text or "\r" in text or len(text) > 40:
            continue
        name = d.get("Name")
        parts.append(f"{name}={text}" if name else text)
        if len(parts) >= 2:
            break
    return ", ".join(parts)


def _eventdata_map(ev: ET.Element, ns_prefix: str) -> dict[str, str]:
    """Tous les <Data Name="X">valeur</Data> de EventData, en dictionnaire.

    Complementaire de _simple_eventdata (qui fabrique un resume humain court) :
    ici on veut les champs EXACTS, sans troncature ni filtre de longueur.
    """
    parent = ev.find(f"{ns_prefix}EventData")
    if parent is None:
        return {}
    out: dict[str, str] = {}
    for d in parent.findall(f"{ns_prefix}Data"):
        name = d.get("Name")
        if name:
            out[name] = (d.text or "").strip()
    return out


def _as_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sysmon_connection(fields: dict[str, str]) -> Optional[ConnectionInfo]:
    """Event ID 3 (NetworkConnect) -> ConnectionInfo.

    Noms de champs releves sur le SCHEMA du binaire livre avec Windows
    (`sysmon.exe -s`, schemaversion 4.91) et non devines : SourceIp,
    SourcePort, DestinationIp, DestinationPort, ProcessId, Image, User,
    Protocol, Initiated.

    Un quadruplet incomplet renvoie None : une jointure sur une adresse ou un
    port manquant rattacherait le flux au mauvais process, ce qui est pire que
    pas de jointure du tout.
    """
    src_ip = fields.get("SourceIp", "")
    dst_ip = fields.get("DestinationIp", "")
    src_port = _as_int(fields.get("SourcePort", ""))
    dst_port = _as_int(fields.get("DestinationPort", ""))
    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None

    initiated_raw = fields.get("Initiated", "").strip().lower()
    initiated: Optional[bool]
    if initiated_raw in {"true", "1"}:
        initiated = True
    elif initiated_raw in {"false", "0"}:
        initiated = False
    else:
        initiated = None

    return ConnectionInfo(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=fields.get("Protocol", "").strip().lower(),
        pid=_as_int(fields.get("ProcessId", "")),
        image=fields.get("Image", ""),
        user=fields.get("User", ""),
        initiated=initiated,
    )


def _wfp_connection(fields: dict[str, str]) -> Optional[ConnectionInfo]:
    """Event ID 5156/5157 (WFP, canal Security) -> ConnectionInfo.

    Noms de champs EventData exacts du provider
    Microsoft-Windows-Security-Auditing : ProcessID, Application, Direction,
    SourceAddress, SourcePort, DestAddress, DestPort, Protocol.

    Avantage sur Sysmon ET sur auditd : WFP donne les DEUX extremites (src
    ET dst), la jointure via correlate._side_of sera donc EXACTE
    (ProcessAttribution.exact=True) -- exactement ce qu'auditd ne peut pas
    offrir puisque connect() ne journalise jamais le port source.

    Un quadruplet incomplet renvoie None : meme regle que Sysmon, une
    jointure sur un champ manquant rattacherait le flux au mauvais process,
    ce qui est pire que pas de jointure du tout.
    """
    src_ip = fields.get("SourceAddress", "")
    dst_ip = fields.get("DestAddress", "")
    src_port = _as_int(fields.get("SourcePort", ""))
    dst_port = _as_int(fields.get("DestPort", ""))
    if not src_ip or not dst_ip or src_port is None or dst_port is None:
        return None

    protocol_raw = fields.get("Protocol", "").strip()
    if protocol_raw == "6":
        protocol = "tcp"
    elif protocol_raw == "17":
        protocol = "udp"
    else:
        # Protocole ni TCP ni UDP (1=ICMP, etc.), ou absent : on GARDE la
        # valeur numerique telle quelle plutot que de forcer "tcp" par
        # defaut. correlate.attribution_for() ignore tout ce qui n'est pas
        # exactement "tcp" -- un protocole inconnu doit rester distinct de
        # "tcp" pour ne pas fausser une jointure qui ne le concerne pas.
        protocol = protocol_raw

    direction = fields.get("Direction", "").strip()
    initiated: Optional[bool]
    if direction == "%%14593":       # Outbound
        initiated = True
    elif direction == "%%14592":     # Inbound
        initiated = False
    else:
        initiated = None

    return ConnectionInfo(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        pid=_as_int(fields.get("ProcessID", "")),
        # Chemin NT (\device\harddiskvolumeN\...) : impossible a resoudre de
        # facon fiable vers une lettre de lecteur sans API Windows, et
        # l'analyse peut se faire hors ligne sur une autre machine -- on le
        # garde tel quel. ConnectionInfo.process_label() n'a besoin que du
        # dernier segment de chemin, qui reste "curl.exe" quel que soit le
        # separateur : verifie, aucune degradation cote rapport.
        image=fields.get("Application", ""),
        user=fields.get("SubjectUserName", ""),
        initiated=initiated,
    )


def _parse_event_element(ev: ET.Element) -> Optional[TimelineEvent]:
    """Convertit UN element <Event> (namespace ou non) en TimelineEvent.

    Retourne None uniquement si l'evenement n'a pas de timestamp
    exploitable (ou pas de bloc <System> du tout) : c'est le seul echec dur
    du contrat. Tout le reste (Provider/Computer/Level/EventID absents)
    degrade en valeurs par defaut plutot que de sacrifier l'evenement
    entier pour un champ secondaire manquant.
    """
    ns = _ns_of(ev)
    p = f"{{{ns}}}" if ns else ""

    system = ev.find(f"{p}System")
    if system is None:
        return None

    time_created = system.find(f"{p}TimeCreated")
    system_time = time_created.get("SystemTime") if time_created is not None else None
    ts = _parse_system_time(system_time) if system_time else None
    if ts is None:
        return None

    provider_el = system.find(f"{p}Provider")
    provider = ""
    if provider_el is not None:
        provider = (provider_el.get("Name") or "").strip()

    def _text(tag: str) -> str:
        el = system.find(f"{p}{tag}")
        return (el.text or "").strip() if el is not None else ""

    ident = _text("EventID")
    host = _text("Computer")
    level = _text("Level")

    entry = _EVENT_TABLE.get((provider, ident))
    # Certains exports tiers raccourcissent le provider ("Kernel-Power" au
    # lieu de "Microsoft-Windows-Kernel-Power") : on retente en prefixant,
    # pour que la table au nom canonique matche les deux formes.
    if entry is None and provider and not provider.startswith("Microsoft-Windows-"):
        entry = _EVENT_TABLE.get((f"Microsoft-Windows-{provider}", ident))
    if entry is not None:
        category, severity, desc = entry
    else:
        category, severity = _LEVEL_DEFAULT.get(level, ("info", 0))
        desc = f"EventID {ident}" if ident else "evenement sans EventID"

    # Sysmon Event 3 ou WFP 5156/5157 : on extrait la jointure
    # process<->connexion, et on fabrique un resume lisible plutot que le
    # "Name=valeur" generique.
    connection: Optional[ConnectionInfo] = None
    champs: dict[str, str] = {}
    if provider == _SYSMON_PROVIDER and ident == _SYSMON_NETWORK_CONNECT:
        champs = _eventdata_map(ev, p)
        connection = _sysmon_connection(champs)
    elif provider == _WFP_PROVIDER and ident in (_WFP_EID_ALLOW, _WFP_EID_BLOCK):
        champs = _eventdata_map(ev, p)
        connection = _wfp_connection(champs)

    if connection is not None:
        # HORODATAGE : TimeCreated est le moment ou le journal a ECRIT le
        # record ; UtcTime est le moment ou la connexion a eu lieu. Pour une
        # jointure avec un pcap, seul le second a du sens — l'ecriture peut
        # etre differee (charge, buffer du canal), et le decalage faisait
        # sortir l'evenement de la fenetre du flux SANS AUCUN SIGNAL, ou
        # elisait le mauvais process quand un port avait ete reutilise.
        # On ne bascule que si UtcTime est exploitable : sinon TimeCreated
        # reste une approximation utilisable, pas une raison de tout jeter.
        utc = _parse_system_time(champs.get("UtcTime", ""))
        if utc is not None:
            ts = utc
        c = connection
        resume = (f"{desc} : {c.process_label()} "
                  f"{c.src_ip}:{c.src_port} -> {c.dst_ip}:{c.dst_port}")
        if c.protocol:
            resume += f" ({c.protocol})"
    else:
        extra = _simple_eventdata(ev, p)
        resume = f"{desc} ({extra})" if extra else desc
    message = f"{provider or '(provider inconnu)'}: {resume}"

    return TimelineEvent(
        ts=ts,
        source="evtx",
        host=host,
        category=category,
        severity=severity,
        ident=ident,
        message=message,
        tz_known=True,
        connection=connection,
    )


def _parse_xml_file(path: Path, stats: SourceStats) -> list[TimelineEvent]:
    text = _read_text(path)
    try:
        root = _wrap_and_parse(text)
    except Exception as exc:
        raise ValueError(
            f"XML illisible dans {path} ({exc}). L'export wevtutil est-il "
            "complet ? Regenerer avec : wevtutil qe System /f:xml > events.xml"
        ) from exc

    events: list[TimelineEvent] = []
    for ev in _find_events(root):
        stats.total_lines += 1
        tev = _parse_event_element(ev)
        if tev is None:
            stats.unparsed += 1
            continue
        events.append(tev)
        stats.parsed += 1
    return events


def _parse_binary(path: Path, stats: SourceStats) -> list[TimelineEvent]:
    try:
        # Import paresseux : python-evtx est un extra optionnel ([evtx]),
        # jamais charge tant qu'on lit du XML (le cas courant, zero
        # dependance).
        import Evtx.Evtx as evtx
    except ImportError as exc:
        raise ValueError(
            "Fichier .evtx binaire detecte mais python-evtx n'est pas "
            "installe. Deux options : installer l'extra "
            "(pip install 'netverdict[evtx]'), ou exporter en XML (zero "
            "dependance) puis relancer netverdict sur le fichier XML : "
            "wevtutil qe System /f:xml > events.xml  (canal en direct) ; "
            "wevtutil qe C:\\chemin\\fichier.evtx /lf:true /f:xml > events.xml"
            "  (canal sauvegarde / .evtx deja exporte)."
        ) from exc

    events: list[TimelineEvent] = []
    try:
        with evtx.Evtx(str(path)) as log:
            for record in log.records():
                stats.total_lines += 1
                try:
                    root = ET.fromstring(_strip_decl(record.xml()))
                except Exception:
                    stats.unparsed += 1
                    continue
                tev = _parse_event_element(root)
                if tev is None:
                    stats.unparsed += 1
                    continue
                events.append(tev)
                stats.parsed += 1
    except Exception as exc:
        raise ValueError(f"Lecture du .evtx {path} interrompue : {exc}") from exc

    return events


def parse(path: str | Path) -> tuple[list[TimelineEvent], SourceStats]:
    """Point d'entree du contrat sources/*.py (voir timeline.py).

    Detecte le format par le contenu (magic .evtx) et non par l'extension,
    parse, trie par ts croissant. Un fichier absent/illisible sur le
    disque leve l'OSError naturel de open() (meme choix que pcap.read_capture) ;
    ValueError est reserve au format reconnu-mais-invalide.
    """
    path = Path(path)
    stats = SourceStats()

    with path.open("rb") as f:
        head = f.read(8)

    if head == _EVTX_MAGIC:
        events = _parse_binary(path, stats)
    else:
        events = _parse_xml_file(path, stats)

    # Garde-fou constate sur machine reelle : `sysmon -i` SANS config
    # n'active pas NetworkConnect (EID3). Les events Sysmon se parsent alors
    # tres bien (ProcessCreate...), la jointure process<->flux ne matche
    # jamais, et RIEN ne le dit — une capacite silencieusement inerte. Le
    # critere est semantique (aucun event ne porte de ConnectionInfo), pas
    # le numero 3 : il couvre aussi WFP (5156/5157) ci-dessous, meme
    # symptome, meme remede (documenter la commande d'activation). Le
    # prefixe du message est NOTRE format (f"{provider}: ..."), invariant
    # teste.
    # Zero evenement lu : le cas peut etre legitime (export filtre vide), mais
    # il est INDISCERNABLE d'un fichier illisible tant qu'on ne le dit pas.
    # Constate en CI le 26/07 : un .evtx binaire tronque traverse python-evtx
    # sans lever et rendait ([], stats) — l'admin en concluait « rien ne s'est
    # passe » alors que sa source n'avait jamais ete lue.
    if not events:
        stats.note = (
            "aucun evenement lu dans ce fichier. S'il ne devait pas etre vide : "
            "verifier l'export (canal, filtre de date, droits) — pour un .evtx "
            "binaire, reexporter en XML avec  wevtutil qe <canal> /f:xml > events.xml")
    elif not any(e.connection is not None for e in events):
        # Deux sources possibles de connexion, deux verifications
        # INDEPENDANTES (sur le prefixe reel du message, pas sur une
        # supposition) : un fichier Sysmon sans EID3 ne doit jamais produire
        # la note WFP, et reciproquement -- chaque source a sa propre
        # commande d'activation, melanger les deux induirait l'admin en erreur.
        notes: list[str] = []
        if any(e.message.startswith(_SYSMON_PROVIDER) for e in events):
            notes.append(
                "events Sysmon lus mais AUCUN NetworkConnect (EID3) : "
                "l'attribution process<->flux ne peut pas fonctionner. "
                "Activer : sysmon -c <chemin>\\netverdict\\capture\\"
                "sysmon-netverdict.xml (console administrateur)")
        if any(e.message.startswith(_WFP_PROVIDER) for e in events):
            notes.append(
                "events de securite Windows lus mais AUCUN WFP 5156/5157 "
                "(Filtering Platform Connection) : l'attribution "
                "process<->flux ne peut pas fonctionner. Activer : "
                'auditpol /set /subcategory:"Filtering Platform Connection" '
                "/success:enable /failure:enable -- TRES verbeux (beaucoup "
                "d'evenements sur une machine chargee) : a n'activer que le "
                "temps du diagnostic, puis desactiver avec "
                "auditpol /set /subcategory:\"Filtering Platform Connection\" "
                "/success:disable /failure:disable")
        stats.note = " ".join(notes)

    events.sort(key=lambda e: e.ts)
    return events, stats
