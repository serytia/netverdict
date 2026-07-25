"""Point d'entree CLI : netverdict analyze | capture | rules."""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

from . import __version__


def cmd_analyze(args: argparse.Namespace) -> int:
    from .pcap import read_capture
    from .flows import build_flows
    from .signals import compute_signals
    from .rules.engine import load_rules, evaluate, RuleError
    from .report import render_console, to_json
    from .hostsnap import HostSnapshot

    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f"Erreur dans les regles : {e}", file=sys.stderr)
        return 2

    try:
        cap = read_capture(args.capture)
    except FileNotFoundError:
        print(f"Fichier introuvable : {args.capture}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{e}", file=sys.stderr)
        return 2

    flows = build_flows(cap)
    signals = [compute_signals(fl) for fl in flows]
    verdicts = evaluate(signals, rules)

    snapshot = None
    if args.snapshot:
        snapshot = HostSnapshot.load(args.snapshot)

    # Fuseau valide AVANT toute lecture : une faute de frappe doit se dire
    # tout de suite, pas apres avoir parse trois fichiers.
    syslog_tz = None
    if args.syslog_tz:
        if not args.syslog:
            # Sans --syslog, l'option ne s'applique a rien. Le silence ferait
            # croire a un decalage corrige alors que rien n'a bouge.
            print("--syslog-tz n'a d'effet qu'avec --syslog (aucun fichier "
                  "syslog fourni)", file=sys.stderr)
            return 2
        from .sources.syslog import parse_tz
        try:
            syslog_tz = parse_tz(args.syslog_tz)
        except ValueError as e:
            print(f"--syslog-tz: {e}", file=sys.stderr)
            return 2

    timeline = None
    if args.events or args.syslog or args.audit:
        from .timeline import Timeline
        timeline = Timeline()
        # OSError attrape aussi : un chemin --events/--syslog invalide doit
        # produire le meme message propre qu'un format invalide, pas un
        # traceback (les deux parseurs n'ont pas la meme convention interne,
        # le CLI unifie).
        for path in args.events:
            from .sources import evtx
            try:
                evs, st = evtx.parse(path)
            except (ValueError, OSError) as e:
                print(f"--events {path}: {e}", file=sys.stderr)
                return 2
            timeline.add_source(f"events:{Path(path).name}", evs, st)
        # Ancre de datation RFC3164 = la capture, pas l'horloge du poste :
        # un bundle archive (log de fevrier analyse en juillet) resterait
        # sinon date de l'annee courante et sortirait de la fenetre.
        syslog_anchor = None
        # `is not None` et non la veracite : l'epoch 0 est une VALEUR (pcap
        # synthetique ou anonymise), pas une absence. Un `if cap.t_last:`
        # retombait alors sur l'horloge du POSTE pour dater les lignes RFC3164,
        # sans le moindre signal — meme panne muette que celle corrigee dans
        # correlate.py, et elle deplace les evenements de plusieurs decennies.
        if cap.t_last is not None:
            from datetime import datetime as _dt, timezone as _tz
            try:
                # Ancre AWARE en UTC, jamais naive locale : sous Windows
                # fromtimestamp() sans fuseau leve pour un instant local
                # anterieur a l'epoch (poste a l'ouest de Greenwich + capture
                # proche de 0), et le repli du parseur syslog relisait alors
                # l'ancre comme de l'UTC — l'annee de reference basculait de
                # 1970 a 1969, les lignes RFC3164 sortaient de la fenetre et
                # le rapport affirmait « aucun changement detecte ». Avec un
                # fuseau explicite, fromtimestamp n'appelle jamais localtime
                # et le calcul est de l'arithmetique pure (audit du 26/07).
                syslog_anchor = _dt.fromtimestamp(cap.t_last, _tz.utc)
            except (OSError, OverflowError, ValueError):
                syslog_anchor = None
        for path in args.syslog:
            from .sources import syslog as syslog_src
            try:
                evs, st = syslog_src.parse(path, now=syslog_anchor,
                                           tz=syslog_tz)
            except (ValueError, OSError) as e:
                print(f"--syslog {path}: {e}", file=sys.stderr)
                return 2
            timeline.add_source(f"syslog:{Path(path).name}", evs, st)
        for path in args.audit:
            from .sources import auditd
            try:
                evs, st = auditd.parse(path)
            except (ValueError, OSError) as e:
                print(f"--audit {path}: {e}", file=sys.stderr)
                return 2
            timeline.add_source(f"audit:{Path(path).name}", evs, st)
        # Fenetre : les changements des 15 min qui precedent la capture ;
        # rien apres sa fin ne peut expliquer ce qu'elle contient.
        timeline = timeline.window(cap.t_first, cap.t_last)

    if args.json:
        print(to_json(cap, verdicts, snapshot, timeline))
    else:
        render_console(cap, verdicts, snapshot, top=args.top,
                       timeline=timeline)

    if args.explain:
        from .explain import explain, ExplainUnavailable
        try:
            print(explain(to_json(cap, verdicts, snapshot, timeline)))
            print()
        except ExplainUnavailable as e:
            print(f"[--explain indisponible] {e}", file=sys.stderr)

    # Code retour utilisable en script : 0 = rien d'anormal, 1 = au moins un
    # verdict non-RAS (meme convention que grep : "trouve" vs "rien trouve").
    problematic = any(fv.primary and fv.verdict != "RAS" for fv in verdicts)
    return 1 if problematic else 0


def cmd_capture(args: argparse.Namespace) -> int:
    """Delegue au script de capture assistee de la plateforme courante.

    Le script fait deux choses en parallele : capture reseau ciblee (pktmon
    sur Windows — natif, zero install ; tcpdump sur Linux) + snapshot de
    l'etat hote (sockets/PID/process, CPU, disque) au meme moment.
    """
    # DANS le paquet, jamais a cote : `parent.parent / "capture"` visait la
    # racine du depot, qui n'existe pas apres un `pip install` — le dossier
    # cible devenait site-packages/capture et la sous-commande sortait en
    # erreur 2 pour TOUT utilisateur installe, alors qu'elle est annoncee dans
    # l'aide (verifie sur le wheel 0.3.0 le 25/07/2026).
    # Refuser explicitement plutot que de lancer le script Linux sur un OS
    # qui n'en a aucune des briques : sur macOS, capture.sh echoue sur `ss`
    # (inexistant), /proc/loadavg (inexistant) et `tcpdump -i any` (pas de
    # pseudo-interface `any` en BSD), en laissant un tcpdump orphelin en train
    # d'ecrire. Mieux vaut un message honnete (audit du 26/07).
    systeme = platform.system()
    if systeme not in ("Windows", "Linux"):
        print(f"`netverdict capture` ne gere que Windows et Linux "
              f"(detecte : {systeme or 'inconnu'}).\n"
              f"Capturer avec l'outil natif du systeme, puis analyser :\n"
              f"  sudo tcpdump -i <interface> -s 96 -w capture.pcap\n"
              f"  netverdict analyze capture.pcap", file=sys.stderr)
        return 2
    here = Path(__file__).parent / "capture"
    if systeme == "Windows":
        script = here / "capture.ps1"
        cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
               "-File", str(script)]
        if args.duration:
            cmd += ["-DurationSec", str(args.duration)]
        if args.out:
            cmd += ["-OutDir", str(args.out)]
    else:
        script = here / "capture.sh"
        cmd = ["bash", str(script)]
        if args.duration:
            cmd += ["-d", str(args.duration)]
        if args.out:
            cmd += ["-o", str(args.out)]
    if not script.exists():
        print(f"Script de capture introuvable : {script}", file=sys.stderr)
        return 2
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        # bash absent (Alpine/busybox, image distroless) ou powershell hors
        # du PATH : un traceback nu n'aide personne.
        print(f"Interpreteur introuvable : `{cmd[0]}` n'est pas installe ou "
              f"absent du PATH.", file=sys.stderr)
        return 2


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules.engine import load_rules, RuleError
    try:
        rules = load_rules(args.rules)
    except RuleError as e:
        print(f"Erreur dans les regles : {e}", file=sys.stderr)
        return 2
    for r in sorted(rules, key=lambda x: -x.priority):
        print(f"{r.priority:>3}  {r.verdict:<7} {r.id:<22} {r.title}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # Sortie en UTF-8, quelle que soit la console. Sans ca, sous Windows, un
    # stdout redirige encode en cp1252 : une donnee LINUX parfaitement banale
    # (hostname non latin-1, message syslog, proctitle auditd) faisait lever
    # UnicodeEncodeError en plein print. Le JSON etant emis en UN SEUL print,
    # le fichier de sortie faisait 0 OCTET et le process rendait 1 — le meme
    # code que « des verdicts ont ete trouves » : un script appelant ne pouvait
    # pas distinguer un probleme trouve d'un rapport perdu (audit du 26/07).
    # errors="replace" plutot que strict : mieux vaut un caractere de
    # remplacement qu'un rapport perdu.
    for flux in (sys.stdout, sys.stderr):
        try:
            flux.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass          # flux remplace par un test ou non reconfigurable
    p = argparse.ArgumentParser(
        prog="netverdict",
        description="Triage d'incident : la capture dit si c'est le reseau, "
                    "l'application ou le systeme — avec preuves.",
    )
    p.add_argument("--version", action="version", version=f"netverdict {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    pa = sub.add_parser("analyze", help="Analyse un pcap/pcapng et rend les verdicts")
    pa.add_argument("capture", help="Fichier .pcap ou .pcapng (pour un .etl Windows : "
                                    "pktmon etl2pcap d'abord)")
    pa.add_argument("--snapshot", help="snapshot.json d'etat hote pris pendant la capture")
    pa.add_argument("--events", action="append", default=[],
                    help="Events Windows : .evtx ou export XML wevtutil "
                         "(cumulable) — alimente la timeline des changements")
    pa.add_argument("--syslog", action="append", default=[],
                    help="Fichier syslog plat (cumulable) — alimente la "
                         "timeline des changements")
    pa.add_argument("--audit", action="append", default=[],
                    help="Journal auditd Linux (/var/log/audit/audit.log, "
                         "cumulable) — retrouve le process d'un flux meme "
                         "deja mort (parite Linux de Sysmon)")
    pa.add_argument("--syslog-tz", metavar="FUSEAU",
                    help="Fuseau des lignes RFC3164 (sans fuseau dans le "
                         "format) : UTC, un decalage fixe (+02:00) ou un nom "
                         "IANA (Europe/Paris). Par defaut : fuseau du poste "
                         "d'analyse, ce qui decale un syslog central en UTC "
                         "hors de la fenetre de la capture. Sans effet sur "
                         "les lignes RFC5424, qui portent leur propre fuseau")
    pa.add_argument("--rules", action="append", default=[],
                    help="Fichier YAML de regles additionnelles (cumulable)")
    pa.add_argument("--json", action="store_true", help="Sortie JSON complete")
    pa.add_argument("--top", type=int, default=10,
                    help="Nombre max de conversations detaillees (defaut 10)")
    pa.add_argument("--explain", action="store_true",
                    help="Ajoute une synthese narrative via l'API Claude "
                         "(optionnel, n'envoie que le rapport, jamais le pcap)")
    pa.set_defaults(func=cmd_analyze)

    pc = sub.add_parser("capture", help="Capture assistee : trafic + etat hote en un coup")
    pc.add_argument("--duration", type=int, help="Duree de capture en secondes (defaut 60)")
    pc.add_argument("--out", help="Dossier de sortie du bundle")
    pc.set_defaults(func=cmd_capture)

    pr = sub.add_parser("rules", help="Liste les regles de verdict chargees")
    pr.add_argument("--rules", action="append", default=[],
                    help="Fichier YAML de regles additionnelles (cumulable)")
    pr.set_defaults(func=cmd_rules)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
