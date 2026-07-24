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

    if args.json:
        print(to_json(cap, verdicts, snapshot))
    else:
        render_console(cap, verdicts, snapshot, top=args.top)

    if args.explain:
        from .explain import explain, ExplainUnavailable
        try:
            print(explain(to_json(cap, verdicts, snapshot)))
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
    here = Path(__file__).parent.parent / "capture"
    if platform.system() == "Windows":
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
    return subprocess.call(cmd)


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
