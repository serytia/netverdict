"""Point d'entree CLI : netverdict analyze | capture | rules."""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
from pathlib import Path

from . import __version__
from .i18n import LANGS, resolve_lang, t


def cmd_analyze(args: argparse.Namespace) -> int:
    from .pcap import read_capture
    from .flows import build_flows
    from .signals import compute_signals
    from .rules.engine import (load_rules, load_dns_rules, load_udp_rules,
                               evaluate, evaluate_dns, evaluate_udp, RuleError)
    from .report import render_console, to_json
    from .dns import (MDNS_PORT, build_resolutions, compute_dns_signals,
                      link_flows, parse_dns_over_tcp, reassemble_stream)
    from .udp import build_udp_conversations, compute_udp_signals
    from .hostsnap import HostSnapshot

    # Resolue AVANT tout : le premier message d'erreur possible doit deja
    # sortir dans la bonne langue.
    lang = resolve_lang(args.lang)

    try:
        rules = load_rules(args.rules)
        dns_rules = load_dns_rules(args.rules)
        udp_rules = load_udp_rules(args.rules)
    except RuleError as e:
        print(t("err.rules", lang, e=e), file=sys.stderr)
        return 2

    try:
        cap = read_capture(args.capture, lang)
    except FileNotFoundError:
        print(t("err.file_not_found", lang, path=args.capture), file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{e}", file=sys.stderr)
        return 2

    flows = build_flows(cap)
    signals = [compute_signals(fl) for fl in flows]
    verdicts = evaluate(signals, rules, lang)

    # Etage DNS. Les flux TCP vers le port 53 sont passes au constructeur de
    # resolutions : ils repondent a la question « le client a-t-il rejoue sa
    # question en TCP apres une reponse tronquee ? », qui n'a pas de reponse
    # dans les datagrammes UDP seuls.
    # `established_seen` et non la simple existence du flux : au lab, un repli
    # TCP/53 reduit a deux SYN jetes par un pare-feu passait pour un repli
    # reussi, et le verdict disparaissait dans le cas meme qu'il vise.
    tcp53 = [(s.t_first, s.client, s.server, s.established_seen)
             for s in signals if s.sport == 53]
    # Messages DNS transportes par TCP/53 : ils s'ajoutent aux datagrammes,
    # dans la meme liste. Une reponse tronquee puis rejouee en TCP forme ainsi
    # UNE resolution, et son aboutissement est visible au lieu d'etre suppose.
    msgs = list(cap.dns_msgs)
    for fl in flows:
        if fl.sport != 53:
            continue
        for du_client in (True, False):
            segs = [(op.pkt.seq, op.pkt.payload) for op in fl.pkts
                    if op.from_client is du_client and op.pkt.payload]
            if not segs:
                continue
            flux, complet = reassemble_stream(segs)
            t0 = next(op.pkt.ts for op in fl.pkts
                      if op.from_client is du_client and op.pkt.payload)
            src, dst = ((fl.client, fl.server) if du_client
                        else (fl.server, fl.client))
            sp, dp = ((fl.cport, fl.sport) if du_client
                      else (fl.sport, fl.cport))
            msgs.extend(parse_dns_over_tcp(t0, src, dst, sp, dp, flux, complet))
    resolutions = build_resolutions(msgs, cap.t_last_seen, tcp53)
    dns_verdicts = evaluate_dns(
        [compute_dns_signals(r, cap.t_last_seen) for r in resolutions],
        dns_rules, lang)
    dns_links = link_flows(
        resolutions,
        [(i, s.server, s.t_first, s.client) for i, s in enumerate(signals)])

    # Etage UDP. Il couvre TOUT l'UDP, DNS compris, mais se tait sur les
    # conversations dont l'etage DNS a su tirer une resolution : ses verdicts
    # y sont plus precis. L'inverse aurait laisse un trou - un DNS dont le nom
    # est illisible (snaplen) ne produit aucune resolution, et personne
    # n'aurait alors rien dit du silence de son resolveur.
    # La cle porte le PORT SERVEUR et TOUS les resolveurs essayes. Sans le
    # port, une simple resolution entre deux machines suffisait a marquer
    # `dns_handled` sur TOUTE conversation UDP entre ces deux machines - le
    # NTP, le RADIUS ou le syslog vers le meme serveur devenaient muets. Sans
    # la totalite des resolveurs, un client a deux nameservers ne voyait
    # couvert que le premier (revue du 15/08/2026).
    conversations = build_udp_conversations(cap)
    couvert_par_dns = {(r.client, srv, port)
                       for r in resolutions if r.attempts
                       for srv in r.resolvers
                       for port in (53, MDNS_PORT)}
    udp_verdicts = evaluate_udp(
        [compute_udp_signals(
            c, dns_handled=(c.client, c.server, c.sport) in couvert_par_dns)
         for c in conversations],
        udp_rules, lang)

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
            print(t("err.syslog_tz_needs_syslog", lang), file=sys.stderr)
            return 2
        from .sources.syslog import parse_tz
        try:
            syslog_tz = parse_tz(args.syslog_tz, lang)
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
                evs, st = evtx.parse(path, lang)
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
                                           tz=syslog_tz, lang=lang)
            except (ValueError, OSError) as e:
                print(f"--syslog {path}: {e}", file=sys.stderr)
                return 2
            timeline.add_source(f"syslog:{Path(path).name}", evs, st)
        for path in args.audit:
            from .sources import auditd
            try:
                evs, st = auditd.parse(path, lang)
            except (ValueError, OSError) as e:
                print(f"--audit {path}: {e}", file=sys.stderr)
                return 2
            timeline.add_source(f"audit:{Path(path).name}", evs, st)
        # Fenetre : les changements des 15 min qui precedent la capture ;
        # rien apres sa fin ne peut expliquer ce qu'elle contient.
        timeline = timeline.window(cap.t_first, cap.t_last)

    if args.json:
        print(to_json(cap, verdicts, snapshot, timeline, lang,
                      dns_verdicts=dns_verdicts, dns_links=dns_links,
                      udp_verdicts=udp_verdicts))
    else:
        render_console(cap, verdicts, snapshot, top=args.top,
                       timeline=timeline, lang=lang,
                       dns_verdicts=dns_verdicts, dns_links=dns_links,
                       udp_verdicts=udp_verdicts)

    if args.explain:
        from .explain import explain, ExplainUnavailable
        try:
            # Le MEME rapport que celui rendu a l'utilisateur, etages DNS et
            # UDP compris : sans eux, la synthese narrative expliquerait une
            # capture dont elle ignore la resolution de nom qui a coute deux
            # secondes - et elle le ferait avec aplomb.
            print(explain(to_json(cap, verdicts, snapshot, timeline, lang,
                                  dns_verdicts=dns_verdicts,
                                  dns_links=dns_links,
                                  udp_verdicts=udp_verdicts),
                          lang))
            print()
        except ExplainUnavailable as e:
            print(t("explain.unavailable", lang, e=e), file=sys.stderr)

    # Code retour utilisable en script : 0 = rien d'anormal, 1 = au moins un
    # verdict non-RAS (meme convention que grep : "trouve" vs "rien trouve").
    # Les verdicts DNS comptent AUTANT que ceux des flux : une resolution de
    # 2,4 s devant des connexions saines rendait 0, et toute supervision
    # branchee sur ce code lisait « rien d'anormal » pendant que l'utilisateur
    # attendait. Le silence en console avait ete corrige ; celui-ci, plus
    # discret encore, ne se voit que d'un script.
    problematic = (any(fv.primary and fv.verdict != "RAS" for fv in verdicts)
                   or any(dv.primary and dv.verdict != "RAS"
                          for dv in dns_verdicts)
                   or any(uv.primary and uv.verdict != "RAS"
                          for uv in udp_verdicts))
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
    lang = resolve_lang(args.lang)
    systeme = platform.system()
    if systeme not in ("Windows", "Linux"):
        print(t("err.capture_unsupported_os", lang,
                systeme=systeme or t("err.capture_os_unknown", lang)),
              file=sys.stderr)
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
        print(t("err.capture_script_missing", lang, path=script),
              file=sys.stderr)
        return 2
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        # bash absent (Alpine/busybox, image distroless) ou powershell hors
        # du PATH : un traceback nu n'aide personne.
        print(t("err.interpreter_missing", lang, cmd=cmd[0]), file=sys.stderr)
        return 2


def cmd_compare(args: argparse.Namespace) -> int:
    """Compare deux captures du meme trafic prises en deux points."""
    from rich.console import Console
    from rich.text import Text

    from .compare import comparer

    lang = resolve_lang(args.lang)

    try:
        resultats, diag = comparer(args.amont, args.aval, lang)
    except FileNotFoundError as e:
        print(t("err.file_not_found", lang, path=e.filename), file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"{e}", file=sys.stderr)
        return 2

    # En mode --json, RIEN d'autre ne doit sortir sur stdout : une seule
    # ligne de contexte suffit a rendre la sortie non parsable par le script
    # appelant. Les avertissements partent alors sur stderr.
    con = Console(file=sys.stderr if args.json else None)
    con.print()
    con.print(Text(t("compare.diag", lang, a=diag["flux_a"], b=diag["flux_b"],
                     communs=diag["flux_communs"]), style="dim"))
    if diag["nat_probable"]:
        con.print(Text(t("compare.nat", lang), style="bold red"))
        return 2
    if not resultats:
        con.print(Text(t("compare.no_common", lang), style="bold red"))
        return 2

    if args.json:
        import json
        print(json.dumps({
            "netverdict_compare": 1,
            "diagnostic": diag,
            "flux": [{
                "flow": str(c.cle),
                "verdict": c.verdict(lang)[0],
                "explication": c.verdict(lang)[1],
                "offset_horloge_s": c.offset_horloge_s,
                "latence_reseau_ms": c.latence_reseau_ms,
                "note": c.note,
                "sens": [{"sens": e.sens, "emis": e.segments_amont,
                          "retrouves": e.segments_aval, "perdus": e.perdus,
                          "taux_perte": round(e.taux_perte, 4)}
                         for e in c.ecarts],
            } for c in resultats],
        }, indent=2, ensure_ascii=False))
        return 1 if any(c.verdict(lang)[0] == "RESEAU" for c in resultats) else 0

    from .report import verdict_label
    couleurs = {"RESEAU": "bold red", "RAS": "bold green", "AMBIGU": "bold cyan"}
    for c in resultats[:args.top]:
        verdict, phrase = c.verdict(lang)
        con.print()
        con.print(Text(f" {verdict_label(verdict, lang)} ",
                       style=couleurs.get(verdict, "bold")),
                  Text(f"— {c.cle}"))
        con.print(Text(f"  {phrase}"))
        for e in c.ecarts:
            con.print(Text(t("compare.direction_line", lang, sens=e.sens,
                             amont=e.segments_amont, aval=e.segments_aval)
                           + (t("compare.lost", lang, n=e.perdus,
                                taux=e.taux_perte) if e.perdus else "")))
        if c.latence_reseau_ms is not None:
            con.print(Text(t("compare.latency", lang, ms=c.latence_reseau_ms),
                           style="dim"))
        if c.offset_horloge_s:
            con.print(Text(t("compare.clock_offset", lang,
                             s=c.offset_horloge_s), style="dim"))
        if c.note:
            con.print(Text(f"  ! {c.note}", style="yellow"))
    if len(resultats) > args.top:
        con.print(Text(t("compare.more_flows", lang,
                         n=len(resultats) - args.top), style="dim"))
    con.print()
    return 1 if any(c.verdict(lang)[0] == "RESEAU" for c in resultats) else 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules.engine import (load_rules, load_dns_rules, load_udp_rules,
                               RuleError)
    lang = resolve_lang(args.lang)
    try:
        # LES TROIS contrats, pas seulement les flux TCP. Cette commande sert a
        # ecrire des regles : n'en montrer qu'un tiers cachait l'existence des
        # scopes dns et udp, et surtout ne VALIDAIT pas les regles utilisateur
        # portant ces scopes - un `--rules` fautif restait donc muet ici avant
        # d'exploser au milieu d'une analyse (revue du 15/08/2026).
        rules = (load_rules(args.rules) + load_dns_rules(args.rules)
                 + load_udp_rules(args.rules))
    except RuleError as e:
        print(t("err.rules", lang, e=e), file=sys.stderr)
        return 2
    # Le JETON de verdict est garde tel quel ici, et non son libelle : cette
    # sortie sert a ecrire des regles (--rules), donc a manipuler des
    # identifiants. Seul le titre suit la langue.
    for r in sorted(rules, key=lambda x: (x.scope, -x.priority)):
        print(f"{r.scope:<5} {r.priority:>3}  {r.verdict:<7} {r.id:<30} "
              f"{r.title_for(lang)}")
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
    # L'aide elle-meme suit $NETVERDICT_LANG : argparse construit ses textes
    # AVANT de lire --lang, donc l'option ne peut pas traduire sa propre aide.
    # La variable d'environnement, elle, est lisible tout de suite.
    hlang = resolve_lang()
    p = argparse.ArgumentParser(
        prog="netverdict",
        description=t("help.description", hlang),
    )
    p.add_argument("--version", action="version", version=f"netverdict {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_lang(parser):
        # Sur CHAQUE sous-commande plutot qu'en global : `netverdict analyze
        # x.pcap --lang en` est l'ordre qu'on tape naturellement, et un
        # argument global devrait se placer avant la sous-commande.
        parser.add_argument("--lang", choices=list(LANGS), default=None,
                            help=t("help.lang", hlang))

    pa = sub.add_parser("analyze", help=t("help.analyze", hlang))
    pa.add_argument("capture", help=t("help.capture_arg", hlang))
    pa.add_argument("--snapshot", help=t("help.snapshot", hlang))
    pa.add_argument("--events", action="append", default=[],
                    help=t("help.events", hlang))
    pa.add_argument("--syslog", action="append", default=[],
                    help=t("help.syslog", hlang))
    pa.add_argument("--audit", action="append", default=[],
                    help=t("help.audit", hlang))
    pa.add_argument("--syslog-tz", metavar=t("help.syslog_tz_metavar", hlang),
                    help=t("help.syslog_tz", hlang))
    pa.add_argument("--rules", action="append", default=[],
                    help=t("help.rules", hlang))
    pa.add_argument("--json", action="store_true", help=t("help.json", hlang))
    pa.add_argument("--top", type=int, default=10, help=t("help.top", hlang))
    pa.add_argument("--explain", action="store_true",
                    help=t("help.explain", hlang))
    add_lang(pa)
    pa.set_defaults(func=cmd_analyze)

    pc = sub.add_parser("capture", help=t("help.capture", hlang))
    pc.add_argument("--duration", type=int, help=t("help.duration", hlang))
    pc.add_argument("--out", help=t("help.out", hlang))
    add_lang(pc)
    pc.set_defaults(func=cmd_capture)

    pcmp = sub.add_parser("compare", help=t("help.compare", hlang))
    pcmp.add_argument("amont", help=t("help.amont", hlang))
    pcmp.add_argument("aval", help=t("help.aval", hlang))
    pcmp.add_argument("--json", action="store_true",
                      help=t("help.compare_json", hlang))
    pcmp.add_argument("--top", type=int, default=10,
                      help=t("help.compare_top", hlang))
    add_lang(pcmp)
    pcmp.set_defaults(func=cmd_compare)

    pr = sub.add_parser("rules", help=t("help.rules_cmd", hlang))
    pr.add_argument("--rules", action="append", default=[],
                    help=t("help.rules", hlang))
    add_lang(pr)
    pr.set_defaults(func=cmd_rules)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
