"""Restitution : verdicts -> console (rich) et JSON.

Ordre d'affichage = ordre d'action pour l'admin : les verdicts les plus
prioritaires d'abord, les flux sains agreges en une ligne a la fin.
La preuve est TOUJOURS montree avec le verdict — un verdict sans preuve
est une opinion, et l'outil ne vend pas des opinions.
"""

from __future__ import annotations

import json
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from .pcap import Capture
from .rules.engine import FlowVerdict
from .hostsnap import HostSnapshot
from .timeline import Timeline

VERDICT_STYLE = {
    "RESEAU": "bold red",
    "APP": "bold yellow",
    "OS": "bold magenta",
    "HOTE": "bold magenta",
    "AMBIGU": "bold cyan",
    "RAS": "bold green",
}

CONF_LABEL = {"haute": "confiance haute", "moyenne": "confiance moyenne",
              "basse": "confiance basse"}


def _sort_key(fv: FlowVerdict) -> tuple:
    if fv.primary is None:
        return (2, 0)
    if fv.verdict == "RAS":
        return (1, -fv.primary.rule.priority)
    return (0, -fv.primary.rule.priority)


def _fmt_ts(ts: float, tz_known: bool) -> str:
    """Heure locale lisible ; '~' devant si le fuseau source etait inconnu
    (RFC3164) — l'admin doit savoir que la minute peut etre fausse.

    Jamais via datetime.fromtimestamp(ts) directement : sous Windows il leve
    OSError pour tout ts negatif (pcap a l'epoch 1970, SystemTime 1601 d'un
    FILETIME vide) et le rapport entier planterait sur UN horodatage pourri.
    """
    from datetime import datetime, timedelta, timezone
    mark = "" if tz_known else "~"
    try:
        dt = (datetime(1970, 1, 1, tzinfo=timezone.utc)
              + timedelta(seconds=ts)).astimezone()
        return mark + dt.strftime("%H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return f"{mark}@{ts:.0f}"


def render_timeline(tl: Timeline, incident_ts: Optional[float],
                    con: Console, windowed: bool, top: int = 10) -> None:
    """Section « qu'est-ce qui a change » : les changements d'infra de la
    fenetre, les plus recents d'abord. On TRIE par pertinence, on ne conclut
    pas a la causalite — un changement qui precede l'incident est un suspect
    a verifier, pas un coupable.

    Appelee DES QUE des sources ont ete fournies, meme si la fenetre est
    vide : le silence est le pire des rapports quand l'admin a donne des
    logs a lire (il conclurait « rien n'a change » au lieu de « rien n'a
    ete retenu/lu »)."""
    if windowed:
        con.print(Text("Changements dans l'infra (fenetre de la capture) :",
                       style="bold"))
    else:
        con.print(Text("Changements dans l'infra — fenetre NON appliquee "
                       "(capture sans paquet TCP date) :", style="bold"))
    changes = tl.changes()
    if not changes:
        con.print(Text("  aucun changement detecte dans la fenetre — les "
                       "sources fournies n'expliquent pas l'incident par un "
                       "changement recent", style="dim"))
    for e in changes[:top]:
        line = Text()
        line.append(f"  {_fmt_ts(e.ts, e.tz_known)}  ")
        line.append(f"[{e.category}] ", style="bold cyan")
        line.append(f"{e.host} — {e.message} ")
        line.append(f"({e.source}:{e.ident})", style="dim")
        # Suspect : changement qui precede de peu le debut de l'incident.
        # Sur un timestamp sans fuseau fiable, pas de delta a la seconde :
        # afficher une precision qu'on n'a pas serait mentir.
        if incident_ts is not None and 0 <= incident_ts - e.ts <= 300:
            delta = incident_ts - e.ts
            if e.tz_known:
                line.append(f"  << precede l'incident de {delta:.0f}s",
                            style="bold yellow")
            else:
                line.append(f"  << precede l'incident d'environ "
                            f"{max(1, round(delta / 60)):.0f} min (heure "
                            f"source approximative)", style="bold yellow")
        con.print(line)
    if len(changes) > top:
        con.print(Text(f"  ... {len(changes) - top} autre(s) changement(s) "
                       f"masque(s) — --top pour en voir plus", style="dim"))
    # O(n) par categorie — jamais de comparaison d'objets sur les listes
    # completes (quadratique sur un gros syslog central).
    from .timeline import CHANGE_CATEGORIES
    errors = sum(1 for e in tl.events
                 if e.category not in CHANGE_CATEGORIES and e.severity >= 2)
    if errors:
        con.print(Text(f"  + {errors} erreur(s) hors changement dans "
                       f"la fenetre (--json pour le detail)", style="dim"))
    for name, st in tl.stats.items():
        note = f"{st.parsed}/{st.total_lines} entrees lues"
        if st.unparsed:
            note += f", {st.unparsed} illisibles"
        con.print(Text(f"  {name}: {note}", style="dim"))
    con.print()


def render_console(cap: Capture, verdicts: list[FlowVerdict],
                   snapshot: Optional[HostSnapshot] = None,
                   top: int = 10, console: Optional[Console] = None,
                   timeline: Optional[Timeline] = None) -> None:
    con = console or Console()
    st = cap.stats
    # Suspects rattaches a chaque flux. Indexe par position dans `verdicts`,
    # avant tout tri d'affichage — l'ordre d'affichage ne doit pas changer
    # l'association flux <-> suspects.
    from .correlate import attributions, correlate
    suspects_par_flux = correlate(verdicts, timeline)
    process_par_flux = attributions(verdicts, timeline)
    position_de = {id(fv): i for i, fv in enumerate(verdicts)}

    con.print()
    header = (f"{st.total} paquets lus — {st.tcp} TCP, {st.icmp} ICMP, "
              f"{st.non_ip} non-IP, {st.parse_errors} illisibles — "
              f"{len(verdicts)} conversations")
    con.print(Text(header, style="dim"))
    # Honnetete de la mesure : une capture largement illisible ou tronquee
    # doit se voir AVANT les verdicts qu'elle affaiblit.
    if st.total and st.parse_errors / st.total > 0.05:
        con.print(Text(f"attention : {st.parse_errors}/{st.total} paquets "
                       f"illisibles, les verdicts peuvent etre incomplets",
                       style="bold red"))
    if st.unsupported_linktype:
        con.print(Text("attention : linktype partiellement supporte, "
                       "des trames ont ete ignorees", style="bold red"))

    ordered = sorted(verdicts, key=_sort_key)
    shown = 0
    ras_flows: list[FlowVerdict] = []
    silent = 0

    for fv in ordered:
        if fv.primary is None:
            silent += 1
            continue
        if fv.verdict == "RAS":
            ras_flows.append(fv)
            continue
        if shown >= top:
            continue
        shown += 1
        s = fv.signals
        m = fv.primary
        style = VERDICT_STYLE.get(m.verdict, "bold")

        body = Text()
        body.append(f"{m.rule.title}\n", style="bold")
        for ev in m.evidence:
            body.append(f"  * {ev}\n")
        if snapshot:
            ctx = snapshot.context_for(s)
            if ctx and ctx.summary():
                body.append(f"  * etat hote : {ctx.summary()}\n", style="cyan")
        # Attribution RETROACTIVE : contrairement au snapshot, elle retrouve
        # aussi un process deja mort a la fin de la capture.
        attr = process_par_flux.get(position_de.get(id(fv), -1))
        if attr:
            body.append(f"  * process (journal, retroactif) : "
                        f"{attr.describe()}\n", style="cyan")
        if not s.direction_confident:
            body.append("  * sens client/serveur estime (pas de SYN dans la "
                        "capture) : lire les roles avec prudence\n", style="dim")
        # Changements d'infra rattaches a CE flux. Place avant la piste de
        # correction : c'est souvent la reponse la plus rapide, et c'est la
        # que l'admin regarde. Vocabulaire du SOUPCON, jamais de la cause.
        mes_suspects = suspects_par_flux.get(position_de.get(id(fv), -1), [])
        if mes_suspects:
            body.append("\nA verifier en premier (suspects, pas une cause "
                        "etablie) :\n", style="bold")
            for sp in mes_suspects:
                e = sp.event
                marque = "*" if sp.affinity else "-"
                body.append(f"  {marque} {_fmt_ts(e.ts, e.tz_known)} "
                            f"[{e.category}] {e.host} — {e.message} "
                            f"({sp.describe()})\n",
                            style="yellow" if sp.affinity else "")
            if any(sp.affinity for sp in mes_suspects):
                body.append("    * = type de changement pouvant produire ce "
                            "verdict\n", style="dim")

        if m.remediation:
            body.append("\nPiste de correction :\n", style="bold")
            for line in m.remediation.splitlines():
                body.append(f"  {line}\n")
        secondary = fv.matches[1:]
        if secondary:
            body.append("\nSignaux secondaires : ", style="dim")
            body.append(", ".join(f"{x.rule.id} ({x.verdict})"
                                  for x in secondary), style="dim")
            body.append("\n")

        title = Text()
        title.append(f" {m.verdict} ", style=style)
        title.append(f"— {s.client}:{s.cport} -> {s.server}:{s.sport} ")
        title.append(f"[{CONF_LABEL.get(m.rule.confidence, m.rule.confidence)}]",
                     style="dim")
        con.print(Panel(body, title=title, border_style=style.split()[-1]))

    if timeline is not None:
        # L'« incident » = debut du premier flux a verdict non-RAS : les
        # changements qui le precedent de peu sont les suspects a verifier.
        incident_ts = min((fv.signals.t_first for fv in ordered
                           if fv.primary and fv.verdict != "RAS"),
                          default=None)
        con.print()
        render_timeline(timeline, incident_ts, con,
                        windowed=timeline.windowed, top=top)

    hidden = sum(1 for fv in ordered
                 if fv.primary and fv.verdict != "RAS") - shown
    if hidden > 0:
        con.print(Text(f"... {hidden} autre(s) conversation(s) avec verdict "
                       f"masquee(s) — utiliser --top pour en voir plus",
                       style="dim"))
    if ras_flows:
        con.print(Text(f"[RAS] {len(ras_flows)} conversation(s) au transport "
                       f"sain", style="green"))
    if silent:
        con.print(Text(f"{silent} conversation(s) anodine(s) (trop peu de "
                       f"trafic pour juger)", style="dim"))
    con.print()


def to_json(cap: Capture, verdicts: list[FlowVerdict],
            snapshot: Optional[HostSnapshot] = None,
            timeline: Optional[Timeline] = None) -> str:
    st = cap.stats
    from .correlate import attributions, correlate
    suspects_par_flux = correlate(verdicts, timeline)
    process_par_flux = attributions(verdicts, timeline)
    out = {
        "netverdict": 1,
        "stats": {"packets": st.total, "tcp": st.tcp, "icmp": st.icmp,
                  "non_ip": st.non_ip, "parse_errors": st.parse_errors,
                  "linktype": st.linktype},
        "flows": [],
    }
    for index, fv in enumerate(verdicts):
        s = fv.signals
        entry = {
            "flow": f"{s.client}:{s.cport}->{s.server}:{s.sport}",
            "verdict": fv.verdict if fv.primary else None,
            "signals": s.as_dict(),
            "matches": [{
                "rule": m.rule.id,
                "verdict": m.verdict,
                "priority": m.rule.priority,
                "confidence": m.rule.confidence,
                "title": m.rule.title,
                "evidence": m.evidence,
                "remediation": m.remediation,
            } for m in fv.matches],
        }
        if snapshot:
            ctx = snapshot.context_for(s)
            if ctx:
                entry["host_context"] = {
                    "host": ctx.host, "process": ctx.process, "pid": ctx.pid,
                    "cpu_pct": ctx.cpu_pct, "disk_busy_pct": ctx.disk_busy_pct,
                    "process_cpu_pct": ctx.process_cpu_pct,
                }
        # Suspects rattaches a ce flux. `affinity` et `during_flow` sont
        # exposes pour qu'un consommateur machine puisse ponderer lui-meme —
        # et le nom du champ dit qu'il s'agit de suspects, pas de causes.
        if attr := process_par_flux.get(index):
            c = attr.connection
            entry["process_attribution"] = {
                "source": attr.event.source,
                "retroactive": True,
                "side": attr.side,
                "candidates": attr.candidates,
                "pid": c.pid,
                "image": c.image,
                "user": c.user,
                "protocol": c.protocol,
                "initiated": c.initiated,
                "ts": attr.event.ts,
            }
        if suspects := suspects_par_flux.get(index):
            entry["suspects"] = [{
                "ts": sp.event.ts,
                "delay_s": sp.delay_s,
                "during_flow": sp.during_flow,
                "affinity": sp.affinity,
                "tz_known": sp.event.tz_known,
                "source": sp.event.source,
                "host": sp.event.host,
                "category": sp.event.category,
                "ident": sp.event.ident,
                "message": sp.event.message,
            } for sp in suspects]
        out["flows"].append(entry)
    if timeline is not None:
        out["timeline"] = {
            "windowed": timeline.windowed,
            "events": [{
                "ts": e.ts, "source": e.source, "host": e.host,
                "category": e.category, "severity": e.severity,
                "ident": e.ident, "message": e.message,
                "tz_known": e.tz_known,
            } for e in timeline.events],
            "stats": {k: {"total_lines": v.total_lines, "parsed": v.parsed,
                          "unparsed": v.unparsed}
                      for k, v in timeline.stats.items()},
        }
    return json.dumps(out, indent=2, ensure_ascii=False)
