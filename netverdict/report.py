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


def render_console(cap: Capture, verdicts: list[FlowVerdict],
                   snapshot: Optional[HostSnapshot] = None,
                   top: int = 10, console: Optional[Console] = None) -> None:
    con = console or Console()
    st = cap.stats

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
        if not s.direction_confident:
            body.append("  * sens client/serveur estime (pas de SYN dans la "
                        "capture) : lire les roles avec prudence\n", style="dim")
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
            snapshot: Optional[HostSnapshot] = None) -> str:
    st = cap.stats
    out = {
        "netverdict": 1,
        "stats": {"packets": st.total, "tcp": st.tcp, "icmp": st.icmp,
                  "non_ip": st.non_ip, "parse_errors": st.parse_errors,
                  "linktype": st.linktype},
        "flows": [],
    }
    for fv in verdicts:
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
        out["flows"].append(entry)
    return json.dumps(out, indent=2, ensure_ascii=False)
