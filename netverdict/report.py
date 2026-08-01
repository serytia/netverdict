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

from .i18n import DEFAULT_LANG, t
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


def verdict_label(verdict: str, lang: str = DEFAULT_LANG) -> str:
    """Etiquette AFFICHEE d'un jeton de verdict.

    Le jeton (RESEAU, HOTE...) reste identique dans le YAML, le JSON et le code
    de retour : c'est un identifiant. Seule cette etiquette suit la langue —
    sinon un script qui teste `verdict == "RESEAU"` casserait en silence des
    qu'on change de langue (voir i18n.py)."""
    return t(f"verdict.{verdict}", lang)


def conf_label(confidence: str, lang: str = DEFAULT_LANG) -> str:
    """Idem pour `confidence`. Une valeur sans etiquette dans cette langue sort
    TELLE QUELLE : c'est le comportement historique de `faible` cote francais
    (jamais traduit depuis la v1), et une regle utilisateur peut de toute facon
    inventer sa propre valeur."""
    cle = f"conf.{confidence}"
    libelle = t(cle, lang)
    return confidence if libelle == cle else libelle


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
                    con: Console, windowed: bool, top: int = 10,
                    lang: str = DEFAULT_LANG) -> None:
    """Section « qu'est-ce qui a change » : les changements d'infra de la
    fenetre, les plus recents d'abord. On TRIE par pertinence, on ne conclut
    pas a la causalite — un changement qui precede l'incident est un suspect
    a verifier, pas un coupable.

    Appelee DES QUE des sources ont ete fournies, meme si la fenetre est
    vide : le silence est le pire des rapports quand l'admin a donne des
    logs a lire (il conclurait « rien n'a change » au lieu de « rien n'a
    ete retenu/lu »)."""
    entete = ("timeline.header_windowed" if windowed
              else "timeline.header_unwindowed")
    con.print(Text(t(entete, lang), style="bold"))
    changes = tl.changes()
    if not changes:
        con.print(Text("  " + t("timeline.no_change", lang), style="dim"))
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
                line.append(t("timeline.precedes", lang, delta=delta),
                            style="bold yellow")
            else:
                line.append(t("timeline.precedes_approx", lang,
                              delta=max(1, round(delta / 60))),
                            style="bold yellow")
        con.print(line)
    if len(changes) > top:
        con.print(Text("  " + t("timeline.more_changes", lang,
                                n=len(changes) - top), style="dim"))
    # O(n) par categorie — jamais de comparaison d'objets sur les listes
    # completes (quadratique sur un gros syslog central).
    from .timeline import CHANGE_CATEGORIES
    errors = sum(1 for e in tl.events
                 if e.category not in CHANGE_CATEGORIES and e.severity >= 2)
    if errors:
        con.print(Text("  " + t("timeline.other_errors", lang, n=errors),
                       style="dim"))
    for name, st in tl.stats.items():
        note = t("timeline.entries_read", lang, parsed=st.parsed,
                 total=st.total_lines)
        if st.unparsed:
            note += t("timeline.entries_unreadable", lang, n=st.unparsed)
        con.print(Text(f"  {name}: {note}", style="dim"))
        if st.note:
            # Avertissement actionnable du parseur : en evidence, pas en dim —
            # c'est la difference entre une capacite inerte et une absente.
            con.print(Text(f"  {name}: {st.note}", style="bold yellow"))
    con.print()


def render_console(cap: Capture, verdicts: list[FlowVerdict],
                   snapshot: Optional[HostSnapshot] = None,
                   top: int = 10, console: Optional[Console] = None,
                   timeline: Optional[Timeline] = None,
                   lang: str = DEFAULT_LANG) -> None:
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
    con.print(Text(t("report.header", lang, total=st.total, tcp=st.tcp,
                     icmp=st.icmp, non_ip=st.non_ip, errors=st.parse_errors,
                     flows=len(verdicts)), style="dim"))
    # Honnetete de la mesure : une capture largement illisible ou tronquee
    # doit se voir AVANT les verdicts qu'elle affaiblit.
    if st.total and st.parse_errors / st.total > 0.05:
        con.print(Text(t("report.warn_parse_errors", lang,
                         errors=st.parse_errors, total=st.total),
                       style="bold red"))
    if st.unsupported_linktype:
        con.print(Text(t("report.warn_linktype", lang), style="bold red"))
    if st.mixed_linktypes:
        con.print(Text(t("report.warn_mixed_linktypes", lang),
                       style="bold red"))

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
        body.append(f"{m.title}\n", style="bold")
        for ev in m.evidence:
            body.append(f"  * {ev}\n")
        if snapshot:
            ctx = snapshot.context_for(s)
            if ctx and ctx.summary(lang):
                body.append(f"  * {t('report.host_state', lang)}"
                            f"{ctx.summary(lang)}\n", style="cyan")
        # Attribution RETROACTIVE : contrairement au snapshot, elle retrouve
        # aussi un process deja mort a la fin de la capture.
        attr = process_par_flux.get(position_de.get(id(fv), -1))
        if attr:
            body.append(f"  * {t('report.process_retro', lang)}"
                        f"{attr.describe(lang)}\n", style="cyan")
        if not s.direction_confident:
            body.append(f"  * {t('report.direction_unsure', lang)}\n",
                        style="dim")
        # Changements d'infra rattaches a CE flux. Place avant la piste de
        # correction : c'est souvent la reponse la plus rapide, et c'est la
        # que l'admin regarde. Vocabulaire du SOUPCON, jamais de la cause.
        mes_suspects = suspects_par_flux.get(position_de.get(id(fv), -1), [])
        if mes_suspects:
            body.append(f"\n{t('report.suspects_header', lang)}\n",
                        style="bold")
            for sp in mes_suspects:
                e = sp.event
                marque = "*" if sp.affinity else "-"
                body.append(f"  {marque} {_fmt_ts(e.ts, e.tz_known)} "
                            f"[{e.category}] {e.host} — {e.message} "
                            f"({sp.describe(lang)})\n",
                            style="yellow" if sp.affinity else "")
            if any(sp.affinity for sp in mes_suspects):
                body.append(f"    {t('report.suspects_legend', lang)}\n",
                            style="dim")

        if m.remediation:
            body.append(f"\n{t('report.fix_header', lang)}\n", style="bold")
            for line in m.remediation.splitlines():
                body.append(f"  {line}\n")
        # Une regle RAS n'est jamais listee en signal secondaire : son titre
        # affirme « le probleme n'est pas dans cette conversation reseau », ce
        # qui contredit mot pour mot le verdict imprime juste au-dessus. Sur les
        # captures netem du lab, un flux a gigue franche sortait « RESEAU [...]
        # Signaux secondaires : clean (RAS) » — l'admin ne peut pas savoir
        # laquelle des deux lignes croire. Le match reste expose en JSON, qui
        # porte aussi le verdict faisant autorite.
        secondary = [x for x in fv.matches[1:] if x.verdict != "RAS"]
        if secondary:
            body.append(f"\n{t('report.secondary', lang)}", style="dim")
            body.append(", ".join(
                f"{x.rule.id} ({verdict_label(x.verdict, lang)})"
                for x in secondary), style="dim")
            body.append("\n")

        title = Text()
        title.append(f" {verdict_label(m.verdict, lang)} ", style=style)
        title.append(f"— {s.client}:{s.cport} -> {s.server}:{s.sport} ")
        title.append(f"[{conf_label(m.rule.confidence, lang)}]", style="dim")
        con.print(Panel(body, title=title, border_style=style.split()[-1]))

    if timeline is not None:
        # L'« incident » = debut du premier flux a verdict non-RAS : les
        # changements qui le precedent de peu sont les suspects a verifier.
        incident_ts = min((fv.signals.t_first for fv in ordered
                           if fv.primary and fv.verdict != "RAS"),
                          default=None)
        con.print()
        render_timeline(timeline, incident_ts, con,
                        windowed=timeline.windowed, top=top, lang=lang)

    hidden = sum(1 for fv in ordered
                 if fv.primary and fv.verdict != "RAS") - shown
    if hidden > 0:
        con.print(Text(t("report.hidden_flows", lang, n=hidden), style="dim"))
    if ras_flows:
        con.print(Text(t("report.healthy_flows", lang,
                         label=verdict_label("RAS", lang), n=len(ras_flows)),
                       style="green"))
    if silent:
        con.print(Text(t("report.silent_flows", lang, n=silent), style="dim"))
    con.print()


def to_json(cap: Capture, verdicts: list[FlowVerdict],
            snapshot: Optional[HostSnapshot] = None,
            timeline: Optional[Timeline] = None,
            lang: str = DEFAULT_LANG) -> str:
    """Rapport machine.

    Les CLES et les JETONS (verdict, confidence, side) ne suivent PAS la
    langue : un script qui filtre sur `verdict == "RESEAU"` doit continuer a
    marcher quelle que soit --lang. Seule la PROSE (title, evidence,
    remediation) est localisee — c'est aussi elle que --explain relit."""
    st = cap.stats
    from .correlate import attributions, correlate
    suspects_par_flux = correlate(verdicts, timeline)
    process_par_flux = attributions(verdicts, timeline)
    out = {
        "netverdict": 1,
        "stats": {"packets": st.total, "tcp": st.tcp, "icmp": st.icmp,
                  "non_ip": st.non_ip, "parse_errors": st.parse_errors,
                  "linktype": st.linktype,
                  "mixed_linktypes": st.mixed_linktypes},
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
                "title": m.title,
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
                # False = rapproche sur la destination seule (auditd) : un
                # consommateur machine doit pouvoir ponderer cette attribution
                # plus faible sans avoir a lire la phrase du rapport.
                "exact": attr.exact,
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
                          "unparsed": v.unparsed, "note": v.note}
                      for k, v in timeline.stats.items()},
        }
    return json.dumps(out, indent=2, ensure_ascii=False)
