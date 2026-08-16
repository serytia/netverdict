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

# Au-dela de cet ecart entre les DEUX derniers horodatages, le dernier paquet
# est un aberrant, pas la fin de la capture : une heure separe deja largement
# deux paquets d'une meme session, meme tres calme.
HORODATAGE_ABERRANT_S = 3600.0

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
                   lang: str = DEFAULT_LANG,
                   dns_verdicts: Optional[list] = None,
                   dns_links: Optional[dict] = None,
                   udp_verdicts: Optional[list] = None,
                   dns_orphelines: int = 0) -> None:
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
                     udp=st.udp, icmp=st.icmp, other=st.other_ip,
                     non_ip=st.non_ip, frags=st.fragments_skipped,
                     errors=st.parse_errors,
                     flows=len(verdicts)), style="dim"))
    # Honnetete de la mesure : une capture largement illisible ou tronquee
    # doit se voir AVANT les verdicts qu'elle affaiblit.
    if st.total and st.parse_errors / st.total > 0.05:
        con.print(Text(t("report.warn_parse_errors", lang,
                         errors=st.parse_errors, total=st.total),
                       style="bold red"))
    # Le DNS n'est pas une affaire de VOLUME : trois paquets peuvent porter
    # les deux secondes que l'utilisateur a subies, au milieu de dix mille
    # paquets TCP sains. Le seuil est donc "au moins un", pas un pourcentage.
    if dns_verdicts is None:
        # Appelant qui ne fait pas passer l'etage DNS : l'avertissement dit
        # alors la stricte verite pour CET appel.
        if st.udp_dns:
            con.print(Text(t("report.warn_dns_not_analyzed", lang, dns=st.udp_dns),
                           style="bold yellow"))
    elif st.udp_dns and not dns_verdicts:
        con.print(Text(t("report.warn_dns_no_resolution", lang, n=st.udp_dns),
                       style="bold yellow"))
    if st.dns_unreadable:
        con.print(Text(t("report.warn_dns_unreadable", lang, n=st.dns_unreadable),
                       style="bold yellow"))
    # Messages DNS lus mais rattaches a aucune resolution. Les taire faisait
    # affirmer « le serveur ne repond pas » avec la reponse dans la capture.
    # Un dernier paquet isole tres loin des autres : toutes les durees
    # calculees contre la fin de capture sont alors fausses.
    if (cap.t_last_seen is not None and cap.t_avant_dernier is not None
            and cap.t_last_seen - cap.t_avant_dernier > HORODATAGE_ABERRANT_S):
        con.print(Text(t("report.warn_horodatage", lang,
                         ecart=int(cap.t_last_seen - cap.t_avant_dernier)),
                       style="bold yellow"))
    if dns_orphelines:
        con.print(Text(t("report.warn_dns_orphelins", lang, n=dns_orphelines),
                       style="bold yellow"))
    if st.unsupported_linktype:
        con.print(Text(t("report.warn_linktype", lang), style="bold red"))
    if st.mixed_linktypes:
        con.print(Text(t("report.warn_mixed_linktypes", lang),
                       style="bold red"))

    # --- Resolutions DNS -----------------------------------------------
    # Placees AVANT les conversations, parce qu'elles les precedent : quand un
    # nom met deux secondes a se resoudre, la connexion qui suit peut etre
    # parfaitement saine et l'utilisateur avoir attendu quand meme. Les lire
    # apres reviendrait a lire l'histoire a l'envers.
    dns_links = dns_links or {}
    if dns_verdicts:
        # Cle (nom, CLIENT) et non le nom seul : sans le client, une
        # resolution EN ECHEC d'un poste se voyait crediter les connexions
        # faites par un AUTRE poste ayant resolu le meme nom. Le panneau se
        # contredisait alors lui-meme - « connexion(s) qui ont suivi : ... »
        # au-dessus de « la connexion qui devait suivre n'a donc jamais pu
        # commencer » (revue du 16/08/2026). C'est le meme defaut que celui
        # corrige dans link_flows la veille, reste ici.
        noms_vers_flux: dict[tuple, list[str]] = {}
        for index, lien in dns_links.items():
            if not lien.explains_delay or index >= len(verdicts):
                continue
            sf = verdicts[index].signals
            noms_vers_flux.setdefault((lien.qname, sf.client), []).append(
                f"{sf.server}:{sf.sport}")
        dns_sains = 0
        dns_muets = 0
        coupees = 0
        dns_caches = 0
        dns_affiches = 0
        entete_posee = False
        for dv in sorted(dns_verdicts, key=lambda d: d.signals.t_first):
            ds = dv.signals
            if ds.capture_truncated and not ds.answers_readable and ds.answered:
                coupees += 1
            # RAS et « aucune regle n'a matche » ne sont PAS la meme chose :
            # le premier est un verdict rendu, le second un silence. Les
            # confondre faisait annoncer « N resolutions saines » a propos de
            # resolutions dont l'outil n'avait rien su dire (revue du 15/08).
            if dv.primary is None:
                dns_muets += 1
                continue
            if dv.verdict == "RAS":
                dns_sains += 1
                continue
            if entete_posee and dns_affiches >= top:
                dns_caches += 1          # --top borne AUSSI cette section
                continue
            if not entete_posee:
                con.print()
                con.print(Text(t("report.dns_header", lang), style="bold"))
                entete_posee = True
            dns_affiches += 1
            m = dv.primary
            style = VERDICT_STYLE.get(m.verdict, "bold")
            body = Text()
            body.append(f"{m.title}\n", style="bold")
            for ev in m.evidence:
                body.append(f"  * {ev}\n")
            suivants = noms_vers_flux.get((ds.qname, ds.client))
            if suivants:
                body.append(f"  * {t('report.dns_leads_to', lang)}"
                            f"{', '.join(sorted(set(suivants)))}\n", style="cyan")
            if m.remediation:
                body.append(f"\n{t('report.fix_header', lang)}\n", style="bold")
                for line in m.remediation.splitlines():
                    body.append(f"  {line}\n")
            title = Text()
            title.append(f" {verdict_label(m.verdict, lang)} ", style=style)
            title.append(f"— DNS {ds.qname} ({ds.qtype}) ")
            title.append(f"[{conf_label(m.rule.confidence, lang)}]", style="dim")
            con.print(Panel(body, title=title, border_style=style.split()[-1]))
        if coupees:
            con.print(Text(t("report.dns_answers_unreadable", lang, n=coupees),
                           style="yellow"))
        if dns_sains:
            con.print(Text(t("report.dns_healthy", lang, n=dns_sains),
                           style="dim"))
        if dns_muets:
            con.print(Text(t("report.dns_silent", lang, n=dns_muets),
                           style="dim"))
        if dns_caches:
            con.print(Text(t("report.hidden_flows", lang, n=dns_caches),
                           style="dim"))

    # --- Conversations UDP ----------------------------------------------
    # Apres le DNS et avant le TCP : ce sont des echanges de meme nature que
    # les conversations TCP, mais l'etage est volontairement plus pauvre - un
    # datagramme ne prouve ni la reception, ni le sens, ni la perte.
    if udp_verdicts:
        udp_sains = 0
        udp_muets = 0
        udp_caches = 0
        udp_affiches = 0
        entete_posee = False
        for uv in sorted(udp_verdicts, key=lambda u: u.signals.t_first):
            us = uv.signals
            # Voir la section DNS : un silence n'est pas une sante. Les
            # conversations prises en charge par l'etage DNS sont exclues du
            # compte : les annoncer « sans verdict » alors qu'elles en ont
            # recu un, plus haut, contredit le rapport lui-meme.
            if uv.primary is None:
                if not us.dns_handled:
                    udp_muets += 1
                continue
            if uv.verdict == "RAS":
                udp_sains += 1
                continue
            if entete_posee and udp_affiches >= top:
                udp_caches += 1
                continue
            if not entete_posee:
                con.print()
                con.print(Text(t("report.udp_header", lang), style="bold"))
                entete_posee = True
            udp_affiches += 1
            m = uv.primary
            style = VERDICT_STYLE.get(m.verdict, "bold")
            body = Text()
            body.append(f"{m.title}\n", style="bold")
            for ev in m.evidence:
                body.append(f"  * {ev}\n")
            if us.expects_reply:
                body.append(f"  * {t('report.udp_unidirectional_hint', lang, sport=us.sport, service=us.service_hint)}\n",
                            style="cyan")
            if not us.direction_confident:
                body.append(f"  * {t('report.udp_direction_unsure', lang)}\n",
                            style="dim")
            if m.remediation:
                body.append(f"\n{t('report.fix_header', lang)}\n", style="bold")
                for line in m.remediation.splitlines():
                    body.append(f"  {line}\n")
            title = Text()
            title.append(f" {verdict_label(m.verdict, lang)} ", style=style)
            title.append(f"— UDP {us.client}:{us.cport} -> {us.server}:{us.sport} ")
            title.append(f"[{conf_label(m.rule.confidence, lang)}]", style="dim")
            con.print(Panel(body, title=title, border_style=style.split()[-1]))
        if udp_sains:
            con.print(Text(t("report.udp_healthy", lang, n=udp_sains),
                           style="dim"))
        if udp_muets:
            con.print(Text(t("report.udp_silent", lang, n=udp_muets),
                           style="dim"))
        if udp_caches:
            con.print(Text(t("report.hidden_flows", lang, n=udp_caches),
                           style="dim"))

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
        # Le nom qui a produit cette connexion, et - seulement s'il la precede
        # immediatement - le temps que sa resolution a coute. Un flux dont le
        # transport est irreprochable peut avoir ete precede de deux secondes
        # d'attente : c'est la seule ligne du rapport qui les rend visibles.
        lien = dns_links.get(position_de.get(id(fv), -1))
        if lien is not None:
            if lien.explains_delay and lien.latency_ms:
                body.append(f"  * {t('report.dns_before_flow', lang, ms=lien.latency_ms, qname=lien.qname)}\n",
                            style="cyan")
            else:
                body.append(f"  * {t('report.dns_name_hint', lang, qname=lien.qname)}\n",
                            style="cyan")
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
            lang: str = DEFAULT_LANG,
            dns_verdicts: Optional[list] = None,
            dns_links: Optional[dict] = None,
            udp_verdicts: Optional[list] = None,
            dns_orphelines: int = 0) -> str:
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
        "stats": {"packets": st.total, "tcp": st.tcp, "udp": st.udp,
                  "udp_dns": st.udp_dns, "icmp": st.icmp,
                  "other_ip": st.other_ip, "non_ip": st.non_ip,
                  "fragments_skipped": st.fragments_skipped,
                  "parse_errors": st.parse_errors,
                  "dns_unreadable": st.dns_unreadable,
                  "dns_orphelins": dns_orphelines,
                  "linktype": st.linktype,
                  "mixed_linktypes": st.mixed_linktypes},
        "flows": [],
    }
    if dns_verdicts is not None:
        out["dns"] = [{
            "qname": dv.signals.qname,
            "qtype": dv.signals.qtype,
            "verdict": dv.verdict if dv.primary else None,
            "signals": dv.signals.as_dict(),
            "matches": [{
                "rule": m.rule.id,
                "verdict": m.verdict,
                "priority": m.rule.priority,
                "confidence": m.rule.confidence,
                "title": m.title,
                "evidence": m.evidence,
                "remediation": m.remediation,
            } for m in dv.matches],
        } for dv in dns_verdicts]
    if udp_verdicts is not None:
        out["udp"] = [{
            "conversation": (f"{uv.signals.client}:{uv.signals.cport}"
                             f"->{uv.signals.server}:{uv.signals.sport}"),
            "verdict": uv.verdict if uv.primary else None,
            "signals": uv.signals.as_dict(),
            "matches": [{
                "rule": m.rule.id,
                "verdict": m.verdict,
                "priority": m.rule.priority,
                "confidence": m.rule.confidence,
                "title": m.title,
                "evidence": m.evidence,
                "remediation": m.remediation,
            } for m in uv.matches],
        } for uv in udp_verdicts]
    dns_links = dns_links or {}
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
        lien = dns_links.get(index)
        if lien is not None:
            entry["dns"] = {
                "qname": lien.qname,
                "answered_at": lien.answered_at,
                "resolution_ms": lien.latency_ms,
                "lag_s": lien.lag_s,
                "explains_delay": lien.explains_delay,
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
