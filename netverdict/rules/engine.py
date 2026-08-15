"""Moteur de regles : FlowSignals -> verdicts avec preuves et remediation.

Meme philosophie que des regles Wazuh : DECLARATIF. Une regle est de la
donnee (YAML), pas du code — lisible, diffable, extensible par l'utilisateur
sans toucher au moteur (--rules fichier.yaml en plus des builtin).

Une regle :
  - id, verdict (RESEAU|APP|OS|HOTE|AMBIGU|RAS), priority, confidence, title
  - when:   conditions all/any sur les champs de FlowSignals
  - unless: conditions inhibitrices (une seule vraie suffit a inhiber)
  - evidence: templates interpoles avec les signaux -> les preuves citees
  - remediation: texte redige a la main, jamais genere

Traduction (v0.6) : `title`/`evidence`/`remediation` portent le francais, et
les champs freres `title_en`/`evidence_en`/`remediation_en` l'anglais. Une
traduction absente retombe sur le francais — jamais d'erreur, jamais de trou
dans le rapport. Le champ `verdict` et le champ `confidence`, eux, ne sont PAS
traduits : ce sont des identifiants sur lesquels le JSON et les regles
utilisateur s'appuient (voir i18n.py).

Le mini-DSL de condition est volontairement pauvre : "champ op litteral".
Pas d'eval(), pas d'expressions arbitraires — une regle illisible est une
regle fausse en puissance.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from ..dns import DnsSignals
from ..i18n import DEFAULT_LANG, LANGS
from ..signals import FlowSignals
from ..udp import UdpSignals

VERDICTS = {"RESEAU", "APP", "OS", "HOTE", "AMBIGU", "RAS"}

# Une regle s'evalue contre UN contrat de signaux. `flow` = FlowSignals (une
# conversation TCP), `dns` = DnsSignals (une resolution de nom). Le champ
# existe pour que le fichier `--rules` d'un utilisateur puisse contenir les
# deux : sans lui, une regle DNS serait sondee contre FlowSignals et
# exploserait au chargement sur « Champ inconnu: latency_ms » - message vrai
# mais incomprehensible pour qui vient d'ecrire une regle DNS parfaitement
# valide.
SCOPES = {"flow", "dns", "udp"}

_OPS = {
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">":  lambda a, b: a > b,
    "<":  lambda a, b: a < b,
}


class RuleError(ValueError):
    """Regle malformee : on echoue au CHARGEMENT, jamais a l'evaluation.
    Une regle qui casse pendant l'analyse produirait un verdict partiel
    silencieux — inacceptable pour un outil dont le produit est la confiance."""


def _parse_literal(tok: str) -> Any:
    low = tok.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("none", "null"):
        return None
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        pass
    return tok.strip("\"'")


@dataclass
class Condition:
    fld: str
    op: str
    value: Any

    @classmethod
    def parse(cls, expr: str) -> "Condition":
        # Ordre de test : operateurs longs d'abord, sinon ">=" matche sur ">".
        for op in ("==", "!=", ">=", "<=", ">", "<"):
            if op in expr:
                left, right = expr.split(op, 1)
                fld = left.strip()
                if not fld or not fld.replace("_", "").isalnum():
                    raise RuleError(f"Champ invalide dans la condition: {expr!r}")
                return cls(fld=fld, op=op, value=_parse_literal(right.strip()))
        raise RuleError(f"Aucun operateur reconnu dans: {expr!r}")

    def eval(self, sig: dict) -> bool:
        if self.fld not in sig:
            raise RuleError(f"Champ inconnu: {self.fld!r} (typo dans la regle ?)")
        actual = sig[self.fld]
        # None ne se compare pas : seul ==/!= a un sens, les relations sont
        # fausses (un RTT non mesurable n'est ni grand ni petit).
        if actual is None and self.op not in ("==", "!="):
            return False
        if self.value is None or actual is None:
            return _OPS[self.op](actual, self.value) if self.op in ("==", "!=") else False
        try:
            return _OPS[self.op](actual, self.value)
        except TypeError:
            raise RuleError(
                f"Types incompatibles: {self.fld}={actual!r} {self.op} {self.value!r}")


@dataclass
class Clause:
    """Noeud all/any, un niveau d'imbrication libre (all de any de all...)."""
    mode: str                      # "all" | "any"
    children: list                 # Condition | Clause

    @classmethod
    def parse(cls, node: Any, default_mode: str = "all") -> "Clause":
        if isinstance(node, str):
            return cls(mode="all", children=[Condition.parse(node)])
        if isinstance(node, list):
            return cls(mode=default_mode,
                       children=[cls._parse_child(c) for c in node])
        if isinstance(node, dict) and len(node) == 1:
            mode = next(iter(node))
            if mode not in ("all", "any"):
                raise RuleError(f"Clause inconnue: {mode!r} (attendu all/any)")
            body = node[mode]
            if not isinstance(body, list):
                raise RuleError(f"'{mode}' doit contenir une liste")
            return cls(mode=mode, children=[cls._parse_child(c) for c in body])
        raise RuleError(f"Structure de condition invalide: {node!r}")

    @classmethod
    def _parse_child(cls, node: Any):
        if isinstance(node, str):
            return Condition.parse(node)
        return cls.parse(node)

    def eval(self, sig: dict) -> bool:
        results = (c.eval(sig) for c in self.children)
        return all(results) if self.mode == "all" else any(results)

    def valider(self, sig: dict) -> None:
        """Evalue TOUTES les conditions, sans court-circuit, pour le dry-run.

        `eval` s'arrete des la premiere condition fausse d'un `all` - c'est le
        comportement voulu a l'analyse, mais il rendait le controle de
        chargement partiel : une faute de frappe placee apres une condition
        fausse n'etait jamais atteinte, donc jamais signalee. La moitie des
        conditions des regles livrees n'etaient ainsi jamais eprouvees, et une
        regle utilisateur pouvait contenir un champ inexistant sans que
        `--rules` ne dise rien (revue du 15/08/2026).
        """
        for c in self.children:
            if isinstance(c, Clause):
                c.valider(sig)
            else:
                c.eval(sig)


class _EvidenceFormatter(string.Formatter):
    """Interpole les signaux dans les preuves en tolerant les None :
    '{rtt_ms_p50:.1f}' sur un RTT non mesure rend 'n/a' au lieu de crasher."""

    def get_value(self, key, args, kwargs):
        v = kwargs.get(key) if isinstance(key, str) else None
        return "n/a" if v is None else v

    def format_field(self, value, format_spec):
        if value == "n/a":
            return "n/a"
        return super().format_field(value, format_spec)


_FMT = _EvidenceFormatter()


@dataclass
class Rule:
    id: str
    verdict: str
    priority: int
    confidence: str
    title: str
    when: Clause
    unless: Optional[Clause]
    evidence: list[str]
    remediation: str
    scope: str = "flow"
    # Traductions, par code de langue. Le francais reste dans les champs
    # ci-dessus (compatibilite : tout code existant lit `rule.title`).
    title_i18n: dict[str, str] = field(default_factory=dict)
    evidence_i18n: dict[str, list[str]] = field(default_factory=dict)
    remediation_i18n: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        missing = {"id", "verdict", "title", "when"} - set(d)
        if missing:
            raise RuleError(f"Regle {d.get('id', '?')!r}: champs manquants {missing}")
        if d["verdict"] not in VERDICTS:
            raise RuleError(f"Regle {d['id']!r}: verdict {d['verdict']!r} inconnu "
                            f"(attendu: {sorted(VERDICTS)})")
        scope = d.get("scope", "flow")
        if scope not in SCOPES:
            raise RuleError(f"Regle {d['id']!r}: scope {scope!r} inconnu "
                            f"(attendu: {sorted(SCOPES)})")
        # Champs freres `<champ>_<lang>` pour toute langue connue autre que le
        # francais, qui est porte par le champ nu. Une regle utilisateur qui
        # n'en fournit aucun reste parfaitement valide : elle sortira en
        # francais quelle que soit --lang, ce qui est honnete et ne casse rien.
        titres, preuves, remedes = {}, {}, {}
        for lang in LANGS:
            # Le champ nu (title/evidence/remediation) porte TOUJOURS le
            # francais, quelle que soit DEFAULT_LANG (voir docstring de la
            # classe) : comparer a DEFAULT_LANG ici sautait "en" une fois le
            # defaut passe a l'anglais, et les regles builtin (qui ne
            # fournissent que title_en/evidence_en/remediation_en) se
            # retrouvaient sans aucune traduction enregistree -> title_for
            # ("en") repliait sur le francais. Bug reel revele par le
            # changement de DEFAULT_LANG, corrige ici (pas un contournement
            # de test : le champ nu est fixe en francais par construction).
            if lang == "fr":
                continue
            if d.get(f"title_{lang}"):
                titres[lang] = d[f"title_{lang}"]
            if d.get(f"evidence_{lang}"):
                preuves[lang] = list(d[f"evidence_{lang}"])
            if d.get(f"remediation_{lang}"):
                remedes[lang] = str(d[f"remediation_{lang}"]).strip()
        return cls(
            id=d["id"],
            scope=scope,
            verdict=d["verdict"],
            priority=int(d.get("priority", 50)),
            confidence=d.get("confidence", "moyenne"),
            title=d["title"],
            when=Clause.parse(d["when"]),
            unless=Clause.parse({"any": d["unless"]}) if d.get("unless") else None,
            evidence=list(d.get("evidence", [])),
            remediation=str(d.get("remediation", "")).strip(),
            title_i18n=titres,
            evidence_i18n=preuves,
            remediation_i18n=remedes,
        )

    # --- acces localise ; repli sur le francais, jamais d'exception ---------

    def title_for(self, lang: str = DEFAULT_LANG) -> str:
        return self.title_i18n.get(lang) or self.title

    def evidence_for(self, lang: str = DEFAULT_LANG) -> list[str]:
        return self.evidence_i18n.get(lang) or self.evidence

    def remediation_for(self, lang: str = DEFAULT_LANG) -> str:
        return self.remediation_i18n.get(lang) or self.remediation


@dataclass
class Match:
    rule: Rule
    evidence: list[str]
    remediation: str = ""          # remediation de la regle, interpolee
    # Titre deja localise. Porte par le Match et non relu depuis la regle :
    # l'appelant qui affiche n'a pas a savoir dans quelle langue l'analyse a
    # tourne, et le JSON ne peut pas diverger de la console.
    title: str = ""

    @property
    def verdict(self) -> str: return self.rule.verdict

    def __post_init__(self):
        if not self.title:
            self.title = self.rule.title


@dataclass
class FlowVerdict:
    signals: FlowSignals
    matches: list[Match] = field(default_factory=list)   # tri par priorite desc

    @property
    def primary(self) -> Optional[Match]:
        return self.matches[0] if self.matches else None

    @property
    def verdict(self) -> str:
        return self.primary.verdict if self.primary else "RAS"


def load_rules(extra_files: Optional[list[str | Path]] = None) -> list[Rule]:
    """Regles de flux TCP (scope `flow`) : builtin.yaml + fichiers utilisateur."""
    return _load([Path(__file__).parent / "builtin.yaml"], extra_files,
                 scope="flow", probe=FlowSignals().as_dict())


def load_dns_rules(extra_files: Optional[list[str | Path]] = None) -> list[Rule]:
    """Regles de resolution DNS (scope `dns`) : dns.yaml + fichiers utilisateur.

    Les memes fichiers `--rules` sont relus ici : une regle utilisateur est
    routee par son `scope`, pas par le fichier ou elle se trouve."""
    return _load([Path(__file__).parent / "dns.yaml"], extra_files,
                 scope="dns", probe=DnsSignals().as_dict())


def load_udp_rules(extra_files: Optional[list[str | Path]] = None) -> list[Rule]:
    """Regles de conversation UDP (scope `udp`) : udp.yaml + utilisateur."""
    return _load([Path(__file__).parent / "udp.yaml"], extra_files,
                 scope="udp", probe=UdpSignals().as_dict())


def _load(base: list[Path], extra_files: Optional[list[str | Path]],
          scope: str, probe: dict) -> list[Rule]:
    files = list(base) + [Path(p) for p in (extra_files or [])]
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    # Dry-run de chaque regle sur un jeu de signaux vide : une typo de champ
    # explose ICI, au chargement, pas au milieu d'une analyse.
    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        for d in (doc or {}).get("rules", []):
            r = Rule.from_dict(d)
            if r.scope != scope:
                continue                 # elle sera chargee par l'autre etage
            if r.id in seen_ids:
                raise RuleError(f"Id de regle duplique: {r.id!r} (dans {f.name})")
            seen_ids.add(r.id)
            try:
                # `valider` et non `eval` : sans court-circuit, sinon la
                # moitie des conditions ne sont jamais eprouvees (voir
                # Clause.valider).
                r.when.valider(probe)
                if r.unless is not None:
                    r.unless.valider(probe)
                # TOUTES les langues sont eprouvees, pas seulement le
                # francais : une accolade fautive dans une traduction doit
                # exploser au chargement comme n'importe quelle autre faute de
                # regle. Sans ca, elle attendrait le premier --lang en, c'est
                # a dire le pire moment (en pleine analyse d'incident).
                for lang in LANGS:
                    for t in r.evidence_for(lang):
                        _FMT.vformat(t, (), probe)
                    _FMT.vformat(r.remediation_for(lang), (), probe)
            except RuleError as e:
                raise RuleError(f"Regle {r.id!r} ({f.name}): {e}")
            rules.append(r)
    return rules


# Une capture de triage contient surtout des flux sains ou anodins ; on ne
# rend un AMBIGU par defaut que si le flux presente une anomalie qu'aucune
# regle n'explique — sinon le rapport noierait le signal sous le bruit.
def _has_unexplained_anomaly(s: FlowSignals) -> bool:
    return (s.retrans_total > 0
            or s.zw_from_client + s.zw_from_server > 0
            or s.rst_midstream
            or (s.syn_count > 0 and not s.synack_seen))


AMBIGU_FALLBACK = Rule(
    id="fallback-ambigu",
    verdict="AMBIGU",
    priority=0,
    confidence="basse",
    title="Anomalies presentes mais tableau incomplet",
    when=Clause(mode="all", children=[]),
    unless=None,
    evidence=[
        "retrans={retrans_total} zw={zw_from_client}+{zw_from_server} "
        "rst_midstream={rst_midstream} syn={syn_count} synack={synack_seen}",
    ],
    remediation=(
        "La capture ne suffit pas a trancher. Refaire une capture plus longue "
        "englobant le debut de l'incident, idealement des deux cotes "
        "(client ET serveur) avec 'netverdict capture' pour joindre l'etat hote."
    ),
    title_i18n={"en": "Anomalies present but the picture is incomplete"},
    # La preuve est un vidage de compteurs : les noms de champs sont ceux du
    # moteur, il n'y a rien a traduire.
    evidence_i18n={},
    remediation_i18n={"en": (
        "The capture is not enough to decide. Take a longer capture covering "
        "the start of the incident, ideally from both sides (client AND "
        "server) with 'netverdict capture' to attach the host state."
    )},
)


def _matches_for(sig_dict: dict, rules: list[Rule], lang: str) -> list[Match]:
    """Confronte un jeu de signaux a des regles. Ne connait ni les flux ni le
    DNS : c'est ce qui permet aux deux etages de partager le meme moteur."""
    matches: list[Match] = []
    for r in rules:
        if not r.when.children:
            continue
        if not r.when.eval(sig_dict):
            continue
        if r.unless is not None and r.unless.eval(sig_dict):
            continue
        ev = [_FMT.vformat(t, (), sig_dict) for t in r.evidence_for(lang)]
        matches.append(Match(
            rule=r, evidence=ev, title=r.title_for(lang),
            remediation=_FMT.vformat(r.remediation_for(lang), (), sig_dict)))
    matches.sort(key=lambda m: -m.rule.priority)
    return matches


@dataclass
class DnsVerdict:
    """Pendant de FlowVerdict pour une resolution de nom."""

    signals: DnsSignals
    matches: list[Match] = field(default_factory=list)

    @property
    def primary(self) -> Optional[Match]:
        return self.matches[0] if self.matches else None

    @property
    def verdict(self) -> str:
        return self.primary.verdict if self.primary else "RAS"


def evaluate_dns(all_signals: list[DnsSignals], rules: list[Rule],
                 lang: str = DEFAULT_LANG) -> list[DnsVerdict]:
    return [DnsVerdict(signals=s, matches=_matches_for(s.as_dict(), rules, lang))
            for s in all_signals]


@dataclass
class UdpVerdict:
    """Pendant de FlowVerdict pour une conversation UDP."""

    signals: UdpSignals
    matches: list[Match] = field(default_factory=list)

    @property
    def primary(self) -> Optional[Match]:
        return self.matches[0] if self.matches else None

    @property
    def verdict(self) -> str:
        return self.primary.verdict if self.primary else "RAS"


def evaluate_udp(all_signals: list[UdpSignals], rules: list[Rule],
                 lang: str = DEFAULT_LANG) -> list[UdpVerdict]:
    return [UdpVerdict(signals=s, matches=_matches_for(s.as_dict(), rules, lang))
            for s in all_signals]


def evaluate(all_signals: list[FlowSignals], rules: list[Rule],
             lang: str = DEFAULT_LANG) -> list[FlowVerdict]:
    out: list[FlowVerdict] = []
    for s in all_signals:
        sig_dict = s.as_dict()
        matches = _matches_for(sig_dict, rules, lang)
        if not matches and _has_unexplained_anomaly(s):
            ev = [_FMT.vformat(t, (), sig_dict)
                  for t in AMBIGU_FALLBACK.evidence_for(lang)]
            matches.append(Match(rule=AMBIGU_FALLBACK, evidence=ev,
                                 title=AMBIGU_FALLBACK.title_for(lang),
                                 remediation=AMBIGU_FALLBACK.remediation_for(lang)))
        out.append(FlowVerdict(signals=s, matches=matches))
    return out
