"""Optional narrative layer (--explain): evidence -> a plain-English explanation.

Non-negotiable principles:
- The model NEVER sees the packet capture: only the JSON report (extracted
  signals, verdicts, evidence). A capture carries secrets; a report carries
  only their X-ray.
- The model does not issue the verdict: it NARRATES the verdict the
  deterministic engine already produced. No findings, no narration.
- Optional dependency: the whole tool works without it. `pip install
  netverdict[explain]` plus an API key to enable.
"""

from __future__ import annotations

from .i18n import DEFAULT_LANG, t

MODEL = "claude-opus-5"

# {langue} est remplace par le nom de la langue demandee (voir
# i18n.py: explain.language_name). C'est la SEULE chose qui decide de la langue
# de la synthese : le reste du prompt est un contrat de comportement, pas de
# la prose affichee, et le traduire n'apporterait rien qu'un risque de
# divergence entre les deux versions.
SYSTEM_TEMPLATE = """Tu es un ingenieur reseau senior qui explique un diagnostic a un
collegue administrateur systeme/reseau competent mais presse.

On te fournit le rapport JSON d'un outil de triage d'incident (analyse de
capture reseau) : signaux TCP mesures, verdicts rendus par un moteur de regles
deterministe, preuves et pistes de correction.

Redige en {langue} une synthese narrative courte (10-20 lignes) :
1. Ce qui se passe, en une phrase de conclusion d'abord.
2. Le raisonnement : quelles preuves menent au verdict, en langage clair.
3. La prochaine action concrete, et ce qu'il faut surveiller ensuite.

Regles strictes :
- Tu t'appuies UNIQUEMENT sur les faits du rapport. Aucune invention, aucune
  supposition presentee comme un fait. Si les donnees sont insuffisantes ou
  ambigues, dis-le clairement.
- Ne repete pas le JSON : raconte-le.
- Pas de titres pompeux, pas de liste de 15 recommandations : la synthese
  d'un collegue senior, directe et actionnable.
- Les jetons de verdict du rapport (RESEAU, APP, OS, HOTE, AMBIGU, RAS) sont
  des identifiants internes : ne les cite pas tels quels, dis ce qu'ils
  signifient dans la langue de la synthese.
- TOUTE ta reponse est en {langue}, titres et listes compris."""


def system_prompt(lang: str = DEFAULT_LANG) -> str:
    """Prompt systeme pour la langue demandee."""
    return SYSTEM_TEMPLATE.format(langue=t("explain.language_name", lang))


# Conserve pour compatibilite : la valeur historique, en francais.
SYSTEM = system_prompt(DEFAULT_LANG)


class ExplainUnavailable(RuntimeError):
    """Leve quand la couche explain ne peut pas tourner (SDK absent, pas de
    credentials). L'appelant affiche le message et continue sans."""


def explain(report_json: str, lang: str = DEFAULT_LANG) -> str:
    try:
        import anthropic
    except ImportError:
        raise ExplainUnavailable(t("explain.no_sdk", lang))

    client = anthropic.Anthropic()  # cle via ANTHROPIC_API_KEY ou profil `ant auth login`
    try:
        # Fallback serveur actif par defaut : un rapport d'analyse reseau est
        # du contenu securite benin, mais les classificateurs peuvent
        # occasionnellement le prendre pour autre chose — le fallback re-sert
        # la requete sur un autre modele au lieu de la refuser.
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=8000,
            betas=["server-side-fallback-2026-07-01"],
            system=system_prompt(lang),
            messages=[{
                "role": "user",
                "content": t("explain.user_prompt", lang, report=report_json),
            }],
            extra_body={"fallbacks": "default"},
        )
    except anthropic.AuthenticationError:
        raise ExplainUnavailable(t("explain.no_credentials", lang))
    except anthropic.APIConnectionError:
        raise ExplainUnavailable(t("explain.unreachable", lang))
    except anthropic.APIStatusError as e:
        raise ExplainUnavailable(t("explain.api_error", lang,
                                   code=e.status_code, message=e.message))

    if response.stop_reason == "refusal":
        raise ExplainUnavailable(t("explain.refusal", lang))
    parts = [b.text for b in response.content if b.type == "text"]
    return "\n".join(parts).strip()
