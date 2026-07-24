"""Couche narrative optionnelle (--explain) : les preuves -> une explication.

Principes non negociables :
- Le LLM ne voit JAMAIS le pcap : uniquement le rapport JSON (signaux extraits,
  verdicts, preuves). Un pcap contient des secrets ; un rapport n'en contient
  que la radiographie.
- Le LLM n'emet pas le verdict : il RACONTE le verdict que le moteur
  deterministe a rendu. S'il n'y a pas de matiere, il n'y a pas d'explication.
- Dependance optionnelle : l'outil complet fonctionne sans. `pip install
  netverdict[explain]` + une cle API pour activer.
"""

from __future__ import annotations

MODEL = "claude-opus-5"

SYSTEM = """Tu es un ingenieur reseau senior qui explique un diagnostic a un
collegue administrateur systeme/reseau competent mais presse.

On te fournit le rapport JSON d'un outil de triage d'incident (analyse de
capture reseau) : signaux TCP mesures, verdicts rendus par un moteur de regles
deterministe, preuves et pistes de correction.

Redige en francais une synthese narrative courte (10-20 lignes) :
1. Ce qui se passe, en une phrase de conclusion d'abord.
2. Le raisonnement : quelles preuves menent au verdict, en langage clair.
3. La prochaine action concrete, et ce qu'il faut surveiller ensuite.

Regles strictes :
- Tu t'appuies UNIQUEMENT sur les faits du rapport. Aucune invention, aucune
  supposition presentee comme un fait. Si les donnees sont insuffisantes ou
  ambigues, dis-le clairement.
- Ne repete pas le JSON : raconte-le.
- Pas de titres pompeux, pas de liste de 15 recommandations : la synthese
  d'un collegue senior, directe et actionnable."""


class ExplainUnavailable(RuntimeError):
    """Leve quand la couche explain ne peut pas tourner (SDK absent, pas de
    credentials). L'appelant affiche le message et continue sans."""


def explain(report_json: str) -> str:
    try:
        import anthropic
    except ImportError:
        raise ExplainUnavailable(
            "Le SDK 'anthropic' n'est pas installe. "
            "Installer avec : pip install netverdict[explain]"
        )

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
            system=SYSTEM,
            messages=[{
                "role": "user",
                "content": ("Rapport netverdict a expliquer :\n\n" + report_json),
            }],
            extra_body={"fallbacks": "default"},
        )
    except anthropic.AuthenticationError:
        raise ExplainUnavailable(
            "Pas de credentials API valides. Definir ANTHROPIC_API_KEY "
            "ou se connecter avec `ant auth login`."
        )
    except anthropic.APIConnectionError:
        raise ExplainUnavailable("API Anthropic injoignable (reseau ?).")
    except anthropic.APIStatusError as e:
        raise ExplainUnavailable(f"Erreur API ({e.status_code}): {e.message}")

    if response.stop_reason == "refusal":
        raise ExplainUnavailable(
            "La requete a ete declinee par les garde-fous du modele. "
            "Les verdicts et remediations du rapport restent valables tels quels."
        )
    parts = [b.text for b in response.content if b.type == "text"]
    return "\n".join(parts).strip()
