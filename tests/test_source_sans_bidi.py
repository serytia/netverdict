"""Aucun fichier source du depot ne doit contenir de controle bidi LITTERAL.

Un caractere de direction Unicode (U+202E et sa famille) est INVISIBLE dans un
editeur : il ne s'affiche pas, il reordonne le texte qui suit. Un fichier qui
en contient est rendu a l'envers par tout outil appliquant l'algorithme bidi -
c'est la famille d'attaques dite « Trojan Source », ou le code lu ne dit pas ce
que le code execute. GitHub affiche une banniere d'avertissement sur ces
fichiers.

Ce test existe parce que le defaut s'etait cache dans son propre correctif :
la premiere version de la protection anti-bidi de timeline.py collait les
caracteres eux-memes dans sa classe de caracteres, sous un commentaire
affirmant qu'ils etaient ecrits en echappements (revue du 15/08/2026). Un
verrou par fichier n'aurait pas suffi - c'est la classe entiere qu'il faut
fermer, y compris pour les fichiers ecrits demain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

RACINE = Path(__file__).parent.parent

# U+200E/U+200F (marques), U+202A-U+202E (embedding/override),
# U+2066-U+2069 (isolates). Ecrits en points de code, evidemment.
BIDI = (frozenset({0x200E, 0x200F})
        | frozenset(range(0x202A, 0x202F))
        | frozenset(range(0x2066, 0x206A)))

# Le code, les regles, la doc et les scripts. Pas les .pcap (binaires) ni les
# repertoires d'outillage.
EXTENSIONS = {".py", ".yaml", ".yml", ".md", ".sh", ".ps1", ".xml", ".toml",
              ".cfg", ".txt"}
IGNORES = {".venv", ".git", "build", "dist", "__pycache__", ".pytest_cache"}


def fichiers_source():
    for p in RACINE.rglob("*"):
        if p.suffix.lower() not in EXTENSIONS or not p.is_file():
            continue
        if any(part in IGNORES or part.endswith(".egg-info") for part in p.parts):
            continue
        yield p


def test_le_depot_contient_des_fichiers_a_verifier():
    """Garde-fou du garde-fou : si la collecte se casse, le test suivant
    passerait sur une liste vide sans rien prouver."""
    fichiers = list(fichiers_source())
    assert len(fichiers) > 40, f"seulement {len(fichiers)} fichiers collectes"
    noms = {f.name for f in fichiers}
    assert "timeline.py" in noms and "dns.yaml" in noms


def test_aucun_controle_bidi_litteral_dans_les_sources():
    coupables = []
    for f in fichiers_source():
        try:
            texte = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue                      # binaire deguise : hors sujet ici
        for numero, ligne in enumerate(texte.splitlines(), 1):
            trouves = sorted({ord(c) for c in ligne} & BIDI)
            if trouves:
                coupables.append(
                    f"{f.relative_to(RACINE)}:{numero} -> "
                    + ", ".join(f"U+{cp:04X}" for cp in trouves))
    assert not coupables, (
        "controle(s) bidi LITTERAL(aux) dans le source - a ecrire en "
        "echappement backslash-u :\n  " + "\n  ".join(coupables))


def test_la_protection_neutralise_sans_massacrer_les_langues_a_droite():
    """Le pendant positif : la classe doit prendre les CONTROLES et laisser
    passer un vrai texte ecrit de droite a gauche."""
    from netverdict.timeline import _clean

    assert _clean("ab" + chr(0x202E) + "cd") == "ab.cd"
    assert _clean("a" + chr(0x2066) + "b") == "a.b"
    assert _clean("a\x1b[2Kb") == "a.[2Kb"          # ANSI toujours couvert
    # Hebreu et arabe reels : aucun controle, rien ne doit bouger.
    for legitime in ("שלום עולם", "مرحبا بالعالم", "srv-münchen", "日本語"):
        assert _clean(legitime) == legitime, f"{legitime!r} a ete altere"
