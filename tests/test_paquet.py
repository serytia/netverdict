"""Le paquet installe doit contenir ce que le CLI promet d'executer.

`netverdict capture` resolvait son script via `Path(__file__).parent.parent`,
c'est-a-dire la racine du DEPOT. Apres un `pip install`, ce chemin vaut
site-packages, ou aucun dossier `capture/` n'existe : la sous-commande sortait
en erreur 2 pour tout utilisateur installe, alors qu'elle est annoncee dans
`netverdict --help`. Verifie sur le wheel 0.3.0 le 25/07/2026, avant correction :

    $ netverdict capture
    Script de capture introuvable : ...\\site-packages\\capture\\capture.ps1

Ces tests passent depuis le depot ET depuis une installation, ce qui est
exactement la propriete manquante : les chemins sont resolus relativement au
PAQUET, jamais a l'arborescence de developpement.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import netverdict
from netverdict.cli import cmd_capture

RACINE_PAQUET = Path(netverdict.__file__).parent


@pytest.mark.parametrize("relatif", [
    "capture/capture.ps1",       # execute par cmd_capture sous Windows
    "capture/capture.sh",        # execute par cmd_capture ailleurs
    "capture/sysmon-netverdict.xml",   # referencee par le README et evtx.py
    "rules/builtin.yaml",        # chargee par load_rules a chaque analyse
    "rules/dns.yaml",            # chargee par load_dns_rules a chaque analyse
    "rules/udp.yaml",            # chargee par load_udp_rules a chaque analyse
])
def test_les_ressources_executees_vivent_dans_le_paquet(relatif):
    chemin = RACINE_PAQUET / relatif
    assert chemin.is_file(), (
        f"{relatif} doit etre livre DANS le paquet : hors de netverdict/, "
        f"setuptools ne l'embarque pas et la fonctionnalite casse a "
        f"l'installation sans casser aucun test")
    assert chemin.stat().st_size > 0


def test_chaque_ressource_est_declaree_livrable(recwarn):
    """Le fichier peut exister dans le depot et manquer au wheel : ce sont deux
    proprietes distinctes, et c'est la seconde qui avait lache. On verifie donc
    la DECLARATION, sans payer un build complet a chaque execution de la suite.

    Un `pip install` ne copie que ce que package-data enumere ; retirer une
    ligne ici casse une fonctionnalite sans casser le moindre test de logique.
    """
    import fnmatch
    import tomllib

    pyproject = RACINE_PAQUET.parent / "pyproject.toml"
    if not pyproject.is_file():
        pytest.skip("execute depuis une installation, pas depuis le depot")
    conf = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    motifs = conf["tool"]["setuptools"]["package-data"]["netverdict"]

    for relatif in ("capture/capture.ps1", "capture/capture.sh",
                    "capture/sysmon-netverdict.xml", "rules/builtin.yaml",
                    "rules/dns.yaml", "rules/udp.yaml"):
        assert any(fnmatch.fnmatch(relatif, m) for m in motifs), (
            f"{relatif} est execute a l'exploitation mais aucun motif de "
            f"package-data ne le couvre : absent du wheel, donc casse a "
            f"l'installation. Motifs declares : {motifs}")


def test_cmd_capture_ne_cherche_plus_a_cote_du_paquet(monkeypatch, capsys):
    """Le temoin de la regression : on execute cmd_capture avec un lanceur
    neutralise et on verifie le chemin qu'il a choisi. Un retour a
    `parent.parent` fait tomber ce test."""
    vu: dict[str, list[str]] = {}

    def faux_call(cmd):
        vu["cmd"] = cmd
        return 0

    monkeypatch.setattr("netverdict.cli.subprocess.call", faux_call)
    # Ce test porte sur la RESOLUTION DU CHEMIN, pas sur le systeme : on force
    # un OS supporte pour qu'il verifie la meme propriete partout. Sans ca, il
    # tombait sur macOS depuis l'ajout du garde-fou d'OS (CI du 26/07), en
    # signalant un faux probleme de chemin.
    monkeypatch.setattr("netverdict.cli.platform.system", lambda: "Linux")

    class Args:
        duration = None
        out = None
        lang = None            # comme argparse quand --lang n'est pas passe

    rc = cmd_capture(Args())
    assert rc == 0, capsys.readouterr().err
    script = Path([a for a in vu["cmd"] if a.endswith((".ps1", ".sh"))][0])
    assert script.is_file(), "le script vise doit exister"
    assert script.parent == RACINE_PAQUET / "capture", (
        f"resolu vers {script.parent}, attendu dans le paquet")
