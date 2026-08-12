"""netverdict — triage d'incident reseau a partir d'une capture.

La version n'est PAS ecrite ici : elle est lue depuis les metadonnees du paquet
installe, dont la source unique est pyproject.toml. Avant 0.7.0 elle etait codee
en dur dans ce fichier et personne ne la bumpait : la 0.6.0 publiee sur PyPI
annoncait « netverdict 0.5.0 » a qui tapait --version. Une seule source, ou la
divergence revient.
"""

from importlib.metadata import PackageNotFoundError, version as _installed_version

try:
    __version__ = _installed_version("netverdict")
except PackageNotFoundError:
    # Execution depuis les sources sans installation (git clone + python -m).
    # Le suffixe dit la verite : on ne sait pas quelle version c'est.
    __version__ = "0+unknown"

__all__ = ["__version__"]
