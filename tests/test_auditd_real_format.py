"""Formats REELS d'auditd, releves sur un journal kernel (lab, 26/07).

Les fixtures ecrites a la main decrivaient un auditd ideal : `success=yes` et
un champ saddr propre. Le journal reel a dementi les deux, et la jointure
rendait zero attribution sur 3 flux. Ces tests verrouillent le format tel
qu'il EXISTE, pas tel qu'on l'imaginait.
"""

from netverdict.sources import auditd

# Lignes copiees telles quelles depuis /var/log/audit/audit.log de netlab
# (curl vers 127.0.0.1:8080, socket non bloquante). Noter les DEUX pieges :
# `success=no exit=-115` (EINPROGRESS) et le bloc `SADDR={...}` colle a la
# valeur hexadecimale sans separateur.
_SYSCALL_REEL = (
    'type=SYSCALL msg=audit(1785021872.119:141): arch=c000003e syscall=42 '
    'success=no exit=-115 a0=4 a1=55d3b4e5f8e8 a2=10 a3=0 items=0 ppid=1119 '
    'pid=1139 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 '
    'fsgid=0 tty=(none) ses=1 comm="curl" exe="/usr/bin/curl" '
    'subj=unconfined key="netverdict_connect"ARCH=x86_64 SYSCALL=connect '
    'AUID="netlab" UID="root" GID="root"\n'
)
_SOCKADDR_REEL = (
    'type=SOCKADDR msg=audit(1785021872.119:141): '
    'saddr=02001F907F0000010000000000000000SADDR={ saddr_fam=inet '
    'laddr=127.0.0.1 lport=8080 }\n'
)


def test_saddr_avec_bloc_interprete_colle(tmp_path):
    """`ausearch --raw` colle sa version interpretee derriere la valeur, sans
    separateur : couper a l'espace donnait un hex invalide -> tout le journal
    reel finissait en unparsed."""
    f = tmp_path / "audit.log"
    f.write_text(_SYSCALL_REEL + _SOCKADDR_REEL, encoding="utf-8")
    events, stats = auditd.parse(f)
    assert len(events) == 1, "la connexion reelle n'a pas ete retrouvee"
    c = events[0].connection
    assert (c.dst_ip, c.dst_port) == ("127.0.0.1", 8080)
    assert c.image == "/usr/bin/curl"
    assert c.pid == 1139
    assert stats.unparsed == 0


def test_einprogress_est_une_connexion(tmp_path):
    """EINPROGRESS (-115) est la signature NORMALE d'une socket non
    bloquante : la connexion s'etablit ensuite. C'est le cas de curl, des
    navigateurs et de tout client async."""
    f = tmp_path / "audit.log"
    f.write_text(_SYSCALL_REEL + _SOCKADDR_REEL, encoding="utf-8")
    events, _ = auditd.parse(f)
    assert events and events[0].connection is not None


def test_saddr_hex_de_longueur_impaire_reste_exploitable(tmp_path):
    """Un demi-octet orphelin en fin de champ (troncature) ne doit pas faire
    perdre la famille/le port/l'adresse, qui sont en tete de structure."""
    f = tmp_path / "audit.log"
    f.write_text(
        _SYSCALL_REEL
        + 'type=SOCKADDR msg=audit(1785021872.119:141): saddr=02001F907F0000010\n',
        encoding="utf-8")
    events, _ = auditd.parse(f)
    assert events and events[0].connection.dst_port == 8080
