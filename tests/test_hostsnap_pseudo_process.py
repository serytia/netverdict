"""Une socket sans proprietaire ne doit pas etre presentee comme attribuee.

TIME_WAIT et CLOSE_WAIT survivent au process qui les a ouvertes : Windows
rattache alors la socket a « Idle » (pid 0) ou « System ». Afficher « socket
detenue par Idle (pid 0) » n'est pas une reponse, c'est du bruit qui en a
l'apparence — constate sur une capture reelle le 26/07.
"""

from netverdict.hostsnap import HostSnapshot
from netverdict.signals import FlowSignals


def _snap(connections):
    return HostSnapshot({"host": "H1", "os": "windows", "cpu_pct": 12.0,
                         "disk_busy_pct": 3.0, "mem_free_mb": 2048,
                         "connections": connections, "top_cpu": []})


def _sig():
    return FlowSignals(client="10.0.0.42", cport=51001,
                       server="10.0.0.5", sport=443)


def test_idle_pid0_nest_pas_une_attribution():
    ctx = _snap([{"local_ip": "10.0.0.5", "local_port": 443,
                  "state": "TIME_WAIT", "pid": 0, "process": "Idle"}]
                ).context_for(_sig())
    assert ctx.process is None
    assert ctx.pid is None
    # Les metriques machine, elles, sont vraies : on les garde.
    assert ctx.cpu_pct == 12.0
    assert "Idle" not in ctx.summary()


def test_system_et_pid_absent_traites_pareil():
    for conn in ({"local_ip": "10.0.0.5", "local_port": 443,
                  "pid": 4, "process": "System"},
                 {"local_ip": "10.0.0.5", "local_port": 443,
                  "pid": None, "process": None}):
        ctx = _snap([conn]).context_for(_sig())
        assert ctx.process is None, conn


def test_un_vrai_process_prime_sur_le_pseudo_du_meme_port():
    """Port reutilise : un TIME_WAIT « Idle » ne doit pas masquer la socket
    ESTABLISHED du process vivant."""
    ctx = _snap([
        {"local_ip": "10.0.0.5", "local_port": 443, "state": "TIME_WAIT",
         "pid": 0, "process": "Idle"},
        {"local_ip": "10.0.0.5", "local_port": 443, "state": "ESTABLISHED",
         "pid": 4212, "process": "nginx"},
    ]).context_for(_sig())
    assert ctx.process == "nginx"
    assert ctx.pid == 4212


def test_un_vrai_process_reste_attribue():
    ctx = _snap([{"local_ip": "10.0.0.5", "local_port": 443,
                  "state": "ESTABLISHED", "pid": 4212, "process": "nginx"}]
                ).context_for(_sig())
    assert ctx.process == "nginx" and ctx.pid == 4212
    assert "nginx" in ctx.summary()
