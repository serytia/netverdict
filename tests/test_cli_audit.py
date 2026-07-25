"""Bout en bout CLI de --audit : le flux d'un process mort est attribue.

Meme forme que test_cli_timeline.py : les fixtures pcap vivent a l'epoch ~0,
donc le journal d'audit de test aussi. Le but est de prouver que la chaine
COMPLETE (option CLI -> parseur auditd -> jointure correlate -> rapport)
fonctionne, pas seulement le parseur pris isolement.
"""

import json

from netverdict.cli import main

# slow_app.pcap : client 10.0.0.42:51006 -> serveur 10.0.0.5:5432, t_first=0.
# Un record connect() vers CE serveur, juste avant le flux.
AUDIT_CONTENT = (
    'type=SYSCALL msg=audit(0.100:4242): arch=c000003e syscall=42 '
    'success=yes exit=0 a0=3 ppid=1 pid=31337 auid=1000 uid=1000 gid=1000 '
    'comm="psql" exe="/usr/bin/psql" key="netverdict_connect"\n'
    # 0A0000 05 -> 10.0.0.5 ; port 0x1538 = 5432
    'type=SOCKADDR msg=audit(0.100:4242): saddr=020015380A000005\n'
)


def test_analyze_with_audit_attributes_dead_process(tmp_path, capsys):
    log = tmp_path / "audit.log"
    log.write_text(AUDIT_CONTENT, encoding="utf-8")

    rc = main(["analyze", "tests/fixtures/slow_app.pcap",
               "--audit", str(log), "--json"])
    out = json.loads(capsys.readouterr().out)

    assert rc == 1                              # le flux a bien un verdict
    flux = [f for f in out["flows"] if "5432" in f["flow"]]
    assert flux, "flux vers 5432 absent"
    attr = flux[0].get("process_attribution")
    assert attr is not None, "aucune attribution : la jointure auditd est inerte"
    assert attr["image"] == "/usr/bin/psql"
    assert attr["pid"] == 31337
    assert attr["source"] == "auditd"
    assert attr["side"] == "client"
    # Correspondance par destination seule : l'outil doit l'annoncer.
    assert attr["exact"] is False


def test_analyze_bad_audit_path_clean_error(tmp_path, capsys):
    rc = main(["analyze", "tests/fixtures/clean.pcap",
               "--audit", str(tmp_path / "absent.log"), "--json"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "--audit" in err                     # message propre, pas un traceback
