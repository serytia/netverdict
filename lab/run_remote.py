"""Pilote la VM lab depuis l'hote : outils, scenarios, rapatriement des pcaps.

    python lab/run_remote.py            # defauts : VM netlab locale (port 2224)

Fait, dans l'ordre :
1. installe tcpdump/iptables/curl dans la VM (idempotent),
2. pousse lab/scenarios.sh et l'execute en root (sortie streamee),
3. rapatrie /tmp/netverdict-lab/*.pcap vers tests/fixtures/lab/.

Ensuite : pytest tests/test_lab_pcaps.py valide les verdicts terrain.
Necessite paramiko (dependance de dev, pas de l'outil).
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path

import paramiko

REPO = Path(__file__).parent.parent


def sudo_run(cli: paramiko.SSHClient, password: str, cmd: str,
             timeout: int = 300) -> int:
    """Execute cmd en root via sudo -S, sortie streamee vers stdout."""
    full = f"echo {shlex.quote(password)} | sudo -S -p '' bash -c {shlex.quote(cmd)}"
    chan = cli.get_transport().open_session()
    chan.settimeout(timeout)
    chan.set_combine_stderr(True)
    chan.exec_command(full)
    while True:
        data = chan.recv(4096)
        if not data:
            break
        sys.stdout.write(data.decode(errors="replace"))
        sys.stdout.flush()
    return chan.recv_exit_status()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2224)
    ap.add_argument("--user", default=os.environ.get("NETLAB_USER", "netlab"))
    # Pas de mot de passe en dur : ce depot est public, et un identifiant
    # ecrit dans un projet de securite defensive se remarque. Il vient de
    # l'environnement, ou du drapeau explicite.
    #   Windows : $env:NETLAB_PASSWORD = "..."      Linux : export NETLAB_PASSWORD=...
    ap.add_argument("--password", default=os.environ.get("NETLAB_PASSWORD"),
                    help="mot de passe SSH du lab (defaut : $NETLAB_PASSWORD)")
    ap.add_argument("--out", default=str(REPO / "tests" / "fixtures" / "lab"))
    args = ap.parse_args()
    if not args.password:
        ap.error("mot de passe absent : definir NETLAB_PASSWORD dans "
                 "l'environnement, ou passer --password")

    cli = paramiko.SSHClient()
    # Lab local jetable derriere un NAT VirtualBox : TOFU acceptable ici,
    # a ne jamais recopier vers de l'infra reelle.
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[run_remote] connexion {args.user}@{args.host}:{args.port}")
    cli.connect(args.host, port=args.port, username=args.user,
                password=args.password, timeout=20, look_for_keys=False,
                allow_agent=False)

    print("[run_remote] installation des outils (idempotent)...")
    rc = sudo_run(cli, args.password,
                  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
                  "apt-get install -y -qq tcpdump iptables curl python3")
    if rc != 0:
        print(f"[run_remote] ECHEC apt (rc={rc})")
        return rc

    print("[run_remote] envoi de scenarios.sh...")
    sftp = cli.open_sftp()
    sftp.put(str(REPO / "lab" / "scenarios.sh"), "/home/netlab/scenarios.sh")

    print("[run_remote] execution des scenarios (quelques minutes)...")
    rc = sudo_run(cli, args.password,
                  "bash /home/netlab/scenarios.sh /tmp/netverdict-lab",
                  timeout=420)
    if rc != 0:
        print(f"[run_remote] scenarios.sh rc={rc} — on rapatrie ce qui existe")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    got = []
    for name in sorted(sftp.listdir("/tmp/netverdict-lab")):
        if name.endswith(".pcap"):
            sftp.get(f"/tmp/netverdict-lab/{name}", str(outdir / name))
            got.append(name)
    sftp.close()
    cli.close()

    print(f"[run_remote] {len(got)} pcaps rapatries dans {outdir} :")
    for n in got:
        print(f"  {n}")
    print("[run_remote] valider avec : pytest tests/test_lab_pcaps.py -v")
    return 0


if __name__ == "__main__":
    sys.exit(main())
