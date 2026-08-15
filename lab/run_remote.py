"""Pilote la VM lab depuis l'hote : outils, scenarios, rapatriement des pcaps.

    python lab/run_remote.py            # scenarios TCP (defaut)
    python lab/run_remote.py --script dns_scenario.sh \\
        --remote-dir /tmp/netverdict-dns \\
        --packages "tcpdump dnsutils dnsmasq bind9 iptables iproute2"

Fait, dans l'ordre :
1. installe les paquets demandes dans la VM (idempotent),
2. pousse le script de lab/ et l'execute en root (sortie streamee),
3. rapatrie les *.pcap vers tests/fixtures/lab/.

Le script est POUSSE COMME FICHIER, jamais colle dans un `sudo bash -c`
inline : un `pkill -f` s'y tuerait lui-meme, la cmdline contenant le motif.

Ensuite : pytest tests/test_lab_pcaps.py tests/test_lab_dns.py valide les
verdicts terrain. Necessite paramiko (dependance de dev, pas de l'outil).
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
import time
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
    # Le lab a plusieurs jeux de scenarios (TCP, auditd, compare, DNS) : ils
    # partagent la meme mecanique de pilotage, seuls le script, le repertoire
    # distant et les paquets changent.
    ap.add_argument("--script", default="scenarios.sh",
                    help="script de lab/ a executer (defaut : scenarios.sh)")
    ap.add_argument("--remote-dir", default="/tmp/netverdict-lab",
                    help="repertoire de sortie DANS la VM")
    ap.add_argument("--packages",
                    default="tcpdump iptables curl python3",
                    help="paquets a installer avant l'execution")
    args = ap.parse_args()
    if not args.password:
        ap.error("mot de passe absent : definir NETLAB_PASSWORD dans "
                 "l'environnement, ou passer --password")

    cli = paramiko.SSHClient()
    # Lab local jetable derriere un NAT VirtualBox : TOFU acceptable ici,
    # a ne jamais recopier vers de l'infra reelle.
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[run_remote] connexion {args.user}@{args.host}:{args.port}")
    # Le port forward VirtualBox accepte la connexion des que la VM est
    # allumee, bien AVANT que sshd ne reponde : sans attente, une VM qui vient
    # de demarrer donne « Error reading SSH protocol banner », qui se lit comme
    # une panne alors que le systeme boote encore.
    derniere = None
    for essai in range(1, 31):
        try:
            cli.connect(args.host, port=args.port, username=args.user,
                        password=args.password, timeout=10,
                        look_for_keys=False, allow_agent=False)
            break
        except paramiko.AuthenticationException:
            raise                       # un mauvais mot de passe ne s'arrange pas
        except Exception as e:
            derniere = e
            if essai == 1:
                print("[run_remote] la VM ne repond pas encore, attente du boot")
            time.sleep(5)
    else:
        print(f"[run_remote] VM injoignable apres 30 essais : {derniere}",
              file=sys.stderr)
        return 1

    print("[run_remote] installation des outils (idempotent)...")
    rc = sudo_run(cli, args.password,
                  "apt-get update -qq && DEBIAN_FRONTEND=noninteractive "
                  f"apt-get install -y -qq {args.packages}")
    if rc != 0:
        print(f"[run_remote] ECHEC apt (rc={rc})")
        return rc
    # Un resolveur installe en paquet demarre en service et occupe le port 53 :
    # les scenarios DNS lancent le leur dans un namespace, celui de l'hote
    # doit se taire.
    sudo_run(cli, args.password,
             "systemctl stop dnsmasq named bind9 2>/dev/null; "
             "systemctl disable dnsmasq named bind9 2>/dev/null; true")

    print(f"[run_remote] envoi de {args.script}...")
    sftp = cli.open_sftp()
    distant = f"/home/netlab/{Path(args.script).name}"
    sftp.put(str(REPO / "lab" / args.script), distant)

    print("[run_remote] execution des scenarios (quelques minutes)...")
    rc = sudo_run(cli, args.password,
                  f"bash {distant} {args.remote_dir}",
                  timeout=900)
    if rc != 0:
        print(f"[run_remote] scenarios.sh rc={rc} — on rapatrie ce qui existe")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    got = []
    for name in sorted(sftp.listdir(args.remote_dir)):
        if name.endswith(".pcap"):
            sftp.get(f"{args.remote_dir}/{name}", str(outdir / name))
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
