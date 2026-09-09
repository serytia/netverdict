"""Generate a demo syslog corpus: 10,002 RFC 3164 lines in UTC, anchored on loss.pcap.

Two properties the demo relies on, so they are guaranteed here:
- `wc -l central.log`          -> 10002
- `grep -ci error central.log` -> exactly 400 (hence N_ERRORS)

The 400 error lines are realistic noise: none of them matches a netverdict
CHANGE_CATEGORIES pattern (change/power/network/service/reboot), so they fall
into the "error" bucket and can never become suspects. The only two real
infrastructure changes are appended explicitly at the end — those are the only
legitimate suspects the tool can find.

Usage:
    python gen_syslog_corpus.py        # writes central.log next to the script
    python gen_syslog_corpus.py --burst app-billing:900:-180

`--burst PROGRAM:LINES:OFFSET_S` appends a log burst: LINES lines from PROGRAM
on srv-app01, spread over one minute starting OFFSET_S seconds from the capture
(negative = before it). It is OFF by default, and it must stay off by default:
the two properties above are what the demo asserts, and a corpus that quietly
gained 900 lines would break them without a word.

Timestamps are anchored on tests/fixtures/lab/loss.pcap so the corpus lines up
with the capture: analyze them together with
    netverdict analyze loss.pcap --syslog central.log --syslog-tz UTC
"""

import argparse
import datetime as dt
import random

T0 = 1784923777.988  # t_first of tests/fixtures/lab/loss.pcap
N_TOTAL = 10000
N_ERRORS = 400

hosts = ["sw-core01", "sw-core02", "rtr-edge01", "srv-app01", "srv-db01", "fw01"]

noise = [
    ("sshd", "Accepted publickey for svc_backup from 10.0.0.31 port {n} ssh2"),
    ("cron", "(root) CMD (/usr/lib/sysstat/debian-sa1 1 1)"),
    ("snmpd", "Connection from UDP: [10.0.0.9]:{n}->[10.0.0.1]:161"),
    ("kernel", "TCP: request_sock_TCP: Possible SYN flooding on port {n}"),
    ("named", "client 10.0.0.44#{n}: query: pkg.example.net IN A +"),
    ("chronyd", "Selected source 10.0.0.2"),
    ("systemd", "Started Session {n} of user root."),
    ("postfix/smtpd", "connect from mail-relay.example.net[203.0.113.9]"),
]

# Error noise: the word "error"/"Errors" appears, but NO change keyword
# (no reload/config/firewall/package, no systemd started, no service|daemon
# with start/stop/fail, no interface up/down).
errors = [
    ("kernel", "EXT4-fs error (device sda1): ext4_lookup:1602: inode #{n}: "
               "comm backup: deleted inode referenced"),
    ("smartd", "Device: /dev/sda [SAT], SMART Usage Attribute: "
               "187 Reported_Uncorrect_Errors is {n}"),
    ("nginx", "[error] {n}#0: upstream timed out (110: Connection timed out) "
              "while reading upstream, client: 10.0.0.55"),
    ("snmpd", "error on subcontainer 'ia_addr' insert (-1)"),
]


def parse_burst(spec):
    """PROGRAM:LINES:OFFSET_S -> (program, lines, offset_s). Raises on garbage."""
    try:
        program, lines, offset = spec.split(":")
        return program, int(lines), float(offset)
    except ValueError:
        raise SystemExit(f"--burst: expected PROGRAM:LINES:OFFSET_S, got {spec!r}")


def burst_lines(program, count, offset_s, host="srv-app01", span_s=60.0):
    """A single application gone into an error loop: `count` identical-ish lines
    in one minute. No "error" word on purpose — the grep property of the corpus
    counts that word, and a burst is recognised by its RATE, not its wording."""
    out = []
    for i in range(count):
        ts = dt.datetime.fromtimestamp(
            T0 + offset_s + i * span_s / max(1, count), dt.timezone.utc)
        out.append((ts.timestamp(),
                    f"<27>{ts.strftime('%b %d %H:%M:%S')} {host} "
                    f"{program}[7231]: ORA-00060: deadlock detected while "
                    f"waiting for resource (session {1000 + i})"))
    return out


lines = []
random.seed(7)
for i in range(N_TOTAL):
    ts = dt.datetime.fromtimestamp(T0 - random.uniform(0, 6 * 3600), dt.timezone.utc)
    h = random.choice(hosts)
    pool = errors if i < N_ERRORS else noise
    tag, msg = random.choice(pool)
    pri = random.choice([30, 38, 86, 85])
    lines.append((ts.timestamp(),
                  f"<{pri}>{ts.strftime('%b %d %H:%M:%S')} {h} "
                  f"{tag}[{random.randint(400, 9999)}]: "
                  f"{msg.format(n=random.randint(1000, 65000))}"))

# The two real changes — the only legitimate suspects.
tsc = dt.datetime.fromtimestamp(T0 - 43, dt.timezone.utc)
lines.append((tsc.timestamp(), f"<30>{tsc.strftime('%b %d %H:%M:%S')} fw01 "
              f"firewalld[955]: firewall rules reloaded (policy commit 4471)"))
tsl = dt.datetime.fromtimestamp(T0 - 122, dt.timezone.utc)
lines.append((tsl.timestamp(), f"<28>{tsl.strftime('%b %d %H:%M:%S')} sw-core01 "
              f"ifplugd[812]: eth3: link down"))

# parse_known_args et non parse_args : ce fichier est AUSSI execute par la suite
# de tests via runpy.run_path(..., run_name="__main__"), donc avec le sys.argv de
# pytest. Refuser ces arguments-la ferait echouer le test de non-regression du
# corpus par defaut, qui est precisement la propriete que cette option ne doit
# pas casser. Le prix est connu et assume : une option mal orthographiee est
# ignoree en silence plutot que refusee.
_p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
_p.add_argument("--burst", metavar="PROGRAM:LINES:OFFSET_S", default=None,
                help="append a log burst (off by default)")
_args, _ignores = _p.parse_known_args()

if _args.burst:
    lines += burst_lines(*parse_burst(_args.burst))

lines.sort()
open("central.log", "w", encoding="utf-8").write(
    "\n".join(l for _, l in lines) + "\n")

n_err = sum(1 for _, l in lines if "error" in l.lower())
print(f"central.log: {len(lines)} lines, {n_err} containing 'error'")
