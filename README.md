# netverdict

[![PyPI](https://img.shields.io/pypi/v/netverdict)](https://pypi.org/project/netverdict/)
[![Python](https://img.shields.io/pypi/pyversions/netverdict)](https://pypi.org/project/netverdict/)
[![CI](https://github.com/serytia/netverdict/actions/workflows/ci.yml/badge.svg)](https://github.com/serytia/netverdict/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPLv2-blue)](LICENSE)

**The packet capture says whether the problem is the network, the application
or the host — with the evidence, and a suggested fix.**

🇫🇷 [Version française : README.fr.md](README.fr.md)

No more "it's the network / it's the app / it's the server" blame game.
`netverdict` reads a pcap (plus, when available, a snapshot of the host state
taken at the same moment), extracts the TCP signals that don't lie, and returns
an **argued verdict**:

```
$ netverdict analyze capture.pcapng

18 packets read — 18 TCP, 0 UDP, 0 ICMP, 0 other IP, 0 non-IP, 0 fragments, 0 unreadable — 1 conversations
┌─────────  APP — 10.0.0.42:51006 -> 10.0.0.5:5432 [high confidence] ─────────┐
│ Slow application response, reception proven by a fast ACK                   │
│   * 3 exchanges: server ACK in 5 ms but response in 800 ms (p50), 0 loss    │
│                                                                             │
│ Suggested fix:                                                              │
│   The network delivered the request (immediate ACK) and then waited for     │
│   the application. Look on the APPLICATION SIDE of 10.0.0.5:5432:           │
│   1. Internal processing time (application logs at the same timestamp)      │
│   2. Downstream dependencies: database, third-party API, DNS resolution     │
│      done BY the server — the stall is often one hop further back           │
│   3. Exhausted thread/connection pool (requests queuing up).                │
└─────────────────────────────────────────────────────────────────────────────┘
```

The reasoning is what an expert applies when reading a pcap in Wireshark —
encoded in a deterministic rule engine:

| Observed signature | Verdict |
|---|---|
| Repeated SYN with no answer | NETWORK (silent DROP or unreachable host) |
| ICMP admin-prohibited | NETWORK (explicit REJECT, the device is identified) |
| Immediate RST to SYN | APP (nothing listening on that port) |
| Massive retransmissions | NETWORK (loss on the path) |
| Zero window | HOST (the application stopped reading its socket) |
| Fast ACK but slow response | APP (the delay is inside the server, evidence attached) |
| ICMP fragmentation-needed | NETWORK (MTU/tunnel) |
| RST mid-session | AMBIGUOUS (firewall timeout, IPS, or crash — who sent it?) |

## Install

```
pip install netverdict                # analysis: no system dependency
pip install "netverdict[explain]"     # + narrative summary via the Claude API (optional)
pip install "netverdict[evtx]"        # + direct reading of binary .evtx files
```

From source (to contribute):

```
git clone https://github.com/serytia/netverdict
cd netverdict
pip install -e ".[dev]"
pytest
```

100% Python (dpkt). No Wireshark/tshark needed, neither on the analysis
machine nor on the servers.

## Output language

Console output defaults to **English** since 0.7.0. The tool was born French and
still speaks it fully — one flag, or one environment variable so you never have
to repeat it:

```
netverdict analyze capture.pcap --lang fr
export NETVERDICT_LANG=fr                 # Windows: $env:NETVERDICT_LANG="fr"
```

`--lang` translates verdict titles, evidence, suggested fixes, the timeline,
`--help`, error messages, and the language requested from the model by
`--explain`. `--lang` beats `$NETVERDICT_LANG`, which beats the default.

What `--lang` deliberately never changes: the verdict tokens (`RESEAU`, `APP`,
`OS`, `HOTE`, `AMBIGU`, `RAS`), `confidence` values and JSON keys. Those are
identifiers, not prose: they appear in user `--rules` files and in scripts
that filter the `--json` output. Translating them would break a
`verdict == "RESEAU"` check the day someone exports `NETVERDICT_LANG=en` —
with no signal at all. The *displayed* console label follows the language
(`NETWORK`, `HOST`...); the data doesn't move.

Custom rules (`--rules my-rules.yaml`) accept sibling fields
`title_en` / `evidence_en` / `remediation_en`. A rule without a translation
falls back to its French text whatever the requested language, without error.

## Usage

```
# Analyze an existing capture
netverdict analyze capture.pcapng
netverdict analyze capture.pcapng --json          # machine output
netverdict analyze capture.pcapng --explain       # + narrative summary (Claude API)

# Cross-reference with what changed in the infrastructure (timeline)
netverdict analyze capture.pcapng --events events.xml --syslog fw01.log
#   --events : Windows events (.evtx with the [evtx] extra, or an XML export:
#              wevtutil qe System /f:xml > events.xml)
#   --syslog : flat syslog files (mixed RFC3164/RFC5424 accepted)

# Timezone of RFC3164 lines (the format carries NONE). Required whenever the
# syslog does not come from a machine set like the analysis host: otherwise
# events shift out of the window, silently.
netverdict analyze capture.pcapng --syslog central.log --syslog-tz UTC
netverdict analyze capture.pcapng --syslog fw01.log    --syslog-tz Europe/Paris
netverdict analyze capture.pcapng --syslog fw01.log    --syslog-tz +02:00
#   UTC / IANA name / fixed offset. The IANA name handles DST.
#   No effect on RFC5424 lines, which carry their own timezone.

# WHERE are packets getting lost? Two captures of the same traffic, two points.
netverdict compare upstream.pcap downstream.pcap
#   upstream = near the client, downstream = near the server, captured
#   SIMULTANEOUSLY. A segment seen upstream and missing downstream was lost
#   BETWEEN the two points; if all are accounted for, the middle path is
#   cleared and the search moves past it. It is the only way to settle the
#   question without guessing. The two machines' clocks do not need to be
#   synchronized: the offset is estimated, and the tool stays silent about
#   latency rather than inventing one when it cannot estimate it.

# WHO owned the socket? The answer EVEN IF the process is already dead.
netverdict analyze capture.pcap --audit /var/log/audit/audit.log   # Linux
netverdict analyze capture.pcapng --events sysmon.xml              # Windows (Sysmon)
netverdict analyze capture.pcapng --events security.xml            # Windows (native WFP)
#   WFP = native Windows auditing, with NO agent to install:
#     auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
#     wevtutil qe Security /f:xml > security.xml
#     auditpol /set /subcategory:"Filtering Platform Connection" /success:disable
#   (very verbose: enable only for the duration of the diagnosis. 5157 also
#    names the process whose connection got BLOCKED — Sysmon stays silent.)
#   The host snapshot is taken at ONE instant: it misses a process that
#   exited before the capture ended. A journal dates every connection at
#   establishment time — attribution becomes retroactive.
#   Linux  : rule to load (once) —
#            auditctl -a always,exit -F arch=b64 -S connect -k netverdict_connect
#            (persistent: a file in /etc/audit/rules.d/)
#   Windows: Sysmon with NetworkConnect enabled —
#            sysmon -c netverdict/capture/sysmon-netverdict.xml
#   If the source is present but the rule is missing, the tool SAYS SO
#   instead of returning a silent report.
# The report adds the changes from the 15 minutes before the capture
# (service installed, firewall rule reloaded, switch to battery power...)
# and flags those that closely precede the incident.
#
# Relevant changes are ALSO attached to the affected flow, inside its verdict
# panel, under "Check first". A `*` marks a change type that can produce that
# exact verdict (firewall rule -> NETWORK, service crash -> APP,
# battery -> OS). It is a RANKING of suspects, never a causality conclusion:
# unrelated changes stay listed, further down.

# Assisted capture: traffic + host state in one go (admin/root console)
netverdict capture --duration 60                  # Windows: pktmon (native) / Linux: tcpdump

# List the verdict rules
netverdict rules
```

Exit code: `0` = nothing abnormal, `1` = at least one verdict, `2` = error.

Assisted capture is **truncated by default** (128 bytes/packet on Windows,
96 on Linux): enough for the analysis, and light.

**This is NOT a guarantee of credential absence**, contrary to what this
README claimed before 2026-07-25. Truncation cuts at N bytes *from the start
of the frame* — a packet shorter than N is therefore captured IN FULL,
payload included. Measured:

| Payload | `-s 96` | 128 B |
|---|---|---|
| `PASS hunter2` (cleartext POP3/FTP) | **complete** | **complete** |
| `USER admin` + `PASS ...` | **complete** | **complete** |
| `{"token":"eyJhbGciOi..."}` | **complete** | **complete** |
| `Authorization: Basic ...` header (51 B) | 42/51 B | **complete** |

In other words: truncation removes large transfers, not short secrets — and
cleartext authentication protocols are precisely short. Treat a bundle as
sensitive data: review it before sharing it, and reserve `--full-packets`
for when it is necessary and deliberate.

`--explain` never sends the pcap: only the JSON report (signals and verdicts).

## How it works

Two strictly separated stages, like decoders/rules in Wazuh:

1. **Measurement** (`pcap.py`, `flows.py`, `signals.py`): reading the capture,
   rebuilding TCP conversations, computing the signals — retransmissions
   (excluding capture duplicates and keepalives), RTT, zero window,
   application request->response delay, server ACK delay, attached ICMP.
   Facts only, no judgment.
2. **Verdict** (`rules/`): declarative YAML rules — conditions on the signals,
   verdict, confidence, interpolated evidence, written remediation. Every
   threshold is commented with its justification.

Add your own rules: `netverdict analyze ... --rules my_rules.yaml`
(same format as `netverdict/rules/builtin.yaml`).

## Platforms

| | Analysis (`analyze`) | Assisted capture | Process <-> flow join |
|---|---|---|---|
| Linux | yes | `capture.sh` (tcpdump + ss) | `--audit` (auditd) |
| Windows | yes | `capture.ps1` (pktmon, native) | `--events`: Sysmon EID 3, **or WFP 5156/5157 with no agent** |
| macOS | yes | no — capture with `tcpdump`, then analyze | no |

`compare` (two captures, two points) works on all three.

CI: Linux/Windows/macOS x Python 3.11-3.13, plus one job under a shifted
timezone, one with the extras installed, one against the built package.

## Validation status

- **Validated**: 462 automated tests, green on Linux, Windows and macOS
  (Python 3.11 to 3.13) and under a shifted timezone.
- **Validated against a kernel**: 8 failure scenarios reproduced by a real
  Linux kernel (netem, iptables, real sockets — `lab/`), plus the auditd join
  against a real auditd journal. The resulting pcaps serve as fixtures.
- **DNS validated against real servers**: 9 more scenarios answered by
  dnsmasq 2.91 and BIND 9.20 in network namespaces (`lab/dns_scenario.sh`).
  A `netem delay 1500ms` is measured at 1501 ms, including on a capture taken
  at `-s 96` where the answers are unreadable. That confrontation found one
  real defect — a TCP/53 retry merely *attempted* counted as a *successful*
  one, which silenced the verdict in exactly the case it exists to catch —
  and two defects in the test bench itself.
- **UDP validated against a kernel**: 5 scenarios (`lab/udp_scenario.sh`)
  where the ICMP errors are emitted by the Linux stack itself. One of them is
  a NEGATIVE WITNESS: a one-way syslog flow, on which netverdict must stay
  silent. It caught a real defect — the first version of the rule accused any
  unknown port, and five syslog datagrams were enough to raise a panel and
  flip the exit code.
- **Validated on a real incident**: full Windows capture chain (pktmon ->
  analysis) against a slow service, a closed port and a filtered port — all
  three verdicts exact.
- **Not done yet**: production incidents suffered (not provoked). Verdicts are
  an instrumented starting point, not an oracle — AMBIGUOUS is an owned
  verdict, and the report says what it could not read.

What these validations cost, and why they are listed here: each one found
defects that tests on fabricated data could not see — retransmission
detection broken by TSO/GSO, `pktmon` announcing one frame type and writing
another, `auditd` whose default format is not the one in its documentation,
and Windows failures triggered by Linux data. Hand-written fixtures describe
the tool you imagine; real execution describes the one that exists.

## Known limits (v1)

- TCP, DNS and UDP (IPv4/IPv6). No QUIC, no fragment reassembly. The
  packet-count line always adds up, so you can see what was left out.
- **UDP verdicts rest on ICMP, never on silence.** A closed port or an
  explicit REJECT is an act and yields a firm verdict; the absence of a reply
  is nothing, because syslog, NetFlow, StatsD and SNMP traps emit blind by
  design. Only ports known to answer (NTP, SNMP, RADIUS, TFTP, IKE…) allow
  anything to be said about a silence, and even then the verdict is
  AMBIGUOUS — a service can receive and deliberately ignore (unknown RADIUS
  secret, wrong SNMP community), which is indistinguishable from a DROP seen
  from the client.
- **DoH and DoT are invisible.** Encrypted resolution rides TCP/443 or
  TCP/853 and looks like any other connection. If a host resolves over DoH,
  netverdict sees the TCP flow to the resolver and nothing about the names.
- DNS answers are the first casualty of a tight snaplen: `tcpdump -s 96`
  leaves 54 bytes of payload, enough for the header and the question, rarely
  enough for the answer records. Latency, retries and response codes stay
  accurate (they live in the first 12 bytes); the resolved addresses do not,
  so flows cannot be named. The report says so instead of guessing — capture
  with `capture.sh -s 256` if you want the names.
- RTT p95 polluted by delayed ACKs (~40-200 ms): min and p50 are reliable.
  No rule therefore returns a NETWORK verdict on p95 alone. A high p95 is not
  ignored either: a healthy median with a significant tail produces an
  explicit AMBIGUOUS verdict ("latency spikes the capture cannot attribute")
  that names both possible causes — path jitter or delayed ACK — and gives
  what is needed to separate them. Neither a false network verdict, nor a
  false "transport healthy".
- Client/server direction estimated heuristically if the capture starts
  mid-session (flagged in the report).
- The host snapshot comes from a single machine (the one where the capture
  was launched). It is taken at ONE instant: it misses a process already dead
  by the end of the capture. The Sysmon join (Event ID 3) is retroactive and
  recovers it.
- Process <-> flow join: match on the EXACT four-tuple (both directions
  tested), TCP only, with 60 s of clock tolerance between capture and
  journal. A client port reused during the capture yields several candidates:
  the closest to the flow start is kept, and the report flags the ambiguity
  rather than hiding it.
- RFC3164 syslog (no timezone): by default timestamps are interpreted in the
  analysis machine's timezone, and the affected timestamps are marked `~` in
  the report. A UTC source read from a machine on local time then shifts OUT
  of the window, and the report shows "no infrastructure changes detected" —
  to be read as "nothing was retained", not "nothing changed". **Fix with
  `--syslog-tz`** (see Usage): timestamps become exact, the `~` disappears
  and the delay before the incident is given to the second.
- `--syslog-tz` with a FIXED offset (`+02:00`) is wrong on either side of a
  DST switch: a file that crosses the fall-back transition will be misdated
  on one half. Prefer an IANA name (`Europe/Paris`), which handles DST. On an
  ambiguous hour (the one that exists twice at fall-back), the first
  occurrence is kept.

## Roadmap

- v1.1 (done): multi-source timeline — Windows events (EVTX/XML) + syslog to
  answer "what changed in the infrastructure just before?".
- v1.2 (done): `--syslog-tz`, change->verdict correlation, retroactive
  process<->flow join via Sysmon Event ID 3. To enable the source (admin
  console):

  ```powershell
  sysmon -i -accepteula <path>\netverdict\capture\sysmon-netverdict.xml
  ```

  This configuration enables ONLY Event ID 3 (NetworkConnect), disabled by
  default in the Sysmon shipped with Windows 11 24H2. The 21 other event
  types are left `onmatch="include"` with no rule, which keeps them off —
  you don't turn on a full journal for one join.
- English output (`--lang en`) — done, see above.
- DNS resolutions (done): see below.
- v2: capture driven from both sides (client AND server) and comparison.

## DNS: the time TCP cannot show you

A slow resolution happens **before the SYN**. It is therefore outside
everything the TCP stage can measure — which is why, until v0.7, a capture
where the user waited 2.4 seconds produced this:

```
13 packets read — 10 TCP, 0 ICMP, 0 non-IP, 0 unreadable
[CLEAN] 1 conversation(s) with healthy transport          # exit code 0
```

The TCP verdict was right. The silence was not: three packets had vanished
from the count, and any monitoring wired to that exit code read "nothing
wrong". Now:

```
13 packets read — 10 TCP, 3 UDP, 0 ICMP, 0 other IP, 0 non-IP, 0 fragments, 0 unreadable

DNS resolutions — what happened BEFORE the connections
┌──────────  NETWORK — DNS api.corp.local (A) [high confidence] ──────────┐
│ Slow DNS resolution: the delay happens before the connection            │
│   * api.corp.local (A) resolved in 2400 ms by 10.0.0.53 after 2 queries │
│   * addresses returned: 10.0.0.5                                        │
│   * connection(s) that followed: 10.0.0.5:443                           │
└─────────────────────────────────────────────────────────────────────────┘
[CLEAN] 1 conversation(s) with healthy transport          # exit code 1
```

What it decides, from the same deterministic rule engine (`scope: dns`):

| Observed | Verdict |
|---|---|
| Repeated queries, no answer | NETWORK (resolver unreachable or filtered) |
| Answer only after retransmission | NETWORK (loss on the DNS path) |
| Answer in more than a second | NETWORK (the delay is before the connection) |
| SERVFAIL | APP (resolver fails: upstream, DNSSEC, broken zone) |
| REFUSED | NETWORK (ACL on the resolver) |
| NXDOMAIN | APP (typo, search suffix, missing record) |
| TC=1 with no TCP/53 retry | NETWORK (firewall allows UDP/53, forgot TCP/53) |
| One query, no answer, capture ends | AMBIGUOUS (undecidable, and it says so) |

DNS carried over **TCP/53** is decoded too (2-byte length prefix, segments
reassembled): a truncated answer followed by a successful TCP retry is no
longer mistaken for a failure. mDNS (5353) is decoded and counted, but the
accusing rules stand down there — a multicast question with no answer is how
the protocol works.

## UDP: what a datagram lets you say

| Observed | Verdict |
|---|---|
| ICMP port-unreachable | APP (nothing is listening — the UDP twin of RST-to-SYN) |
| ICMP administratively-prohibited | NETWORK (a device names itself and filters) |
| ICMP fragmentation-needed | NETWORK (datagram too large for the path) |
| A known request/reply service stays silent | AMBIGUOUS (DROP, or the service ignoring you) |
| Two-way exchange, no ICMP | CLEAN |
| Anything else with no reply | *nothing* — see the limits above |

Before v0.8 a stopped UDP service (RADIUS, SNMP, a syslog collector) produced
no verdict at all and exit code 0, even though the ICMP was sitting decoded in
the capture: it was attached to nothing.

Flows are also named: a TCP conversation preceded by the resolution that
produced its address carries that name, and — only when the resolution
immediately precedes it — the time it cost.

Rules live in `netverdict/rules/dns.yaml`. Your own `--rules` file can hold
both kinds: a rule is routed by its `scope` field (`flow` by default), so a
DNS rule never gets evaluated against a TCP flow by accident.

## License

GPL-2.0
