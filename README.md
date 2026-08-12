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

18 packets read — 18 TCP, 0 ICMP, 0 non-IP, 0 unreadable — 1 conversations
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

- **Validated**: 323 automated tests, green on Linux, Windows and macOS
  (Python 3.11 to 3.13) and under a shifted timezone.
- **Validated against a kernel**: 8 failure scenarios reproduced by a real
  Linux kernel (netem, iptables, real sockets — `lab/`), plus the auditd join
  against a real auditd journal. The resulting pcaps serve as fixtures.
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

- TCP/IPv4-IPv6 only (no UDP/QUIC, no fragment reassembly).
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
- v2: capture driven from both sides (client AND server) and comparison.

## License

GPL-2.0
