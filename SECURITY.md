# Security policy

## Reporting a vulnerability

Open a [security advisory](https://github.com/serytia/netverdict/security/advisories/new)
on GitHub, or a regular issue if the problem is not sensitive. Please do not
include real capture data in a public issue — see below.

There is no bug bounty. This is a single-maintainer project; expect a first
answer within a few days.

## What netverdict does with your data

Worth stating plainly, because the tool is fed packet captures:

- **Analysis is entirely local.** Reading a pcap, computing signals, matching
  rules and rendering the report never touch the network.
- **`--explain` is the one exception, and it is opt-in.** It sends the JSON
  report — signals and verdicts — to the Claude API. **It never sends the
  pcap.** But be precise about what that report contains, because it is more
  than verdicts:
  - IP addresses, ports, and resolved DNS names (your internal hostnames);
  - process names, PIDs and **usernames**, when host sources are used;
  - **the message body of every timeline entry** — that is, the actual text
    of the Windows events, syslog lines or audit records you passed with
    `--events` / `--syslog` / `--audit`, truncated to 300 characters each.
    Those lines routinely carry hostnames, account names, paths and
    command lines.

  Do not use `--explain` on data you are not allowed to send to a third
  party. Everything else works without it.
- **No telemetry, no auto-update, no phone-home.**

## Handling captures

A capture bundle is sensitive data, and more so than people expect:

- **Header truncation is not a guarantee that secrets are absent.** `tcpdump
  -s 96` and `pktmon --pkt-size 128` cut at N bytes *from the start of the
  frame*, so any packet shorter than N is captured **in full, payload
  included**. Measured on 2026-07-25: `PASS hunter2`, a complete FTP login and
  a short JSON token all pass through intact. Truncation removes large
  transfers, not short secrets — and cleartext authentication is precisely
  short.
- **DNS capture reveals internal names.** Since v0.8 the capture script also
  records UDP/53. Those datagrams carry your internal hostnames, which is
  often the most sensitive part of an infrastructure map.
- Treat the output of `netverdict capture` as you would a credentials file.

## Scope of use

netverdict analyses captures **you are authorised to analyse**. Capturing
traffic on a network you do not own or administer is illegal in most
jurisdictions. The tool provides no capability to intercept traffic it was not
given.

## Supported versions

The latest released version on PyPI receives fixes. Older versions do not.
