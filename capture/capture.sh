#!/usr/bin/env bash
# Capture assistee netverdict (Linux) : trafic + etat hote, en un coup.
#
# tcpdump en-tetes seuls (-s 96 : IP+TCP+options, aucun payload donc aucun
# secret dans le bundle) + snapshot au milieu de la fenetre : sockets avec
# process (ss -tnp), charge CPU, memoire, pression disque.
#
# Usage : sudo ./capture.sh [-d 60] [-o outdir] [-i host_cible] [-p port]
set -euo pipefail

DURATION=60
OUTDIR=""
TARGET_IP=""
TARGET_PORT=""

while getopts "d:o:i:p:" opt; do
  case "$opt" in
    d) DURATION="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    i) TARGET_IP="$OPTARG" ;;
    p) TARGET_PORT="$OPTARG" ;;
    *) echo "usage: $0 [-d sec] [-o dir] [-i ip] [-p port]" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "tcpdump exige root : relancer avec sudo." >&2
  exit 2
fi
command -v tcpdump >/dev/null || { echo "tcpdump absent (apt install tcpdump)" >&2; exit 2; }

OUTDIR="${OUTDIR:-./netverdict-capture-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
PCAP="$OUTDIR/capture.pcap"
SNAP="$OUTDIR/snapshot.json"

FILTER="tcp or icmp"
[ -n "$TARGET_IP" ] && FILTER="($FILTER) and host $TARGET_IP"
[ -n "$TARGET_PORT" ] && FILTER="($FILTER) and port $TARGET_PORT"

echo "Capture tcpdump ${DURATION}s -> $PCAP  (filtre: $FILTER)"
tcpdump -i any -s 96 -w "$PCAP" $FILTER &
TCPDUMP_PID=$!

sleep "$(( DURATION / 2 > 0 ? DURATION / 2 : 1 ))"
echo "Snapshot etat hote..."

# ss -H -tnp : etat + pid/process par socket, parse en python (present partout)
ss -H -tnp > "$OUTDIR/.ss.txt" || true
python3 - "$OUTDIR/.ss.txt" "$SNAP" <<'PYEOF'
import json, os, re, sys, time

ss_file, out = sys.argv[1], sys.argv[2]
conns = []
for line in open(ss_file, encoding="utf-8", errors="replace"):
    parts = line.split()
    if len(parts) < 5:
        continue
    state, _, _, local, peer = parts[0], parts[1], parts[2], parts[3], parts[4]
    m = re.search(r'pid=(\d+)', line)
    proc = re.search(r'users:\(\("([^"]+)"', line)
    def split_hp(s):
        host, _, port = s.rpartition(":")
        return host.strip("[]"), int(port) if port.isdigit() else 0
    lh, lp = split_hp(local)
    rh, rp = split_hp(peer)
    conns.append({"local_ip": lh, "local_port": lp, "remote_ip": rh,
                  "remote_port": rp, "state": state,
                  "pid": int(m.group(1)) if m else None,
                  "process": proc.group(1) if proc else None})

load1 = open("/proc/loadavg").read().split()[0]
mem = {}
for l in open("/proc/meminfo"):
    k, v = l.split(":", 1)
    mem[k] = int(v.strip().split()[0])

snapshot = {
    "host": os.uname().nodename,
    "os": "linux",
    "taken_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "cpu_pct": None,                       # load1 ci-dessous, plus parlant sous Linux
    "load1": float(load1),
    "mem_free_mb": mem.get("MemAvailable", 0) // 1024,
    "disk_busy_pct": None,
    "connections": conns,
    "top_cpu": [],
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(snapshot, f, indent=2)
PYEOF
rm -f "$OUTDIR/.ss.txt"

sleep "$(( DURATION - DURATION / 2 ))"
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

echo ""
echo "Bundle pret :"
echo "  $PCAP"
echo "  $SNAP"
echo ""
echo "Analyse :"
echo "  netverdict analyze \"$PCAP\" --snapshot \"$SNAP\""
