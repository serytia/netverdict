#!/usr/bin/env bash
# Valide la jointure process<->flux AUDITD sur un vrai kernel Linux.
#
# Ce que ce scenario doit prouver, et que le snapshot ne peut PAS faire :
# retrouver le process d'un flux alors qu'il est DEJA MORT quand la capture
# s'arrete. C'est la transposition Linux du test Sysmon du 26/07.
#
# Deroulement : regle auditd sur connect() -> capture tcpdump -> un client
# ephemere se connecte puis meurt -> snapshot (qui ne le verra plus) ->
# export de audit.log. Le bundle produit se rejoue cote hote avec :
#   netverdict analyze capture.pcap --snapshot snapshot.json --audit audit.log
#
# Usage : sudo ./auditd_scenario.sh [outdir]      (defaut /tmp/netverdict-audit)
set -u

OUT="${1:-/tmp/netverdict-audit}"
mkdir -p "$OUT"
SRV_PORT=8080
SRV_IP=127.0.0.1

log() { echo "[audit-lab] $*"; }

# --- prerequis -------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then echo "root requis (sudo)" >&2; exit 2; fi
for bin in tcpdump auditctl ausearch python3 curl ss; do
    command -v "$bin" >/dev/null || { echo "$bin manquant (apt install auditd tcpdump)" >&2; exit 2; }
done

# --- regle auditd ----------------------------------------------------------
# arch=b64 : les regles auditd sont PAR ARCHITECTURE (le numero de syscall
# connect differe entre b32 et b64). On charge les deux pour couvrir un
# binaire 32 bits sur noyau 64 bits.
log "chargement de la regle connect()"
auditctl -D -k netverdict_connect 2>/dev/null || true
auditctl -a always,exit -F arch=b64 -S connect -k netverdict_connect
auditctl -a always,exit -F arch=b32 -S connect -k netverdict_connect 2>/dev/null || true
auditctl -l | grep -q netverdict_connect || { echo "regle non chargee" >&2; exit 1; }

# --- serveur cible ---------------------------------------------------------
# Sur loopback : le but est de valider la JOINTURE, pas le reseau. tcpdump
# capture lo sans probleme (contrairement a pktmon cote Windows, ou le
# loopback est invisible — difference documentee dans le README).
pkill -f netverdict_audit_srv 2>/dev/null || true
cat > /tmp/netverdict_audit_srv.py <<'PYEOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok" * 50
        self.send_response(200); self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 8080), H).serve_forever()
PYEOF
python3 /tmp/netverdict_audit_srv.py &
SRV_PID=$!
sleep 1

# --- capture ---------------------------------------------------------------
log "capture tcpdump sur lo"
tcpdump -i lo --immediate-mode -s 96 -U -w "$OUT/capture.pcap" \
    "tcp port $SRV_PORT" >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1.2

# --- le client ephemere : il se connecte, puis MEURT -----------------------
log "3 connexions par des process ephemeres (curl)"
for i in 1 2 3; do
    curl -s -o /dev/null "http://$SRV_IP:$SRV_PORT/" || true
    sleep 0.3
done
log "les curl sont morts — un snapshot ne peut plus les voir"

# --- snapshot APRES la mort des clients (c'est tout l'enjeu) ---------------
ss -H -tnp > "$OUT/.ss.txt" 2>/dev/null || true
python3 - "$OUT/.ss.txt" "$OUT/snapshot.json" <<'PYEOF'
import json, os, re, sys, time
conns = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    parts = line.split()
    if len(parts) < 5:
        continue
    def split_hp(s):
        host, _, port = s.rpartition(":")
        return host.strip("[]"), int(port) if port.isdigit() else 0
    lh, lp = split_hp(parts[3]); rh, rp = split_hp(parts[4])
    m = re.search(r'pid=(\d+)', line)
    proc = re.search(r'users:\(\("([^"]+)"', line)
    conns.append({"local_ip": lh, "local_port": lp, "remote_ip": rh,
                  "remote_port": rp, "state": parts[0],
                  "pid": int(m.group(1)) if m else None,
                  "process": proc.group(1) if proc else None})
json.dump({"host": os.uname().nodename, "os": "linux",
           "taken_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "connections": conns, "top_cpu": []},
          open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PYEOF
rm -f "$OUT/.ss.txt"

sleep 2
kill -INT "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null

# --- export du journal d'audit --------------------------------------------
# ausearch -i DECODE les champs (et perdrait le saddr brut dont on a besoin) :
# on exporte donc le format natif. -k filtre sur notre cle.
log "export du journal d'audit"
ausearch -k netverdict_connect --start recent --raw > "$OUT/audit.log" 2>/dev/null \
    || cp /var/log/audit/audit.log "$OUT/audit.log"

# Nettoyage : ne pas laisser une regle d'audit chargee sur la VM.
auditctl -D -k netverdict_connect 2>/dev/null || true
rm -f /tmp/netverdict_audit_srv.py

log "bundle pret :"
ls -l "$OUT"
grep -c "SOCKADDR" "$OUT/audit.log" 2>/dev/null \
    | xargs -I{} echo "[audit-lab] records SOCKADDR captures : {}"
