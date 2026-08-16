#!/usr/bin/env bash
# Capture assistee netverdict (Linux) : trafic + etat hote, en un coup.
#
# tcpdump tronque (-s 96 : de quoi lire IP+TCP+options) + snapshot au milieu de
# la fenetre : sockets avec process (ss -tnp), charge CPU, memoire, disque.
#
# ATTENTION : -s 96 n'est PAS une garantie d'absence de secret. tcpdump coupe a
# 96 octets DEPUIS LE DEBUT DE LA TRAME, donc tout paquet plus court est capture
# EN ENTIER, payload compris. Mesure du 25/07/2026 : "PASS hunter2", un login
# FTP complet et un jeton JSON court passent INTACTS. La troncature elimine les
# gros transferts, pas les secrets courts — et l'authentification en clair est
# precisement courte. Traiter le bundle comme une donnee sensible.
#
# Usage : sudo ./capture.sh [-d 60] [-o outdir] [-i host_cible] [-p port]
set -euo pipefail

DURATION=60
OUTDIR=""
TARGET_IP=""
TARGET_PORT=""
# 96 octets : de quoi lire IP + TCP + options, et l'en-tete DNS avec sa
# question. Les REPONSES DNS (nom -> adresse) tiennent rarement dedans : sans
# elles, netverdict mesure encore la latence et les codes de retour, mais ne
# peut plus nommer les connexions qui ont suivi - il le dit dans le rapport
# plutot que de le deviner. Monter a 128-256 les rend lisibles, au prix de
# capturer davantage de payload (voir l'avertissement ci-dessus).
SNAPLEN=96

while getopts "d:o:i:p:s:" opt; do
  case "$opt" in
    d) DURATION="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    i) TARGET_IP="$OPTARG" ;;
    p) TARGET_PORT="$OPTARG" ;;
    s) SNAPLEN="$OPTARG"
       # Valide TOUT DE SUITE : une valeur non numerique tue tcpdump a
       # l'instant zero, et le script annoncait quand meme « Bundle pret »
       # avec le chemin d'un pcap qui n'existait pas.
       case "$SNAPLEN" in
         ''|*[!0-9]*) echo "-s attend un nombre d'octets, recu: $SNAPLEN" >&2
                      exit 2 ;;
       esac
       [ "$SNAPLEN" -lt 64 ] && { echo "-s $SNAPLEN est trop petit pour lire un en-tete TCP (minimum 64)" >&2; exit 2; }
       ;;
    *) echo "usage: $0 [-d sec] [-o dir] [-i ip] [-p port] [-s snaplen]" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "tcpdump exige root : relancer avec sudo." >&2
  exit 2
fi
command -v tcpdump >/dev/null || { echo "tcpdump absent (apt install tcpdump)" >&2; exit 2; }
# ss etait suppose present : sur une image minimale (conteneur, Alpine) son
# absence etait avalee par un `|| true` et produisait un snapshot avec
# "connections": [] — que netverdict accepte sans broncher. Le rapport
# affichait alors un etat hote credible SANS jamais pouvoir attribuer un
# process : capacite silencieusement inerte (audit du 26/07).
command -v ss >/dev/null || { echo "ss absent (apt install iproute2) : sans lui le snapshot n'aurait aucune connexion" >&2; exit 2; }

OUTDIR="${OUTDIR:-./netverdict-capture-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
PCAP="$OUTDIR/capture.pcap"
SNAP="$OUTDIR/snapshot.json"

FILTER="tcp or icmp"
[ -n "$TARGET_IP" ] && FILTER="($FILTER) and host $TARGET_IP"
[ -n "$TARGET_PORT" ] && FILTER="($FILTER) and port $TARGET_PORT"
# Le DNS fait partie de la question posee. Une resolution lente ou en echec se
# produit AVANT le SYN : sans ces datagrammes, la capture montre une connexion
# parfaitement saine et netverdict n'a aucun moyen d'expliquer les secondes que
# l'utilisateur a subies. Le filtre les excluait jusqu'au 15/08/2026.
#
# AJOUTE HORS du ciblage, et c'est delibere : `-i 10.0.0.5` ou `-p 443`
# ecarteraient sinon les echanges avec le RESOLVEUR (qui n'est ni l'hote cible
# ni sur le port cible) et le service UDP en panne - c'est-a-dire precisement
# ce qu'on cherche.
#
# TOUT l'UDP, et pas seulement le port 53. La 0.8 sait diagnostiquer un
# service UDP arrete (RADIUS, SNMP, un collecteur syslog) grace a l'ICMP
# port-unreachable qui lui repond - mais sans les datagrammes UDP, aucune
# conversation n'est construite, l'ICMP ne se rattache a rien, et le rapport
# reste MUET avec un code retour 0. La fonctionnalite phare de la version
# etait donc inatteignable par le chemin que l'outil documente lui-meme
# (revue du 16/08/2026).
#
# Le surcout est reel et assume : l'UDP d'un serveur, c'est du syslog, du
# NetFlow, parfois du VXLAN. `-d` borne la duree, `-i`/`-p` bornent la
# cible, et le snaplen borne chaque paquet.
FILTER="($FILTER) or udp"

echo "Capture tcpdump ${DURATION}s -> $PCAP  (filtre: $FILTER, snaplen: $SNAPLEN)"
tcpdump -i any -s "$SNAPLEN" -w "$PCAP" $FILTER &
TCPDUMP_PID=$!
# Sans ce trap, une sortie anticipee (erreur du snapshot, Ctrl-C) laissait
# tcpdump orphelin en train d'ecrire indefiniment dans le fichier.
trap 'kill "$TCPDUMP_PID" 2>/dev/null' EXIT INT TERM

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
