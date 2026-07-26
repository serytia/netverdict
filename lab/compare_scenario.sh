#!/usr/bin/env bash
# Valide `netverdict compare` sur DEUX captures reelles du meme trafic.
#
#   [hote] veth0 <-> veth1 [netns mid] veth2 <-- netem 15% --> veth3 [netns srv]
#      ^                                                            ^
#   tcpdump AMONT                                              tcpdump AVAL
#
# POURQUOI UN ROUTEUR INTERMEDIAIRE, ET PAS SIMPLEMENT UN NETEM SUR LE LIEN :
# mesure faite au lab le 26/07 (netem loss 50%, 20 pings) — tc a compte 16
# paquets jetes, et tcpdump sur la MEME interface n'en a vu aucun. La capture
# egress se fait donc APRES le qdisc : un paquet jete par netem sur le lien
# direct n'apparait NI en amont NI en aval, les deux captures restent
# identiques, et le scenario ne prouve rien.
#
# Avec un routeur au milieu, le paquet est bien capture en sortie de l'hote
# (point amont), puis jete plus loin par le routeur : il manque au point aval.
# C'est la seule facon de fabriquer une perte OBSERVABLE entre deux points,
# et c'est exactement ce que vit un vrai reseau.
#
# Usage : sudo ./compare_scenario.sh [outdir]     (defaut /tmp/netverdict-cmp)
set -u

OUT="${1:-/tmp/netverdict-cmp}"
mkdir -p "$OUT"
SRV_IP=10.99.1.2
PORT=8080

log() { echo "[cmp-lab] $*"; }

if [ "$(id -u)" -ne 0 ]; then echo "root requis (sudo)" >&2; exit 2; fi
for bin in tcpdump tc ip python3 curl; do
    command -v "$bin" >/dev/null || { echo "$bin manquant" >&2; exit 2; }
done

cleanup() {
    kill "${AMONT_PID:-}" "${AVAL_PID:-}" "${SRV_PID:-}" 2>/dev/null
    ip netns del srv 2>/dev/null
    ip netns del mid 2>/dev/null
    ip link del veth0 2>/dev/null
    ip route del 10.99.1.0/24 via 10.99.0.2 2>/dev/null
}
trap cleanup EXIT INT TERM
cleanup 2>/dev/null

# --- topologie a trois etages ---------------------------------------------
ip netns add mid
ip netns add srv
ip link add veth0 type veth peer name veth1
ip link set veth1 netns mid
ip netns exec mid ip link add veth2 type veth peer name veth3
ip netns exec mid ip link set veth3 netns srv

ip addr add 10.99.0.1/24 dev veth0
ip link set veth0 up
ip -n mid addr add 10.99.0.2/24 dev veth1
ip -n mid link set veth1 up
ip -n mid addr add 10.99.1.1/24 dev veth2
ip -n mid link set veth2 up
ip -n mid link set lo up
ip netns exec mid sysctl -qw net.ipv4.ip_forward=1
ip -n srv addr add 10.99.1.2/24 dev veth3
ip -n srv link set veth3 up
ip -n srv link set lo up

ip route add 10.99.1.0/24 via 10.99.0.2
ip -n srv route add default via 10.99.1.1

# --- serveur qui absorbe un upload ----------------------------------------
cat > /tmp/cmp_srv.py <<'PYEOF'
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        lu = 0
        while lu < n:
            bloc = self.rfile.read(min(65536, n - lu))
            if not bloc:
                break
            lu += len(bloc)
        self.send_response(201); self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("10.99.1.2", 8080), H).serve_forever()
PYEOF
ip netns exec srv python3 /tmp/cmp_srv.py > /tmp/cmp_srv.log 2>&1 &
SRV_PID=$!
# Attente ACTIVE du port : un `sleep` fixe pariait sur le temps de demarrage
# de python et perdait la course par moments — le scenario se deroulait alors
# entierement contre un serveur absent, produisant deux captures de 4 paquets
# et un verdict sans objet.
for _ in $(seq 1 40); do
    ip netns exec srv ss -tln 2>/dev/null | grep -q ":$PORT" && break
    sleep 0.25
done
if ! ip netns exec srv ss -tln 2>/dev/null | grep -q ":$PORT"; then
    echo "le serveur de test n'ecoute pas apres 10 s :" >&2
    cat /tmp/cmp_srv.log >&2
    exit 1
fi

# --- la perte est APRES le point de capture amont, dans le routeur ---------
log "netem : 15% de perte sur le lien mid -> srv"
ip netns exec mid tc qdisc add dev veth2 root netem loss 15%

log "capture AMONT (veth0, hote) et AVAL (veth3, srv)"
tcpdump -i veth0 --immediate-mode -s 96 -U -w "$OUT/amont.pcap" \
    "tcp port $PORT" >/dev/null 2>&1 &
AMONT_PID=$!
ip netns exec srv tcpdump -i veth3 --immediate-mode -s 96 -U \
    -w "$OUT/aval.pcap" "tcp port $PORT" >/dev/null 2>&1 &
AVAL_PID=$!
sleep 1.5

dd if=/dev/urandom of=/tmp/cmp-payload bs=1K count=600 2>/dev/null
log "upload de 600 Ko a travers le routeur"
curl -s -T /tmp/cmp-payload -o /dev/null --max-time 90 \
    "http://$SRV_IP:$PORT/up" || true

sleep 2
kill -INT "$AMONT_PID" "$AVAL_PID" 2>/dev/null
wait "$AMONT_PID" "$AVAL_PID" 2>/dev/null
ip netns exec mid tc -s qdisc show dev veth2 | head -3
rm -f /tmp/cmp-payload /tmp/cmp_srv.py

log "captures produites :"
ls -l "$OUT"/*.pcap
log "comparer sur l'hote :  netverdict compare amont.pcap aval.pcap"
