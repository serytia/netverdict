#!/usr/bin/env bash
# Genere les pcaps de VALIDATION TERRAIN de netverdict, sur un vrai kernel.
#
# Pourquoi ce script existe : les fixtures synthetiques (tests/make_fixtures.py)
# sont ecrites ET lues par dpkt — elles valident la mecanique du moteur mais
# s'auto-valident partiellement. Ici, les pannes sont reproduites par le kernel
# Linux lui-meme (netem, iptables, vraies sockets) et capturees par tcpdump :
# une derivation totalement independante. Si les verdicts concordent sur les
# deux familles de pcaps, on a une vraie preuve.
#
# Topologie : un network namespace "srv" (le serveur) relie a l'hote par une
# paire veth. Les pannes s'appliquent sur ce lien ; tcpdump capture cote hote.
#
#   hote (client) 10.99.0.1 --- veth0 <=> veth1 --- netns srv 10.99.0.2
#
# Usage : sudo ./scenarios.sh [outdir]      (defaut /tmp/netverdict-lab)
set -u  # pas -e : un scenario qui echoue ne doit pas priver les autres

OUT="${1:-/tmp/netverdict-lab}"
mkdir -p "$OUT"
HOST_IP=10.99.0.1
SRV_IP=10.99.0.2
PORT=8080

log() { echo "[lab] $*"; }

cleanup_net() {
    ip netns del srv 2>/dev/null || true
    ip link del veth0 2>/dev/null || true
}

setup_net() {
    cleanup_net
    ip netns add srv
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns srv
    ip addr add $HOST_IP/24 dev veth0
    ip link set veth0 up
    ip -n srv addr add $SRV_IP/24 dev veth1
    ip -n srv link set veth1 up
    ip -n srv link set lo up
}

# start_capture <name> ; stop_capture — en-tetes seuls, comme l'outil le veut
start_capture() {
    # Deux couches de buffering a neutraliser pour les scenarios courts
    # (rst : SYN->RST en ~1 ms) — diagnostique par matrice de variantes :
    # 1. le ring buffer de capture KERNEL livre par blocs avec un timeout
    #    d'environ 1-2 s sur une capture calme -> --immediate-mode ;
    # 2. le buffer d'ECRITURE stdio de tcpdump -> -U (packet-buffered).
    # Sans ca, un kill 0.5 s apres l'echange produit un pcap VIDE alors que
    # les paquets ont bien ete captes (ils sont encore dans le kernel).
    tcpdump -i veth0 --immediate-mode -s 96 -U -w "$OUT/$1.pcap" \
        tcp or icmp >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    # 1.2 s : tcpdump met parfois >0.5 s a s'armer (compilation BPF, promisc).
    sleep 1.2
}
stop_capture() {
    # 2 s : filet si --immediate-mode manque (vieux tcpdump) — laisse le
    # timeout de bloc kernel expirer avant d'arreter la capture.
    sleep 2
    kill -INT "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
}

srv_python() {  # lance un python3 dans le netns serveur, PID dans SRV_PID
    ip netns exec srv python3 -c "$1" &
    SRV_PID=$!
    sleep 0.7
}
kill_srv() { kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; }

# ---------------------------------------------------------------- scenarios

sc_clean() {
    log "clean : echanges HTTP rapides et sains"
    setup_net
    srv_python '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"x" * 500
        self.send_response(200); self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("10.99.0.2", 8080), H).serve_forever()'
    start_capture clean
    for i in 1 2 3; do curl -s -o /dev/null "http://$SRV_IP:$PORT/"; sleep 0.3; done
    stop_capture; kill_srv
}

sc_slow_app() {
    log "slow-app : le serveur ACK vite mais repond en 1.2 s"
    setup_net
    srv_python '
import http.server, time
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(1.2)                      # l app qui traine
        body = b"y" * 500
        self.send_response(200); self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("10.99.0.2", 8080), H).serve_forever()'
    start_capture slow_app
    for i in 1 2 3; do curl -s -o /dev/null "http://$SRV_IP:$PORT/"; done
    stop_capture; kill_srv
}

sc_drop() {
    log "drop : firewall DROP silencieux sur le port"
    setup_net
    ip netns exec srv iptables -A INPUT -p tcp --dport $PORT -j DROP
    start_capture drop
    curl -s -o /dev/null --connect-timeout 8 "http://$SRV_IP:$PORT/" || true
    stop_capture
}

sc_reject() {
    log "reject : firewall REJECT icmp-admin-prohibited"
    setup_net
    ip netns exec srv iptables -A INPUT -p tcp --dport $PORT \
        -j REJECT --reject-with icmp-admin-prohibited
    start_capture reject
    curl -s -o /dev/null --connect-timeout 5 "http://$SRV_IP:$PORT/" || true
    stop_capture
}

sc_rst() {
    log "rst : rien n'ecoute (RST au SYN)"
    setup_net
    start_capture rst
    curl -s -o /dev/null --connect-timeout 5 "http://$SRV_IP:$PORT/" || true
    stop_capture
}

sc_loss() {
    log "loss : 8 % de perte netem sur un UPLOAD de 2 Mo"
    # Subtilite de placement : la capture est sur veth0 (cote hote). Pour
    # qu'une retransmission soit VISIBLE dans la capture il faut voir les
    # deux exemplaires — donc la perte doit frapper APRES le point de
    # capture. netem root sur veth0 = egress hote->ns : ce sont les DATA
    # d'un upload client qui doivent passer par la (un download perdrait
    # surtout des ACKs, presque sans retransmission observable).
    setup_net
    tc qdisc add dev veth0 root netem loss 8% delay 5ms
    srv_python '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_PUT(self):
        n = int(self.headers.get("Content-Length", 0))
        read = 0
        while read < n:
            chunk = self.rfile.read(min(65536, n - read))
            if not chunk: break
            read += len(chunk)
        self.send_response(201); self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(("10.99.0.2", 8080), H).serve_forever()'
    dd if=/dev/urandom of=/tmp/netverdict-big bs=1M count=2 2>/dev/null
    start_capture loss
    curl -s -T /tmp/netverdict-big -o /dev/null --max-time 60 \
        "http://$SRV_IP:$PORT/upload" || true
    stop_capture; kill_srv
    rm -f /tmp/netverdict-big
    tc qdisc del dev veth0 root 2>/dev/null || true
}

sc_zero_window() {
    log "zero-window : le serveur accepte mais ne lit JAMAIS sa socket"
    setup_net
    srv_python '
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)   # petit buffer -> ZW rapide
s.bind(("10.99.0.2", 8080)); s.listen(1)
c, _ = s.accept()
time.sleep(15)                                            # ne recv() jamais'
    start_capture zero_window
    ip netns exec srv true  # noop
    python3 - <<'PYEOF' || true
import socket
c = socket.create_connection(("10.99.0.2", 8080), timeout=5)
c.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
c.settimeout(10)
try:
    for _ in range(200):
        c.send(b"A" * 4096)                # remplit les buffers -> zero window
except (socket.timeout, OSError):
    pass
PYEOF
    stop_capture; kill_srv
}

sc_jitter() {
    log "jitter : latence instable netem 60ms +/- 50ms"
    setup_net
    tc qdisc add dev veth0 root netem delay 60ms 50ms
    srv_python '
import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"j" * 500
        self.send_response(200); self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("10.99.0.2", 8080), H).serve_forever()'
    start_capture jitter
    for i in $(seq 1 8); do curl -s -o /dev/null "http://$SRV_IP:$PORT/"; done
    stop_capture; kill_srv
    tc qdisc del dev veth0 root 2>/dev/null || true
}

# -------------------------------------------------------------------- main

if [ "$(id -u)" -ne 0 ]; then echo "root requis (sudo)" >&2; exit 2; fi
for bin in tcpdump curl python3 tc iptables ip; do
    command -v "$bin" >/dev/null || { echo "$bin manquant" >&2; exit 2; }
done

sc_clean
sc_slow_app
sc_drop
sc_reject
sc_rst
sc_loss
sc_zero_window
sc_jitter
cleanup_net

log "pcaps generes :"
ls -l "$OUT"/*.pcap
log "rapatrier puis analyser avec netverdict analyze <fichier>"
