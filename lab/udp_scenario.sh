#!/usr/bin/env bash
# Genere les pcaps de VALIDATION TERRAIN de l'etage UDP, sur un vrai kernel.
#
# Ce que le kernel fournit ici et qu'aucune fixture ne peut donner : les
# erreurs ICMP sont emises par la pile Linux elle-meme (port ferme -> ICMP
# type 3 code 3), pas fabriquees par nous. C'est exactement ce qui portait le
# verdict manquant : avant cet etage, un service UDP arrete ne produisait
# AUCUN verdict et un code retour 0.
#
# Le dernier scenario est un TEMOIN NEGATIF : il verifie que netverdict SE
# TAIT sur un flux syslog unidirectionnel. C'est le garde-fou de tout l'etage
# - sans lui, un panneau AMBIGU apparaitrait sur a peu pres n'importe quelle
# capture de serveur.
#
#   hote (client) 10.99.2.1 --- veth0 <=> veth1 --- netns srv 10.99.2.2
#
# Usage : sudo ./udp_scenario.sh [outdir]     (defaut /tmp/netverdict-udp)
set -u

OUT="${1:-/tmp/netverdict-udp}"
mkdir -p "$OUT"
HOST_IP=10.99.2.1
SRV_IP=10.99.2.2

log() { echo "[udp-lab] $*"; }

cleanup_net() {
    ip netns exec srv pkill -f absorbeur 2>/dev/null || true
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

start_capture() {
    tcpdump -i veth0 --immediate-mode -s 256 -U -w "$OUT/$1.pcap" \
        'udp or icmp' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1.2
}
stop_capture() {
    sleep 1.5
    kill -INT "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
}

# Emet N datagrammes vers un port, depuis un port source fixe pour que la
# conversation soit une seule et meme.
envoyer() {  # $1 = port, $2 = nombre, $3 = intervalle, $4 = taille
    python3 - "$SRV_IP" "$1" "$2" "$3" "$4" <<'PY'
import socket, sys, time
ip, port, n, delai, taille = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("", 40000))
for i in range(n):
    try:
        s.sendto(b"\x01" * taille, (ip, port))
    except OSError:
        pass          # ICMP d'erreur remonte sur le socket : ce n'est pas fatal
    time.sleep(delai)
PY
}

need() {
    for b in "$@"; do
        command -v "$b" >/dev/null || { echo "manque: $b" >&2; return 1; }
    done
}
need tcpdump python3 iptables || {
    echo "installer: apt-get install -y tcpdump python3 iptables" >&2
    exit 2
}

setup_net
trap 'cleanup_net' EXIT

# ------------------------------------------- 1. port ferme (ICMP du kernel)
# Aucun listener : c'est la pile du namespace qui repond, toute seule.
log "1/5 port UDP ferme -> ICMP port-unreachable emis par le kernel"
start_capture udp_port_ferme
envoyer 1812 3 0.4 20
stop_capture

# --------------------------------------------------- 2. REJECT administratif
log "2/5 REJECT administratif (iptables --reject-with icmp-admin-prohibited)"
ip netns exec srv iptables -A INPUT -p udp --dport 1813 \
    -j REJECT --reject-with icmp-admin-prohibited
start_capture udp_reject
envoyer 1813 3 0.4 20
stop_capture
ip netns exec srv iptables -D INPUT -p udp --dport 1813 \
    -j REJECT --reject-with icmp-admin-prohibited

# ------------------------------------- 3. service connu muet (DROP sur NTP)
# Le port 123 est dans la liste des services qui repondent : le silence y est
# une information, contrairement au scenario 5.
log "3/5 NTP jete en silence (DROP) -> service cense repondre, muet"
ip netns exec srv iptables -A INPUT -p udp --dport 123 -j DROP
start_capture udp_ntp_muet
envoyer 123 3 0.5 48
stop_capture
ip netns exec srv iptables -D INPUT -p udp --dport 123 -j DROP

# ------------------------------------------------ 4. echange bidirectionnel
log "4/5 echange UDP normal (le service repond)"
ip netns exec srv python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("'$SRV_IP'", 1234))
for _ in range(10):
    data, addr = s.recvfrom(4096)
    s.sendto(b"pong", addr)
' >>"$OUT/echo.log" 2>&1 &
ECHO_PID=$!
sleep 0.8
start_capture udp_echange
envoyer 1234 3 0.3 20
stop_capture
kill "$ECHO_PID" 2>/dev/null

# ---------------------------------- 5. TEMOIN NEGATIF : syslog a sens unique
# Un vrai listener qui ne repond JAMAIS - le fonctionnement normal de syslog.
# netverdict doit rester muet : ni verdict, ni code retour a 1.
log "5/5 TEMOIN NEGATIF : syslog unidirectionnel, aucun verdict attendu"
ip netns exec srv python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("'$SRV_IP'", 514))
for _ in range(20):
    s.recvfrom(4096)          # absorbeur : recoit et ne repond jamais
' >>"$OUT/syslog.log" 2>&1 &
SYSLOG_PID=$!
sleep 0.8
start_capture udp_syslog_unidirectionnel
envoyer 514 5 0.2 40
stop_capture
kill "$SYSLOG_PID" 2>/dev/null

log "termine. pcaps :"
ls -la "$OUT"/*.pcap 2>/dev/null
