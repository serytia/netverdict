#!/usr/bin/env bash
# Genere les pcaps de VALIDATION TERRAIN de l'etage DNS, sur un vrai kernel et
# de VRAIS serveurs DNS (dnsmasq pour la plupart des cas, BIND pour la
# troncature - voir le scenario 6, qui explique pourquoi les deux).
#
# Pourquoi : les fixtures de tests/test_dns.py sont ecrites avec dpkt et lues
# par notre parseur - elles valident la mecanique, pas la realite. Ici, les
# messages sont produits par ces serveurs, les pertes par iptables, les delais
# par netem, la capture par tcpdump. Derivation independante de bout en bout.
#
# Topologie : un network namespace "res" (le resolveur) relie a l'hote par une
# paire veth. Les pannes s'appliquent DANS le namespace ; tcpdump capture cote
# hote, c'est-a-dire la ou un admin capturerait sur le client.
#
#   hote (client) 10.99.1.1 --- veth0 <=> veth1 --- netns res 10.99.1.2:53
#
# Deux pieges deja payes ailleurs dans ce lab, respectes ici :
#  - tcpdump doit tourner en --immediate-mode -U, sinon un scenario court rend
#    un pcap VIDE (les paquets dorment dans le ring kernel) ;
#  - ce script doit etre POUSSE COMME FICHIER puis execute, jamais colle dans
#    un `sudo bash -c` inline : un pkill -f s'y tuerait lui-meme.
#
# Usage : sudo ./dns_scenario.sh [outdir]     (defaut /tmp/netverdict-dns)
set -u  # pas -e : un scenario qui echoue ne doit pas priver les autres

OUT="${1:-/tmp/netverdict-dns}"
mkdir -p "$OUT"
HOST_IP=10.99.1.1
RES_IP=10.99.1.2
ZONE=corp.local
NAME=app.$ZONE

log() { echo "[dns-lab] $*"; }

cleanup_net() {
    ip netns exec res pkill dnsmasq 2>/dev/null || true
    ip netns del res 2>/dev/null || true
    ip link del veth0 2>/dev/null || true
}

setup_net() {
    cleanup_net
    ip netns add res
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns res
    ip addr add $HOST_IP/24 dev veth0
    ip link set veth0 up
    ip -n res addr add $RES_IP/24 dev veth1
    ip -n res link set veth1 up
    ip -n res link set lo up
}

# --- le resolveur : un VRAI dnsmasq, pas un serveur fabrique pour l'occasion.
# --local=/corp.local/ le rend AUTORITAIRE sur la zone : un nom absent y donne
# un NXDOMAIN authentique, la ou un dnsmasq non autoritaire repondrait REFUSED.
start_dnsmasq() {  # $1 = options supplementaires
    ip netns exec res pkill dnsmasq 2>/dev/null || true
    sleep 0.3
    ip netns exec res dnsmasq \
        --no-daemon --no-resolv --no-hosts \
        --listen-address=$RES_IP --bind-interfaces \
        --local=/$ZONE/ \
        --address=/$NAME/10.99.1.50 \
        ${1:-} >"$OUT/dnsmasq.log" 2>&1 &
    DNSMASQ_PID=$!
    sleep 1.0
}

start_capture() {  # $1 = nom, $2 = snaplen (defaut 256)
    local snap="${2:-256}"
    tcpdump -i veth0 --immediate-mode -s "$snap" -U -w "$OUT/$1.pcap" \
        'udp port 53 or tcp' >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 1.2   # tcpdump met parfois >0.5 s a s'armer (compilation BPF)
}
stop_capture() {
    sleep 1.5
    kill -INT "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
}

# dig sans EDNS : le buffer redevient 512 octets, seule facon d'obtenir une
# troncature UDP d'un serveur moderne (EDNS0 annonce 4096 et TC=1 disparait).
q() { dig @$RES_IP "$@" >>"$OUT/dig.log" 2>&1; }

need() {
    for b in "$@"; do
        command -v "$b" >/dev/null || { echo "manque: $b" >&2; return 1; }
    done
}

need tcpdump dig dnsmasq iptables named || {
    echo "installer: apt-get install -y tcpdump dnsutils dnsmasq bind9 iptables" >&2
    exit 2
}

setup_net
trap 'cleanup_net' EXIT

# ---------------------------------------------------------------- 1. sain
log "1/9 resolution saine"
start_dnsmasq
start_capture dns_clean
q "$NAME" A
stop_capture

# ------------------------------------------------------------ 2. NXDOMAIN
log "2/9 NXDOMAIN (nom absent d'une zone dont dnsmasq est autoritaire)"
start_capture dns_nxdomain
q "absent.$ZONE" A
stop_capture

# ------------------------------------------------------------- 3. REFUSED
# Hors de la zone locale et sans forwarder : dnsmasq refuse de servir.
log "3/9 REFUSED (question hors zone, aucun forwarder)"
start_capture dns_refused
q "quelquechose.ailleurs.invalid" A
stop_capture

# -------------------------------------------------------------- 4. lenteur
# netem sur l'EGRESS du namespace : c'est la REPONSE qui est retardee, donc le
# delai est visible depuis le client. (Un netem cote hote serait applique
# apres le point de capture et resterait invisible - lecon du lab compare.)
log "4/9 resolution lente (netem delay 1500ms sur la reponse)"
ip netns exec res tc qdisc add dev veth1 root netem delay 1500ms
start_capture dns_slow
q "$NAME" A +time=5
stop_capture
ip netns exec res tc qdisc del dev veth1 root 2>/dev/null

# ----------------------------------------------- 5. silence total (DROP)
log "5/9 aucune reponse (DROP des questions dans le namespace)"
ip netns exec res iptables -A INPUT -p udp --dport 53 -j DROP
start_capture dns_no_answer
q "$NAME" A +tries=3 +time=1
stop_capture
ip netns exec res iptables -D INPUT -p udp --dport 53 -j DROP

# ------------------------------------- 6. reponse tronquee sans repli TCP
# Beaucoup d'adresses pour un meme nom -> la reponse depasse 512 octets. Avec
# +noedns le client annonce un buffer de 512 : le serveur met TC=1. Le repli
# TCP/53 est ensuite jete, ce qui reproduit le pare-feu qui autorise UDP/53 et
# oublie TCP/53 - la panne qui n'apparait que le jour ou une zone grossit.
# Servi par BIND, pas par dnsmasq, et c'est une MESURE qui l'impose :
# dnsmasq 2.91 ne tronque jamais ses reponses locales (celles de --address).
# Confronte deux fois le 15/08 - client +noedns, puis client annoncant un
# buffer EDNS de 512 - il a renvoye 672 puis 683 octets avec TC=0, au-dela de
# la limite de 512 du RFC 1035. `--edns-packet-max` ne regit que le chemin
# FORWARDER, pas les reponses autoritaires. La premiere version du scenario
# croyait donc tester la troncature et ne testait rien : netverdict lisait
# correctement TC=0 et concluait « resolution saine » - le defaut etait dans
# le banc d'essai, pas dans l'outil.
log "6/9 reponse tronquee (TC=1, servie par BIND) et repli TCP/53 bloque"
ip netns exec res pkill dnsmasq 2>/dev/null; sleep 0.3
# Sous /etc/bind et /var/cache/bind, jamais /tmp : sur Debian, named est
# confine par APPARMOR et n'a pas le droit de lire ailleurs. Une premiere
# version posait la conf dans /tmp/bindlab et named mourait sur
# « open: /tmp/bindlab/named.conf: permission denied » MEME en root - la
# capture ne contenait alors qu'une question sans reponse, ce que netverdict
# a d'ailleurs correctement rendu (AMBIGU, « la capture s'arrete trop tot »).
BINDCONF=/etc/bind/nvlab.conf
BINDZONE=/var/cache/bind/nvlab.zone
cat > $BINDCONF <<EOF
options {
    directory "/var/cache/bind";
    pid-file "/var/cache/bind/nvlab.pid";
    listen-on port 53 { $RES_IP; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { any; };
    dnssec-validation no;
};
zone "$ZONE" { type master; file "$BINDZONE"; };
EOF
{
    echo "\$TTL 60"
    echo "@ IN SOA ns.$ZONE. root.$ZONE. ( 1 60 60 60 60 )"
    echo "@ IN NS ns.$ZONE."
    echo "ns IN A $RES_IP"
    for i in $(seq 1 40); do echo "big IN A 10.99.2.$i"; done
} > $BINDZONE
chmod 644 $BINDCONF $BINDZONE
# -g : premier plan et journal sur stderr, seule facon de voir pourquoi named
# refuse de demarrer (apparmor, zone invalide) au lieu d'un pcap vide.
ip netns exec res named -c $BINDCONF -g -u root \
    >"$OUT/named.log" 2>&1 &
NAMED_PID=$!
sleep 2.0
ip netns exec res iptables -A INPUT -p tcp --dport 53 -j DROP
start_capture dns_truncated
q "big.$ZONE" A +edns=0 +bufsize=512 +time=2 +tries=1
stop_capture
ip netns exec res iptables -D INPUT -p tcp --dport 53 -j DROP
kill "$NAMED_PID" 2>/dev/null; ip netns exec res pkill named 2>/dev/null
sleep 0.5

# --------------------------------- 7. la meme resolution lente, snaplen 96
# Valide la DEGRADATION HONNETE : a -s 96 les reponses sont coupees, donc les
# adresses sont illisibles et aucun flux ne peut etre nomme - mais la latence
# et le code de retour, qui vivent dans les douze premiers octets, doivent
# rester exacts. C'est la seule facon de prouver que le parseur maison sert a
# quelque chose.
log "7/9 resolution lente capturee a -s 96 (degradation attendue)"
start_dnsmasq
ip netns exec res tc qdisc add dev veth1 root netem delay 1500ms
start_capture dns_slow_snap96 96
q "$NAME" A +time=5
stop_capture
ip netns exec res tc qdisc del dev veth1 root 2>/dev/null

# --------------------------- 8. resolution lente PUIS connexion vers l'IP
# Le seul scenario qui valide le rattachement nom -> flux : sans lui, la
# fonctionnalite la plus visible de l'etage DNS n'aurait jamais ete confrontee
# a un vrai kernel.
#
# Approximation assumee : la resolution est faite par dig et la connexion par
# curl vers l'adresse obtenue, au lieu d'un unique client qui enchaine les
# deux. Le PCAP est identique - une resolution puis un SYN vers l'adresse
# resolue - et c'est tout ce que netverdict lit. Faire autrement demanderait
# de reecrire le resolv.conf de la VM, pour aucune difference observable.
log "8/9 resolution lente puis connexion TCP vers l'adresse resolue"
start_dnsmasq "--address=/srv.$ZONE/$RES_IP"
# --directory sur un repertoire DEDIE : sans lui, http.server sert le home de
# la VM et le pcap embarque son listing. Un fixture public ne doit dependre du
# contenu d'aucune machine - ni pour la confidentialite, ni pour pouvoir etre
# regenere a l'identique.
WEBDIR=/tmp/nvweb
rm -rf $WEBDIR && mkdir -p $WEBDIR
echo "netverdict lab" > $WEBDIR/index.html
ip netns exec res python3 -m http.server 8080 --bind $RES_IP \
    --directory $WEBDIR >>"$OUT/http.log" 2>&1 &
HTTP_PID=$!
sleep 0.8
ip netns exec res tc qdisc add dev veth1 root netem delay 1500ms
start_capture dns_then_flow
q "srv.$ZONE" A +time=5
# Le delai est retire APRES la resolution : la connexion qui suit doit etre
# saine, sinon on ne saurait pas si le temps perdu vient du DNS ou du TCP -
# et c'est exactement la distinction que l'etage existe pour faire.
ip netns exec res tc qdisc del dev veth1 root 2>/dev/null
curl -s -m 5 -o /dev/null "http://$RES_IP:8080/" || true
stop_capture
kill "$HTTP_PID" 2>/dev/null

# ------------------------- 9. reponse tronquee AVEC repli TCP/53 autorise
# Le pendant du scenario 6 : meme TC=1, mais le repli aboutit. Valide deux
# choses que rien d'autre ne couvre - la lecture d'un message DNS transporte
# par TCP (prefixe de longueur sur 2 octets, reassemblage des segments), et le
# fait qu'une reponse lue sur ce TCP disculpe la troncature.
log "9/9 reponse tronquee (TC=1) avec repli TCP/53 AUTORISE"
# dnsmasq (relance au scenario 8) occupe encore le port 53 : sans ce pkill,
# named ne peut pas s'y lier et c'est dnsmasq qui repond - NXDOMAIN, puisqu'il
# ne connait pas big.corp.local. Mesure du 15/08 : le scenario semblait
# fonctionner (une reponse arrivait bien en TCP) tout en testant le mauvais
# serveur. Troisieme defaut du banc d'essai trouve par cette confrontation,
# et le troisieme ou netverdict lisait parfaitement juste.
ip netns exec res pkill dnsmasq 2>/dev/null; sleep 0.5
ip netns exec res named -c $BINDCONF -g -u root >>"$OUT/named.log" 2>&1 &
NAMED_PID=$!
sleep 2.0
start_capture dns_truncated_tcp_ok
q "big.$ZONE" A +edns=0 +bufsize=512 +time=3 +tries=1
stop_capture
kill "$NAMED_PID" 2>/dev/null; ip netns exec res pkill named 2>/dev/null
sleep 0.5

ip netns exec res pkill dnsmasq 2>/dev/null
log "termine. pcaps :"
ls -la "$OUT"/*.pcap 2>/dev/null
