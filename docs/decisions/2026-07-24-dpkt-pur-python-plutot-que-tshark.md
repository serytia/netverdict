# dpkt pur Python plutot que tshark/pyshark

Date : 2026-07-24
Statut : accepte

## Contexte

Le parseur pcap est le socle de l'outil. Deux voies : deleguer la dissection a
tshark (sous-process, JSON) qui offre tcp.analysis.* gratuitement, ou parser
en Python pur avec dpkt et reimplementer l'analyse TCP nous-memes.

## Decision

dpkt pur Python. On reimplemente le sous-ensemble d'analyse TCP necessaire
(retransmissions, RTT, zero window, TTFB, dedup capture, keepalives).

## Justification

1. **Zero dependance systeme** : `pip install netverdict` et ca marche sur un
   poste d'admin nu. Wireshark (~200 Mo) est absent de la plupart des machines
   ou l'on veut trier un incident — l'exiger tuerait le "zero deploiement",
   qui est l'argument produit n°1.
2. **L'analyse TCP est le coeur de la valeur, pas un cout accidentel** : la
   posseder permet de la tester finement (18 tests) et d'y integrer des
   subtilites que tshark n'expose pas simplement (delai d'ACK serveur separe
   du TTFB, politique keepalive/dup-capture explicite).
3. pyshark a ete ecarte d'office : wrapper fragile autour de tshark (asyncio,
   fuites de handles) qui cumule les inconvenients des deux mondes.

## Consequences

- Le perimetre protocolaire est volontairement etroit (TCP + ICMP). Pas de
  dissection applicative fine (HTTP/TLS) en v1 — le TTFB au niveau TCP suffit
  pour trancher reseau vs app.
- Les captures en-tetes seuls sont supportees par construction (longueurs
  calculees depuis les en-tetes IP/TCP, jamais depuis les octets captures).
- Le risque d'erreur de reimplementation est couvert par deux familles de
  fixtures : synthetiques (dpkt) ET generees par un vrai kernel (lab VM).
