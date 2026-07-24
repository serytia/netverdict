# netverdict

**La capture reseau dit si le probleme vient du reseau, de l'application ou du
systeme — avec les preuves, et une piste de correction.**

Fini le blame game "c'est le reseau / c'est l'appli / c'est le serveur".
`netverdict` lit un pcap (et si possible un snapshot de l'etat de l'hote pris
au meme moment), en extrait les signaux TCP qui ne mentent pas, et rend un
**verdict argumente** :

```
$ netverdict analyze capture.pcapng --snapshot snapshot.json

18 paquets lus - 18 TCP, 0 ICMP, 0 non-IP, 0 illisibles - 1 conversations
+---------  APP - 10.0.0.42:51006 -> 10.0.0.5:5432 [confiance haute] --------+
| Reponse applicative lente, reception prouvee par ACK rapide                |
|   * 3 echanges : ACK serveur en 5 ms mais reponse en 800 ms (p50), 0 perte |
|   * etat hote : [SRV-DB01] socket detenue par postgres (pid 4212),         |
|     cpu machine 22%, disque 97%, ram libre 512 Mo                          |
|                                                                            |
| Piste de correction :                                                      |
|   Le reseau a livre la requete (ACK immediat) puis a attendu l'application.|
|   Chercher COTE APPLICATIF de 10.0.0.5:5432 : ...                          |
+----------------------------------------------------------------------------+
```

Le raisonnement est celui qu'un expert applique en lisant un pcap dans
Wireshark — encode dans un moteur de regles deterministe :

| Signature observee | Verdict |
|---|---|
| SYN repetes sans reponse | RESEAU (DROP silencieux ou hote injoignable) |
| ICMP admin-prohibited | RESEAU (REJECT explicite, l'equipement est identifie) |
| RST immediat au SYN | APP (rien n'ecoute sur ce port) |
| Retransmissions massives | RESEAU (perte sur le chemin) |
| Zero window | HOTE (l'application ne lit plus sa socket) |
| ACK rapide mais reponse lente | APP (le delai est dans le serveur, preuve a l'appui) |
| ICMP fragmentation-needed | RESEAU (MTU/tunnel) |
| RST en pleine session | AMBIGU (timeout firewall, IPS, ou crash — qui a emis ?) |

## Installation

```
pip install netverdict            # analyse : aucune dependance systeme
pip install netverdict[explain]   # + synthese narrative via l'API Claude (optionnel)
```

100 % Python (dpkt). Pas besoin de Wireshark/tshark, ni sur le poste
d'analyse, ni sur les serveurs.

## Usage

```
# Analyser une capture existante
netverdict analyze capture.pcapng
netverdict analyze capture.pcapng --json          # sortie machine
netverdict analyze capture.pcapng --explain       # + synthese narrative (API Claude)

# Capture assistee : trafic + etat hote en un coup (console admin/root)
netverdict capture --duration 60                  # Windows: pktmon (natif) / Linux: tcpdump

# Lister les regles de verdict
netverdict rules
```

Code retour : `0` = rien d'anormal, `1` = au moins un verdict, `2` = erreur.

La capture assistee est **en-tetes seuls par defaut** (128 octets/paquet) :
suffisant pour l'analyse, leger, et aucun payload — donc aucun credential —
dans le bundle. L'option `--explain` n'envoie jamais le pcap : uniquement le
rapport JSON (signaux et verdicts).

## Comment ca marche

Deux etages strictement separes, comme decodeurs/regles dans Wazuh :

1. **Mesure** (`pcap.py`, `flows.py`, `signals.py`) : lecture de la capture,
   reconstruction des conversations TCP, calcul des signaux — retransmissions
   (avec exclusion des doublons de capture et des keepalives), RTT, zero
   window, delai requete->reponse applicatif, delai d'ACK serveur, ICMP
   rattaches. Que des faits, aucun jugement.
2. **Verdict** (`rules/`) : regles declaratives YAML — conditions sur les
   signaux, verdict, confiance, preuves interpolees, remediation redigee.
   Chaque seuil est commente avec sa justification.

Ajouter ses propres regles : `netverdict analyze ... --rules mes_regles.yaml`
(meme format que `netverdict/rules/builtin.yaml`).

## Statut de validation

- **Valide** : 18 tests automatises — 9 scenarios de panne de bout en bout
  (pcaps synthetiques) + cas de bord (wraparound de sequence, doublons de
  capture, keepalives, capture demarree en pleine session, troncature
  en-tetes seuls).
- **En cours** : validation terrain sur pcaps generes par un vrai kernel
  Linux (lab VM : netem, iptables, vraies sockets — voir `lab/`).
- **Pas encore fait** : incidents reels de production. Les verdicts sont un
  point de depart outille, pas un oracle — le AMBIGU est un verdict assume.

## Limites connues (v1)

- TCP/IPv4-IPv6 uniquement (pas d'UDP/QUIC, pas de reassemblage de fragments).
- RTT p95 pollue par les delayed ACK (~40-200 ms) : min et p50 sont fiables.
- Sens client/serveur estime par heuristique si la capture demarre en pleine
  session (signale dans le rapport).
- Le snapshot hote vient d'une seule machine (celle ou on a lance la capture).

## Roadmap

- v1.1 : timeline multi-sources — events Windows (EVTX) + syslog pour
  repondre a "qu'est-ce qui a change dans l'infra juste avant ?".
- v2 : capture pilotee des deux cotes (client ET serveur) et comparaison.

## Licence

GPL-2.0
