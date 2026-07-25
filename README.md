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

# v1.1 : croiser avec ce qui a change dans l'infra (timeline)
netverdict analyze capture.pcapng --events events.xml --syslog fw01.log
#   --events : events Windows (.evtx avec l'extra [evtx], ou export XML :
#              wevtutil qe System /f:xml > events.xml)
#   --syslog : fichiers syslog plats (RFC3164/RFC5424 melanges acceptes)

# Fuseau des lignes RFC3164 (le format n'en porte AUCUN). A donner des que le
# syslog ne vient pas d'une machine reglee comme le poste d'analyse : sinon les
# evenements se decalent et sortent de la fenetre, en silence.
netverdict analyze capture.pcapng --syslog central.log --syslog-tz UTC
netverdict analyze capture.pcapng --syslog fw01.log    --syslog-tz Europe/Paris
netverdict analyze capture.pcapng --syslog fw01.log    --syslog-tz +02:00
#   UTC / nom IANA / decalage fixe. Le nom IANA gere l'heure d'ete (sur Windows,
#   il demande `pip install tzdata` ; le decalage fixe marche partout).
#   Sans effet sur les lignes RFC5424, qui portent deja leur fuseau.
# Le rapport ajoute les changements des 15 min precedant la capture
# (service installe, regle firewall rechargee, passage sur batterie...)
# et marque ceux qui precedent l'incident de peu.
#
# v1.2 : les changements pertinents sont AUSSI rattaches au flux concerne,
# directement dans son panneau de verdict, sous « A verifier en premier ».
# Un `*` signale un type de changement pouvant produire ce verdict precis
# (regle firewall -> RESEAU, crash de service -> APP, batterie -> OS).
# C'est un CLASSEMENT de suspects, jamais une conclusion de causalite : les
# changements sans affinite restent affiches, plus bas.

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
  Il est pris a UN instant : il rate le process deja mort a la fin de la
  capture. La jointure Sysmon (Event ID 3), elle, est retroactive et le
  retrouve — voir « Jointure process » ci-dessous.
- Jointure process <-> flux : correspondance sur le quadruplet EXACT (les deux
  sens sont testes), TCP uniquement, avec 60 s de tolerance d'horloge entre la
  capture et le journal. Un port client reutilise pendant la capture produit
  plusieurs candidats : le plus proche du debut du flux est retenu, et le
  rapport signale l'ambiguite plutot que de la taire.
- Syslog RFC3164 (sans fuseau) : par defaut l'heure est interpretee dans le
  fuseau du poste d'analyse, et les horodatages concernes sont marques `~`
  dans le rapport. Une source en UTC lue depuis un poste en heure locale se
  decale alors HORS de la fenetre, et le rapport affiche « aucun changement
  detecte » — a lire comme « rien n'a ete retenu », pas comme « rien n'a
  change ». **Corriger avec `--syslog-tz`** (voir Usage) : les horodatages
  deviennent exacts, le `~` disparait et le delai avant l'incident est donne
  a la seconde.
- `--syslog-tz` avec un decalage FIXE (`+02:00`) est faux de part et d'autre
  d'un changement d'heure : un fichier qui traverse le passage a l'heure
  d'hiver sera mal date sur une moitie. Preferer un nom IANA
  (`Europe/Paris`), qui gere l'heure d'ete. Sur une heure ambigue (celle qui
  existe deux fois lors du retour a l'heure d'hiver), la premiere occurrence
  est retenue.

## Roadmap

- v1.1 (fait) : timeline multi-sources — events Windows (EVTX/XML) + syslog
  pour repondre a "qu'est-ce qui a change dans l'infra juste avant ?".
- v1.2 (fait) : `--syslog-tz`, correlation changement->verdict, jointure
  process<->flux retroactive via Sysmon Event ID 3. **Reste a valider sur un
  vrai enregistrement Sysmon** (`sysmon -i` demande une console admin) : les
  noms de champs viennent du schema du binaire, la forme du XML est celle des
  evenements Windows standards deja parses par sources/evtx.py.
- v2 : capture pilotee des deux cotes (client ET serveur) et comparaison.

## Licence

GPL-2.0
