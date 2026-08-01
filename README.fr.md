# netverdict

[![PyPI](https://img.shields.io/pypi/v/netverdict)](https://pypi.org/project/netverdict/)
[![Python](https://img.shields.io/pypi/pyversions/netverdict)](https://pypi.org/project/netverdict/)
[![CI](https://github.com/serytia/netverdict/actions/workflows/ci.yml/badge.svg)](https://github.com/serytia/netverdict/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-GPLv2-blue)](LICENSE)

**La capture reseau dit si le probleme vient du reseau, de l'application ou du
systeme — avec les preuves, et une piste de correction.**

🇬🇧 [English version: README.md](README.md)

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
pip install netverdict                # analyse : aucune dependance systeme
pip install "netverdict[explain]"     # + synthese narrative via l'API Claude (optionnel)
pip install "netverdict[evtx]"        # + lecture directe des .evtx binaires
```

Depuis les sources (pour contribuer) :

```
git clone https://github.com/serytia/netverdict
cd netverdict
pip install -e ".[dev]"
pytest
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
#   UTC / nom IANA / decalage fixe. Le nom IANA gere l'heure d'ete.
#   Sans effet sur les lignes RFC5424, qui portent deja leur fuseau.

# OU les paquets se perdent-ils ? Deux captures du meme trafic, deux points.
netverdict compare amont.pcap aval.pcap
#   amont = pres du client, aval = pres du serveur, captures SIMULTANEES.
#   Un segment vu en amont et absent en aval s'est perdu ENTRE les deux
#   points ; s'ils sont tous retrouves, le chemin intermediaire est hors de
#   cause et il faut chercher au-dela. C'est le seul moyen de trancher sans
#   supposition. Les horloges des deux machines n'ont pas besoin d'etre
#   synchronisees : le decalage est estime, et l'outil se tait sur la latence
#   plutot que d'en inventer une quand il ne peut pas l'estimer.

# Qui detenait la socket ? La reponse MEME SI le process est deja mort.
netverdict analyze capture.pcap --audit /var/log/audit/audit.log   # Linux
netverdict analyze capture.pcapng --events sysmon.xml              # Windows (Sysmon)
netverdict analyze capture.pcapng --events security.xml            # Windows (WFP natif)
#   WFP = audit natif Windows, SANS installer d'agent :
#     auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
#     wevtutil qe Security /f:xml > security.xml
#     auditpol /set /subcategory:"Filtering Platform Connection" /success:disable
#   (tres verbeux : a activer le temps du diagnostic. 5157 dit aussi quel
#    process s'est fait BLOQUER une connexion — Sysmon, lui, reste muet.)
#   Le snapshot d'etat hote est pris a UN instant : il rate le process qui
#   s'est termine avant la fin de la capture. Un journal, lui, date chaque
#   connexion a son etablissement — l'attribution devient retroactive.
#   Linux  : regle a charger (une fois) —
#            auditctl -a always,exit -F arch=b64 -S connect -k netverdict_connect
#            (persistant : un fichier dans /etc/audit/rules.d/)
#   Windows: Sysmon avec NetworkConnect actif —
#            sysmon -c netverdict/capture/sysmon-netverdict.xml
#   Si la source est presente mais la regle absente, l'outil le DIT au lieu
#   de rendre un rapport muet.
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

# Sortie en anglais (defaut : francais). Disponible sur toutes les
# sous-commandes, et via l'environnement pour ne pas la repeter :
netverdict analyze capture.pcap --lang en
export NETVERDICT_LANG=en                         # Windows : $env:NETVERDICT_LANG="en"
```

Code retour : `0` = rien d'anormal, `1` = au moins un verdict, `2` = erreur.

### Langue de la sortie

`--lang {fr,en}` traduit **tout ce qu'un humain lit** : titres de verdict,
preuves, pistes de correction, timeline, `--help`, messages d'erreur, et la
langue demandee au modele par `--explain`. Le defaut reste `fr` ; `--lang`
prime sur `$NETVERDICT_LANG`, qui prime sur le defaut.

Ce que `--lang` ne change **jamais**, volontairement : les jetons de verdict
(`RESEAU`, `APP`, `OS`, `HOTE`, `AMBIGU`, `RAS`), les valeurs de `confidence`
et les cles du JSON. Ce sont des identifiants, pas de la prose : ils
apparaissent dans les fichiers `--rules` et dans les scripts qui filtrent la
sortie `--json`. Les traduire ferait casser un `verdict == "RESEAU"` le jour
ou quelqu'un exporte `NETVERDICT_LANG=en` — sans le moindre message. Le
libelle *affiche* en console suit la langue (`NETWORK`, `HOST`...), la donnee
ne bouge pas.

Les regles personnelles (`--rules mes-regles.yaml`) acceptent les champs
freres `title_en` / `evidence_en` / `remediation_en`. Une regle sans
traduction sort en francais quelle que soit la langue demandee, sans erreur.

La capture assistee est **tronquee par defaut** (128 octets/paquet sous Windows,
96 sous Linux) : suffisant pour l'analyse et leger.

**Ce n'est PAS une garantie d'absence de credential**, contrairement a ce que
ce README affirmait avant le 25/07/2026. La troncature coupe a N octets *depuis
le debut de la trame* — un paquet plus court que N est donc capture EN ENTIER,
payload compris. Mesure :

| Payload | `-s 96` | 128 o |
|---|---|---|
| `PASS hunter2` (POP3/FTP en clair) | **complet** | **complet** |
| `USER admin` + `PASS ...` | **complet** | **complet** |
| `{"token":"eyJhbGciOi..."}` | **complet** | **complet** |
| En-tete `Authorization: Basic ...` (51 o) | 42/51 o | **complet** |

Autrement dit : la troncature elimine les gros transferts, pas les secrets
courts — et les protocoles d'authentification en clair sont precisement courts.
Traiter un bundle comme une donnee sensible : le relire avant de le transmettre,
et preferer `--full-packets` uniquement quand c'est necessaire et assume.

L'option `--explain` n'envoie jamais le pcap : uniquement le rapport JSON
(signaux et verdicts).

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

## Plateformes

| | Analyse (`analyze`) | Capture assistee | Jointure process <-> flux |
|---|---|---|---|
| Linux | oui | `capture.sh` (tcpdump + ss) | `--audit` (auditd) |
| Windows | oui | `capture.ps1` (pktmon, natif) | `--events` : Sysmon EID 3, **ou WFP 5156/5157 sans agent** |
| macOS | oui | non — capturer avec `tcpdump`, puis analyser | non |

`compare` (deux captures, deux points) fonctionne sur les trois.

CI : Linux/Windows/macOS x Python 3.11-3.13, plus un job en fuseau decale,
un avec les extras installes, un sur le paquet construit.

## Statut de validation

- **Valide** : 323 tests automatises, verts sur Linux, Windows et macOS
  (Python 3.11 a 3.13) et sous fuseau decale.
- **Valide au kernel** : 8 scenarios de panne reproduits par un vrai noyau
  Linux (netem, iptables, vraies sockets — `lab/`), plus la jointure auditd
  sur un journal auditd reel. Les pcaps produits servent de fixtures.
- **Valide sur incident reel** : chaine de capture Windows complete (pktmon
  -> analyse) contre un service lent, un port ferme et un port filtre — les
  trois verdicts exacts.
- **Pas encore fait** : incidents de production subis (non provoques). Les
  verdicts sont un point de depart outille, pas un oracle — AMBIGU est un
  verdict assume, et le rapport dit ce qu'il n'a pas su lire.

Ce que ces validations ont coute, et pourquoi elles figurent ici : chacune a
trouve des defauts que les tests sur donnees fabriquees ne voyaient pas —
detection de retransmissions cassee par TSO/GSO, `pktmon` qui annonce un
type de trame et en ecrit un autre, `auditd` dont le format par defaut n'est
pas celui de sa documentation, et des pannes Windows declenchees par des
donnees Linux. Les fixtures ecrites a la main decrivent l'outil qu'on
imagine ; l'execution reelle decrit celui qui existe.

## Limites connues (v1)

- TCP/IPv4-IPv6 uniquement (pas d'UDP/QUIC, pas de reassemblage de fragments).
- RTT p95 pollue par les delayed ACK (~40-200 ms) : min et p50 sont fiables.
  Aucune regle ne rend donc un verdict RESEAU sur le seul p95. En revanche un
  p95 eleve n'est pas ignore : une mediane saine avec une queue significative
  produit un verdict AMBIGU explicite (« pics de latence que la capture ne sait
  pas attribuer »), qui nomme les deux causes possibles — gigue du chemin ou
  delayed ACK — et donne de quoi les separer. Ni faux verdict reseau, ni faux
  « transport sain ».
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
  process<->flux retroactive via Sysmon Event ID 3 — validee depuis sur un
  enregistrement Sysmon reel. Pour activer la source (console admin) :

  ```powershell
  sysmon -i -accepteula <chemin>\netverdict\capture\sysmon-netverdict.xml
  ```

  Cette configuration n'active QUE l'Event ID 3 (NetworkConnect), desactive par
  defaut dans le Sysmon livre avec Windows 11 24H2. Les 21 autres types
  d'evenements y sont en `onmatch="include"` sans aucune regle, ce qui les
  laisse eteints — on n'allume pas un journal complet pour une jointure.
- v2 : capture pilotee des deux cotes (client ET serveur) et comparaison.

## Licence

GPL-2.0
