# Inventaire des chaines visibles par l'utilisateur (avant i18n)

Etabli sur netverdict 0.5.0 (commit de10e60) en executant l'outil sur les pcaps
de `tests/fixtures/` et en relisant chaque module qui ecrit sur stdout/stderr.
Ce fichier est la base de la revue : il dit ce qui a ete traduit, ce qui ne l'a
pas ete, et pourquoi.

## Methode

- `python -m netverdict.cli analyze tests/fixtures/*.pcap` (9 pcaps, tous les
  verdicts sauf `slow-app-likely`, `rtt-degraded`, `latency-tail-unexplained`
  et le fallback AMBIGU, atteints par les tests unitaires).
- `analyze --syslog --audit` pour la section timeline.
- Relecture de `raise ValueError(`, `stats.note =`, `print(`, `con.print(` sur
  tout le paquet.

## 1. Sortie normale (`analyze`)

### 1.1 En-tete et avertissements de mesure — `report.py`

| Emplacement | Chaine |
|---|---|
| `render_console` | `{n} paquets lus — {n} TCP, {n} ICMP, {n} non-IP, {n} illisibles — {n} conversations` |
| id. | `attention : {n}/{n} paquets illisibles, les verdicts peuvent etre incomplets` |
| id. | `attention : linktype partiellement supporte, des trames ont ete ignorees` |
| id. | `ATTENTION : cette capture declare PLUSIEURS interfaces de types differents (fusion type mergecap)...` (5 lignes) |

### 1.2 Corps du panneau de verdict — `report.py`

| Chaine |
|---|
| `etat hote : {resume}` (prefixe du snapshot) |
| `process (journal, retroactif) : {description}` |
| `sens client/serveur estime (pas de SYN dans la capture) : lire les roles avec prudence` |
| `A verifier en premier (suspects, pas une cause etablie) :` |
| `* = type de changement pouvant produire ce verdict` |
| `Piste de correction :` |
| `Signaux secondaires : ` |

### 1.3 Libelles structurants — `report.py`

- `CONF_LABEL` : `confiance haute` / `confiance moyenne` / `confiance basse`.
  **Defaut existant** : `builtin.yaml` utilise aussi `confidence: faible`
  (regle `latency-tail-unexplained`), absent du dictionnaire — la valeur brute
  `faible` s'affiche telle quelle. Corrige au passage.
- Jetons de verdict affiches dans le titre du panneau : `RESEAU`, `APP`, `OS`,
  `HOTE`, `AMBIGU`, `RAS`. **Voir §8 : ce sont aussi des identifiants.**

### 1.4 Pieds de rapport — `report.py`

| Chaine |
|---|
| `... {n} autre(s) conversation(s) avec verdict masquee(s) — utiliser --top pour en voir plus` |
| `[RAS] {n} conversation(s) au transport sain` |
| `{n} conversation(s) anodine(s) (trop peu de trafic pour juger)` |

### 1.5 Section timeline — `report.py:render_timeline`

| Chaine |
|---|
| `Changements dans l'infra (fenetre de la capture) :` |
| `Changements dans l'infra — fenetre NON appliquee (capture sans paquet TCP date) :` |
| `aucun changement detecte dans la fenetre — les sources fournies n'expliquent pas l'incident par un changement recent` |
| `<< precede l'incident de {n}s` |
| `<< precede l'incident d'environ {n} min (heure source approximative)` |
| `... {n} autre(s) changement(s) masque(s) — --top pour en voir plus` |
| `+ {n} erreur(s) hors changement dans la fenetre (--json pour le detail)` |
| `{n}/{n} entrees lues` / `, {n} illisibles` |

### 1.6 Correlation — `correlate.py`

| Methode | Chaine |
|---|---|
| `Suspect.describe` | `{n} s` / `environ {n} min (heure source approximative)` |
| id. | `pendant le flux` / `avant le flux` |
| `ProcessAttribution.describe` | `{process} cote {client\|serveur}` |
| id. | `, utilisateur {user}` |
| id. | `— rapproche par la DESTINATION seule (le journal ne donne pas le port source) : un autre process contactant le meme service au meme moment serait indiscernable` |
| id. | `— {n} connexions correspondaient (port reutilise ?), la plus proche du debut du flux` |

Note : `side` vaut litteralement `"client"` / `"serveur"` et **fuit en JSON**
(`process_attribution.side`). Voir §8.

### 1.7 Snapshot hote — `hostsnap.py:HostContext.summary`

`socket detenue par {p}` · `(pid {n})` · `, cpu process {n}%` · `cpu machine {n}%`
· `disque {n}%` · `ram libre {n} Mo`

## 2. Les 14 regles YAML — `rules/builtin.yaml`

Chaque regle porte 3 blocs traduisibles : `title` (1 ligne), `evidence`
(1-2 gabarits interpoles) et `remediation` (4 a 20 lignes redigees a la main).
C'est le gros du volume : ~200 lignes de francais.

| id | verdict | prio | blocs |
|---|---|---|---|
| `reject-icmp` | RESEAU | 92 | title + 1 evidence + remediation |
| `syn-no-answer-icmp-unreach` | RESEAU | 91 | title + 1 + remediation |
| `syn-no-answer` | RESEAU | 90 | title + 1 + remediation |
| `rst-to-syn` | APP | 88 | title + 1 + remediation |
| `mtu-blackhole` | RESEAU | 86 | title + 1 + remediation |
| `zero-window-server` | HOTE | 85 | title + 1 + remediation |
| `slow-app-proven` | APP | 84 | title + 1 + remediation |
| `zero-window-client` | HOTE | 83 | title + 1 + remediation |
| `retrans-heavy` | RESEAU | 80 | title + **2** + remediation |
| `slow-app-likely` | APP | 78 | title + 1 + remediation |
| `rtt-degraded` | RESEAU | 70 | title + 1 + remediation |
| `rst-midstream` | AMBIGU | 65 | title + 1 + remediation |
| `latency-tail-unexplained` | AMBIGU | 25 | title + 1 + remediation (la plus longue) |
| `clean` | RAS | 10 | title + 1 + remediation |

Plus une 15e regle definie **en Python** : `AMBIGU_FALLBACK` dans
`rules/engine.py` (title + evidence + remediation).

## 3. Sortie `--explain` — `explain.py`

- `SYSTEM` : prompt de 19 lignes, dont **`Redige en francais une synthese
  narrative courte`** — c'est lui qui impose la langue de la sortie LLM.
- Message utilisateur : `Rapport netverdict a expliquer :\n\n`
- 5 messages `ExplainUnavailable` : SDK absent, credentials, API injoignable,
  erreur API, refus du modele.
- `[--explain indisponible] {msg}` (prefixe, dans `cli.py`).

## 4. Messages d'erreur

### 4.1 `cli.py`
`Erreur dans les regles : {e}` · `Fichier introuvable : {path}` ·
`--syslog-tz n'a d'effet qu'avec --syslog (aucun fichier syslog fourni)` ·
`--syslog-tz: {e}` · `--events {p}: {e}` · `--syslog {p}: {e}` ·
`--audit {p}: {e}` · `` `netverdict capture` ne gere que Windows et Linux `` (4 lignes)
· `Script de capture introuvable : {p}` · `Interpreteur introuvable : ...`

### 4.2 `pcap.py`
`Format non reconnu (ni pcap ni pcapng). Si c'est un .etl Windows : ...`

### 4.3 `sources/syslog.py` (`parse_tz`, appele depuis le CLI)
`--syslog-tz vide` · `decalage hors bornes: {s} (attendu entre -23:59 et +23:59)` ·
`fuseau inconnu: {s}. {formes}` · `fuseau {s} introuvable : la base IANA n'est pas
installee...` · `fuseau invalide: {s} ({e})` · le bloc `formes` (3 lignes) ·
`syslog illisible ({p}): {e}`

### 4.4 `sources/evtx.py`
`Export XML tronque ou encodage incoherent` · `XML illisible dans {p}` ·
`Fichier .evtx binaire detecte mais python-evtx n'est pas installe` (6 lignes) ·
`Lecture du .evtx {p} interrompue`

### 4.5 `sources/auditd.py`
`audit.log illisible ({p}) : {e}. Verifier le chemin et les permissions...`

### 4.6 Avertissements `stats.note` (affiches en JAUNE dans le rapport)
- evtx : `aucun evenement lu dans ce fichier...`
- evtx : `events Sysmon lus mais AUCUN NetworkConnect (EID3)...`
- evtx : `events de securite Windows lus mais AUCUN WFP 5156/5157...`
- auditd : `records auditd lus mais aucune connexion reseau (SYSCALL connect() + SOCKADDR)...`

## 5. `compare`

- `compare.py:ComparaisonFlux.verdict()` : 3 phrases de verdict (AMBIGU / RESEAU / RAS).
- `compare.py` : 2 `note` (handshake absent, latence negative).
- `compare.py` : libelles de sens `client->serveur` / `serveur->client`.
- `cli.py:cmd_compare` : `amont : {n} flux   aval : {n} flux   communs : {n}` ·
  le bloc NAT (5 lignes) · `aucun flux commun aux deux captures...` ·
  `{n} emis, {n} retrouves` · `{n} PERDUS` · `latence entre les deux points...` ·
  `decalage d'horloge estime entre les deux machines` · `... {n} autre(s) flux — --top pour en voir plus`
- Cles JSON de `compare --json` : `flux`, `explication`, `offset_horloge_s`,
  `latence_reseau_ms`, `sens`, `emis`, `retrouves`, `perdus`, `taux_perte`,
  `diagnostic`, `flux_a`, `flux_b`, `flux_communs`, `nat_probable`. **Voir §8.**

## 6. `--help` — `cli.py`

Description du programme + `help=` de 4 sous-commandes et de 15 arguments.
Entierement en francais.

## 7. `rules` (sous-commande)

`{priorite}  {verdict}  {id}  {title}` — le `title` vient du YAML (§2).

## 8. Ce qui N'EST PAS traduit, et pourquoi

### 8.1 Jetons de verdict (`RESEAU`, `APP`, `OS`, `HOTE`, `AMBIGU`, `RAS`)
Ce ne sont pas de la prose, ce sont des **identifiants** :
- valeurs du champ `verdict:` dans le YAML, y compris dans les fichiers
  `--rules` ecrits par les utilisateurs ;
- valeurs du champ `"verdict"` du JSON, sur lequel des scripts appelants
  filtrent ;
- constantes du moteur (`VERDICTS`), du code de retour
  (`fv.verdict != "RAS"`) et de la table d'affinite de `correlate.py`.

Les traduire rendrait le JSON **dependant de la langue** : un script qui teste
`verdict == "RESEAU"` casserait en silence le jour ou quelqu'un exporte
`NETVERDICT_LANG=en`. C'est exactement la panne muette que cet outil existe
pour debusquer.

**Choix retenu** : le jeton reste `RESEAU` partout dans la donnee (YAML, JSON),
et seul le **libelle d'affichage** de la console est traduit (`NETWORK`, `HOST`,
`CLEAN`...). La console est la vue humaine, le JSON est le contrat machine.

### 8.2 `confidence` (`haute`/`moyenne`/`basse`/`faible`)
Meme raisonnement : valeur YAML et valeur JSON, donc identifiant. Seul le
libelle console est traduit (`high confidence`...).

### 8.3 `process_attribution.side` (`client` / `serveur`) en JSON
Meme raisonnement : champ machine. `serveur` reste `serveur` en JSON, la
console affiche `server side`. **Limite connue** : `serveur` est un mot
francais dans un JSON par ailleurs anglais — le corriger demanderait de casser
le format de sortie, hors perimetre.

### 8.4 Cles JSON francaises de `compare --json`
`flux`, `explication`, `sens`, `emis`, `retrouves`, `perdus`, `taux_perte`,
`offset_horloge_s`, `latence_reseau_ms`, `flux_a`, `flux_b`, `flux_communs`,
`nat_probable`. Les **valeurs** (phrases de verdict, notes) sont traduites ;
les **cles** ne le sont pas — ce sont des noms de champs d'un contrat publie
en 0.5.0, les renommer casserait tout consommateur existant.

### 8.5 Commentaires, docstrings, noms de variables
Le code est ecrit en francais (`comparer`, `resultats`, `suspects_par_flux`,
`_est_proprietaire_reel`). Hors perimetre : invisible pour l'utilisateur, et
le traduire ferait un diff illisible qui noierait le travail reel.

### 8.6 Erreurs internes jamais remontees
`saddr trop court...`, `famille sockaddr {n} non IP`, `categorie inconnue: {c}`
(timeline.py). Les deux premieres sont rattrapees dans la boucle de parsing
d'auditd et comptees en `unparsed` ; la troisieme est une violation de contrat
entre parseurs, c'est-a-dire un bug de developpeur, pas un message d'admin.

### 8.7 README
Le README reste en francais ; seule la section usage mentionne `--lang`.
La traduction complete du README est hors perimetre.

## 9. Points de vigilance releves pendant l'inventaire

1. `render_timeline` est appele **positionnellement** par
   `tests/test_review_fixes.py` — tout nouveau parametre doit aller en fin de
   signature avec un defaut.
2. Un seul test assere du texte francais :
   `test_review_fixes.py:45 assert "aucun changement" in out`. Le defaut `fr`
   doit donc rester au mot pres.
3. `confidence: faible` n'a jamais eu de libelle (bug preexistant, §1.3).
4. Les gabarits `evidence` sont interpoles par `_EvidenceFormatter` : toute
   traduction doit conserver **exactement** les memes noms de champs entre
   accolades, sinon `load_rules` leve au chargement (ce qui est le
   comportement voulu, mais il faut le savoir).

## 10. Etat apres implementation

Tout ce qui est liste en §1 a §7 est traduit, a l'exception documentee en §8.

**Verification du « francais inchange au mot pres »** : la sortie console ET
le JSON des 9 pcaps de `tests/fixtures/`, plus un cas avec timeline
(syslog + auditd), ont ete captures AVANT modification puis rejoues APRES.
Diff : **aucune ligne differente** (961 lignes comparees).

**Verification du « anglais sans residu »** : `tests/test_i18n.py` cherche
37 mots francais sans ambiguite et toute lettre latine accentuee dans la
sortie EN de 9 pcaps, de la timeline (pleine et vide), de l'attribution de
process et du snapshot d'hote. Le detecteur a ete falsifie a l'envers — il
releve 3 a 14 mots sur chaque sortie FR, et 0 sur chaque sortie EN.

Deux ecarts a signaler au relecteur :

1. `confidence: faible` reste **non traduit en francais** (« faible » brut),
   parce que lui donner un libelle changerait la sortie FR existante. En
   anglais il vaut `low confidence`. Le corriger cote FR est une decision de
   mainteneur, pas un effet de bord d'i18n — un commit d'une ligne.
2. `tests/test_paquet.py` a du gagner `lang = None` dans son faux
   `argparse.Namespace` : la signature de `cmd_capture` lit desormais
   `args.lang`. Aucune autre modification de test existant.
