# Verdict deterministe, LLM en couche narrative optionnelle

Date : 2026-07-24
Statut : accepte

## Contexte

Les outils "IA + pcap" existants (ChatTCP, AI Packet Analyzer, Wireshark MCP,
PacketSafari) envoient les donnees de capture a un LLM qui produit l'analyse.
Trois problemes : cout par analyse, confidentialite (un pcap contient des IPs
internes, des hostnames, parfois des credentials), et confiance (une
hallucination sur un diagnostic reseau se paie en heures d'investigation dans
la mauvaise direction).

## Decision

1. Le verdict est rendu par un moteur de regles DETERMINISTE (YAML, seuils
   justifies, remediation redigee a la main). Aucun LLM dans la boucle de
   decision.
2. La couche LLM (`--explain`) est optionnelle, en aval, et ne recoit QUE le
   rapport JSON (signaux extraits + verdicts) — jamais le pcap.

## Justification

- La confiance est le produit : un verdict doit etre reproductible, citable
  (preuves paquet), et auditable (la regle et son seuil sont lisibles).
- Le differenciateur face aux wrappers LLM est precisement la : eux ont le
  narratif sans le determinisme ; nous avons les deux, dans le bon ordre.
- Local-first est un argument fort aupres des admins securite.

## Consequences

- Les regles doivent etre maintenues a la main — c'est un atout (elles sont
  la connaissance metier encodee) mais ca borne la couverture aux cas connus.
  Le fallback AMBIGU + "quoi capturer ensuite" assume les trous.
- `--explain` suit les recommandations Claude API : claude-opus-5, fallback
  serveur actif (les rapports d'analyse reseau peuvent declencher de faux
  positifs des classificateurs cyber), SDK optionnel via l'extra [explain].
