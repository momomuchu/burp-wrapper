# ADR-0007 — Périmètre produit : fonctionnalités complètes, sécurité configurable

**Statut :** accepted · 2026-06-16
**Criticité :** `[CRITICAL]` (définit le périmètre de toute la spec)

## Décision

`bp` vise la **surface fonctionnelle complète d'un outil de bug bounty** — tous les concepts
métier identifiés dans `RESEARCH-concepts.md` (35 gaps) deviennent des **fonctionnalités**, pas
des « hors-scope par design ».

La **sécurité et le scope sont CONFIGURABLES**, jamais des **gardes obligatoires bloquantes** :
- La vérification de scope (anti-OOS pré-tir), l'enveloppe anti-injection (I6), la redaction des
  secrets (I7) sont des **options de configuration** (activables/désactivables), pas des
  préconditions imposées.
- Défaut raisonnable possible (ex. scope-check = `warn`), mais l'utilisateur configure ;
  `bp` n'**impose** rien.

## Rationale

Founder, 2026-06-16 (verbatim) : « vérifier le scope, c'est important, mais c'est pas
nécessairement obligatoire… c'est parmi les configurations… il faut juste toutes les
fonctionnalités du bot, les bug bounties, tout simplement. »

## Alternatives rejetées

- **T1 — Driver pur** : rejeté — `bp` seul ne couvrirait pas le métier ; les 35 gaps resteraient.
- **T2 — Floor sécurité obligatoire** : rejeté — le founder ne veut PAS de garde imposée ; la
  sécurité doit être configurable, pas bloquante.

## Implications (spec, pas exécution)

1. Le **command map `CLI.md` s'étend** : nouveaux namespaces — `bp program`, `bp asset`,
   `bp endpoint`, `bp finding`, `bp report`, multi-session (`bp session --as <ctx>`),
   classification, en plus du driver actuel.
2. Les features **safety** deviennent des **flags/config** : `--enforce-scope warn|block|off`,
   `--envelope on|off`, `--redact on|off` (+ équivalents en fichier de config).
3. `RESEARCH-concepts.md` = la **feuille de route des features** (les 35 gaps priorisés).
4. Phase suivante de spec : mapper chaque gap → commande/config concrète et étendre
   `SPEC.md` + `CLI.md`. **Toujours zéro exécution avant ton GO.**

## Lié

- `docs/RESEARCH-concepts.md` (les 35 gaps) · `ADR-0005` (Run Ledger) · `ADR-0004` (fuzz --async)
- C3 bug-bounty-mini (I6/I7/sole-egress) reste un **adapter optionnel** ; ici on en adopte les
  concepts en **configs natives** de `bp`.
