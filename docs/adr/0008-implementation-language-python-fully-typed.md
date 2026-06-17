# ADR-0008 — Langage d'implémentation : Python, intégralement typé

**Statut :** accepted · 2026-06-16
**Criticité :** `[CRITICAL]` (fondation de toute l'implémentation)

## Décision

`bp` est implémenté en **Python 3.11+**, avec **typage complet et strict** : annotations de
type sur **tout** (signatures, modèles, retours) + vérification statique stricte en CI
(`mypy --strict` ou `pyright` strict). Le typage n'est pas optionnel — c'est une **discipline
imposée** (le gain de sécurité-types qui rendait Go attractif, obtenu en Python).

**Stack :**
- **Python 3.11+**
- **httpx** — client REST `:8089`, **mode async** pour la concurrence du fuzz matriciel (A2)
- **typer** — CLI (nativement piloté par les annotations de type → « tout typé » idiomatique)
- **pydantic** — modèles d'API **typés + validés** miroir des DTO Kotlin (`ApiResponse<T>`,
  `CreateAttackRequest`, …) → applique le contrat de sérialisation (`SPEC §8`, spec-as-contract)
- **sqlite3** (stdlib) — Run Ledger / workspace (`STATE-AND-CONFIG.md`)
- **pytest** — TDD (RED-tests A1/A2 déjà spec'd)
- **mypy --strict** (ou pyright) + **ruff** — typage strict + lint/format en gate

## Rationale

Founder, 2026-06-16 (verbatim) : « je trouve Python 100 fois plus simple… je ne vais pas me
casser la tête… tant que c'est typage complet, c'est tout le temps typé… autant faire du Python,
pas du Go. » + facteur décisif d'ADR-0007 : **le founder possède la validation et maîtrise
Python** → un outil qu'il lit/valide/étend lui-même prime sur l'élégance du binaire unique.

## Alternatives rejetées

- **Go** : rejeté — founder non familier (« ressemble à du C »), courbe d'apprentissage sur
  l'outil-clé pendant qu'il doit le valider ; le seul avantage net (binaire unique) est
  contournable côté Python.
- **POSIX sh** (mirror bb-fetch) : rejeté — souffre sur A2 (expansion/concurrence) et le
  workspace (DB) ; distribution exige `curl`/`jq`/`sqlite3` présents.

## Implications

1. **Distribution** : `uv tool install bp` / `pipx install bp` (1 commande) ; binaire
   zéro-dépendance possible plus tard via **PyInstaller** → objectif « standalone distribuable » tenu.
2. **Modèles pydantic = contrat** : un mismatch avec le contrat Kotlin échoue à la validation
   → renforce `SPEC §14 #7` (sérialisation) et les contract-tests (`§14 #9`).
3. **Typage strict en gate** : ajout aux disciplines (`.claude/rules/disciplines.md`) — typing:strict.
4. `[BLOCKS:critical]` — débloque le TDD. Reste avant code : check live Intruder Community
   (`SPEC §14 #8`) + GO founder. **Zéro code avant GO.**
