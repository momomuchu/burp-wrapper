# `bp` — Persistance (Run Ledger) & Configuration (spec)

> **DRAFT — spec, pas code.** Réf : `ADR-0005` (Ledger ON par défaut, SQLite `~/.bp/`),
> `ADR-0007` (sécurité configurable, non bloquante), `OUTPUT.md` (`bp log`), gaps research
> (resp_sha256 / jamais de body brut, redaction I7).

## 1 · Run Ledger — schéma SQLite (`~/.bp/ledger.db`)

ON par défaut (`--no-ledger` pour opt-out par op). **On stocke des empreintes + refs, PAS les
bodies bruts** par défaut (concept bb-mini : pas de fuite, ledger léger).

```sql
CREATE TABLE ops (
  id          TEXT PRIMARY KEY,   -- court trié temporellement (ex. ULID)
  ts          TEXT NOT NULL,      -- ISO-8601 UTC
  command     TEXT,               -- ligne bp (redactée si redact=on)
  burp_op     TEXT,               -- ex. "POST /intruder/attack/create"
  target      TEXT,               -- host/url visé
  program     TEXT,               -- nullable (workspace futur, ADR-0007)
  tag         TEXT,               -- nullable (--tag)
  status      TEXT NOT NULL,      -- ok | error | refused
  exit_code   INTEGER,
  req_sha256  TEXT,               -- empreinte requête envoyée
  resp_sha256 TEXT,               -- empreinte réponse
  resp_status INTEGER,
  resp_len    INTEGER,
  duration_ms INTEGER,
  error_code  TEXT,               -- nullable (CONNECTION_REFUSED, PRO_REQUIRED, …)
  req_ref     TEXT,               -- nullable: id history Burp ou chemin blob si bodies stockés
  resp_ref    TEXT
);
CREATE INDEX idx_ops_ts     ON ops(ts);
CREATE INDEX idx_ops_target ON ops(target);
CREATE INDEX idx_ops_tag    ON ops(tag);
```

- **Bodies** : non stockés par défaut. `--ledger-bodies` (opt-in) → écrit dans `~/.bp/blobs/<sha256>`, **après redaction** si `redact=on`.
- `bp log [--since T --until T --target H --tag X --status S --limit N]` → SELECT sur `ops`.
- `bp tag <opId> <name>` → UPDATE tag. (Surface query = `OUTPUT.md`.)
- **Intégrité** (concept bb-certify, futur) : `bp certify` pourrait produire un manifeste SHA-256 — hors driver, noté roadmap.

## 2 · Configuration — fichier + env + flags

**Précédence (le plus fort gagne) :** flag CLI > variable d'env > `~/.bp/config` > défaut intégré.

**`~/.bp/config`** — format `KEY=value` (sourceable en sh, simple) :
```
burp_rest_url   = http://127.0.0.1:8089
enforce_scope   = warn        # warn | block | off   (défaut warn — JAMAIS imposé, ADR-0007)
envelope        = off         # on | off  (enveloppe anti-injection des réponses surfacées, I6)
redact          = on          # on | off  (masque JWT/cookies/Authorization/clés dans log+sortie, I7)
ledger          = on          # on | off
throttle_ms     = 0
anomaly_pct     = 5           # seuil anomalie longueur (cf. ALGORITHMS A2)
agent_mode      = auto        # auto | on | off (NDJSON pour agent IA, cf. OUTPUT.md)
```

**Variables d'env** (préfixe `BP_`, + `BURP_REST_URL` historique) :
`BURP_REST_URL`, `BP_ENFORCE_SCOPE`, `BP_ENVELOPE`, `BP_REDACT`, `BP_NO_LEDGER`, `BP_THROTTLE_MS`, `BP_AGENT` (cf. OUTPUT.md).

**Flags équivalents** (par commande) : `--url`, `--enforce-scope`, `--envelope`, `--redact`, `--no-ledger`, `--throttle-ms`. Chaque flag override env+config pour cette invocation.

**Sémantique des gardes (non bloquantes par défaut — ADR-0007) :**
- `enforce_scope=warn` (défaut) : tire quand même, **avertit** si le target est hors-scope.
- `enforce_scope=block` : refuse (exit 4) si hors-scope. **Opt-in**, jamais imposé.
- `enforce_scope=off` : aucune vérif.
- `envelope=on` : enveloppe `<BP_TARGET_DATA>…</BP_TARGET_DATA>` autour des bodies cible surfacés (anti-injection de l'agent). Défaut off (configurable).
- `redact=on` (défaut) : masque les secrets connus avant log/affichage — protège **tes propres** secrets, downside faible.

## 3 · Cas de test RED (TDD)

- Précédence : flag > env > config > défaut (4 niveaux, un test chacun).
- `enforce_scope=warn` + target hors-scope → tire **et** émet le warning (n'échoue pas).
- `enforce_scope=block` + hors-scope → exit 4, ne tire pas.
- `redact=on` → un `Authorization: Bearer X` n'apparaît ni dans `ops.command` ni dans la sortie.
- Ledger : une op `ok` insère 1 ligne avec `resp_sha256` non nul et **aucun body brut** stocké (sans `--ledger-bodies`).
- `--no-ledger` → 0 ligne insérée.

## Statut

`[HIGH][BLOCKS:high]` — complète la surface *driver* (persistance + config). Avec
`A1/A2` (ALGORITHMS) + ce doc, le **driver est spec-complet**. Restent 2 décisions **toi** :
langage d'implémentation + validation `SPEC §14`. **Zéro code avant GO.**
