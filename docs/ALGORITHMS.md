# `bp` — Algorithmes load-bearing (spec, pas code)

> **DRAFT — spec d'implémentation, language-neutral (pseudocode).** Les 2 algos que le TDD
> implémentera. Référence : `CLI.md` (grammaire `--pos`), `SPEC.md §6.4` (modèles Intruder).
> Modèle REST réel : `PayloadPosition{start:Int, end:Int, name:String}` (tous requis),
> `CreateAttackRequest{positions:[…], payloads:Map<name,[String]>, attackType:String}`.

---

## A1 · Résolveur `--pos` : sélecteur sémantique → byte-offset

**Contrat :** `resolvePos(rawRequest: bytes, selector: string) -> PayloadPosition{start,end,name}`
où `start`/`end` sont des **offsets octets** dans `rawRequest` (`end` exclusif), et la tranche
`rawRequest[start:end]` = **la valeur** à fuzzer. Plusieurs `--pos` → liste triée par `start`.

**Pré-parse** (une fois par requête) — découpe HTTP/1.1 :
```
request-line = METHOD SP request-target SP HTTP-version CRLF
headers      = ( field-name ":" OWS field-value OWS CRLF )*
CRLF                       # ligne vide
body         = octets restants
```
Mémoriser les offsets de : request-target, chaque header (nom+valeur), début du body.
Hypothèse CRLF ; si LF-only détecté, ajuster la longueur de fin de ligne (1 vs 2).

**Par type de sélecteur :**

| Sélecteur | Résolution | `name` |
|---|---|---|
| `offset:A-B` | `{A, B}` tel quel. Valider `0 ≤ A < B ≤ len`. | `offset:A-B` |
| `header:NAME` | header dont `field-name` == NAME (**case-insensitive**). Span = `field-value` après OWS, jusqu'à fin de valeur (avant CRLF). **1ʳᵉ occurrence** (voir règle ci-dessous). | `header:NAME` |
| `cookie:NAME` | dans la valeur du header `Cookie:`, trouver le token `NAME=`, span = après `=` jusqu'au prochain `;` ou fin de valeur. | `cookie:NAME` |
| `query:NAME` | dans `request-target` après `?`, trouver `NAME=`, span = jusqu'au prochain `&` ou fin. Span = **valeur encodée brute**. | `query:NAME` |
| `path:INDEX` | path = `request-target` avant `?`, segments séparés par `/`. **1-based** (`path:1` = 1ᵉʳ segment après le `/` initial). Span = octets du segment. | `path:INDEX` |
| `body:FIELD` | dispatch sur `Content-Type` (voir ci-dessous). | `body:FIELD` |

**`body:FIELD` par content-type :**
- `application/x-www-form-urlencoded` → `FIELD=value` dans le body, span = valeur jusqu'au `&`/fin.
- `application/json` → valeur de la clé `FIELD` (top-level ; **extension** : chemin pointé `body:a.b`). String → span = **intérieur des guillemets** ; nombre/bool/null → le littéral.
- `multipart/form-data` → part `name="FIELD"`, span = corps de la part. *(supporté v2)*
- autre → erreur `UNSUPPORTED_BODY`.

**Règles & erreurs :**
- Sélecteur introuvable → `POS_NOT_FOUND` (exit 2).
- Headers/params répétés → **1ʳᵉ occurrence par défaut** ; `header:NAME[k]` (index) en extension.
- 2 positions qui se **chevauchent** → `POS_OVERLAP` (exit 2) (sinon l'expansion A2 casse).
- Les offsets sont **octets** (pas caractères) — attention UTF-8 multi-octets.

**Cas de test RED (TDD) — requête fixture :**
```
POST /api/v2/users/42?redirect=/home HTTP/1.1\r\n
Host: t.example.com\r\n
Authorization: Bearer abc123\r\n
Cookie: sid=XYZ; role=user\r\n
Content-Type: application/json\r\n
\r\n
{"id":42,"name":"bob"}
```
| Sélecteur | Attendu (`rawRequest[start:end]`) |
|---|---|
| `header:Authorization` | `Bearer abc123` |
| `cookie:role` | `user` |
| `query:redirect` | `/home` |
| `path:3` | `42` (segments: api/v2/users/42 → 1=api,2=v2,3=users… **vérifier convention**) |
| `body:id` | `42` (littéral JSON) |
| `body:name` | `bob` (intérieur guillemets) |
| `offset:0-4` | `POST` |
| `header:Nope` | erreur `POS_NOT_FOUND` |

> ⚠️ La convention `path:INDEX` (inclut-on le 1ᵉʳ segment vide avant `/api` ?) est à **figer**
> par un test : reco `path:1`=`api` (segments non-vides). À valider.

---

## A2 · Expansion d'attaque (matricielle, client-side)

**Verdict source (`IntruderService.kt`, vérifié 2026-06-16) :** l'intruder de l'extension est
**inutilisable pour le fuzzing réel** — `executeAttack()` **ignore `attackType`**, n'utilise que
**la 1ʳᵉ position** (`positions.firstOrNull()`), substitue **par NOM** (regex template/query/body/
header, pas par byte-offset), et aplatit tous les payloads en sniper. Pas de battering-ram, pas de
pitchfork, pas de cluster-bomb, pas de multi-position. → **`bp` fait TOUTE l'attaque côté client**,
pour **les 4 types y compris sniper** : A1 résout les offsets, A2 expanse + substitue (byte-offset
précis) + tire chaque requête via `POST /repeater/send`. L'`/intruder/attack/create` natif n'est
**pas** utilisé pour le fuzz (au mieux exposé en passthrough). Le seul chemin natif « ok » est
`/intruder/quick-fuzz` (sniper 1-param, par nom, avec baseline) — `bp` peut le wrapper pour le
raccourci, mais le vrai moteur = A1+A2 client-side.

**Contrat :** `expand(base: bytes, positions: [Pos], payloads: Map<name,[String]>, type) -> [ConcreteRequest]`

**Primitive de substitution (le point de correction critique) :**
```
applySubs(base, subs: [{start, end, payload}]) -> bytes:
    # subs ne se chevauchent pas (garanti par A1 POS_OVERLAP)
    trier subs par start DESCENDANT          # ← droite→gauche, sinon les offsets glissent
    out = base
    pour sub dans subs:
        out = out[0:sub.start] + sub.payload + out[sub.end:]
    si une substitution touche le body:
        recalculer Content-Length = byteLength(body après la ligne vide)  # sur out
    retourner out
```
> **Pourquoi droite→gauche :** substituer une valeur de longueur différente décale tous les
> offsets situés *après*. En appliquant du plus grand `start` au plus petit, les offsets non
> encore traités restent valides. C'est LE bug classique à ne pas faire.

**Générateurs de combinaisons** (positions `p_1..p_n`, sets `s_1..s_n`) :

| `type` | Sets | Génération | Nb requêtes |
|---|---|---|---|
| `sniper` | 1 set `S` | pour chaque position `p_k`, pour chaque `v∈S` : subs=`[{p_k,v}]` (les autres restent l'original) | `n × |S|` |
| `battering-ram` | 1 set `S` | pour chaque `v∈S` : subs=`[{p_k,v} ∀k]` (même payload partout) | `|S|` |
| `pitchfork` | `s_k`/position | `m=min(|s_k|)` ; pour `i∈0..m-1` : subs=`[{p_k, s_k[i]} ∀k]` | `m` |
| `cluster-bomb` | `s_k`/position | pour chaque tuple ∈ `produit(s_1,…,s_n)` : subs=`[{p_k, tuple[k]} ∀k]` | `∏|s_k|` |

**Tir + baseline + anomalie :**
1. Tirer `base` non modifiée 1× → **baseline** `{status0, len0}`.
2. Pour chaque `ConcreteRequest` : `POST /repeater/send` → `{index, payload(s), statusCode, length, durationMs}` → `AttackResultEntry`.
3. **anomalous = true** si `statusCode ≠ status0` **ou** `|length − len0|` dépasse le seuil
   (reco : `> max(0.05·len0, k·σ)` ; seuil à figer par test).
4. `--throttle-ms N` entre tirs ; `--anomalous-only` filtre à la sortie ; `--no-ledger` respecté.

**Gardes (config, non bloquantes par défaut — ADR-0007) :**
- Compte total `> seuil` (reco 10000) → **warn** (ou confirm si `--confirm`), pas un blocage imposé.
- `--enforce-scope warn|block|off` : si activé, vérifier le host de `base` avant de tirer.

**Worked example — ton « 2 headers + 1 cookie » :**
```
bp fuzz 42 --pos 'header:X-Forwarded-For' --payloads X-Forwarded-For=a.txt(2) \
           --pos 'header:X-Real-IP'       --payloads X-Real-IP=a.txt(2) \
           --pos 'cookie:role'            --payloads role=b.txt(3) \
           --type cluster-bomb
→ resolvePos × 3 → 3 Pos (offsets triés, non chevauchants)
→ produit 2×2×3 = 12 ConcreteRequest, chacun applySubs(droite→gauche) + Content-Length si body
→ 12 tirs /repeater/send + 1 baseline → 12 AttackResultEntry, anomalies flaggées
```

**Cas de test RED (TDD) :**
- `applySubs` : 2 subs de longueurs ≠ → vérifier que l'offset bas reste correct après le splice du haut (anti-régression droite→gauche).
- `applySubs` body → `Content-Length` recalculé == nouvelle longueur de body.
- `cluster-bomb` [a,b]×[1,2] → 4 requêtes, combinaisons exactes `{a,1},{a,2},{b,1},{b,2}`.
- `pitchfork` sets de tailles 3 et 2 → 2 requêtes (min), appariées par index.
- `sniper` 2 positions, set de 3 → 6 requêtes, une seule position modifiée à la fois.
- `battering-ram` set de 3, 2 positions → 3 requêtes, même payload aux 2 positions.

---

## Statut

`[CRITICAL][BLOCKS:critical]` A1 + A2 sont le **cœur du driver** — sans eux, pas de fuzz.
Une fois ces 2 algos + cas de test validés → le driver est **implémentable en TDD**.
Conventions à figer par toi/test : `path:INDEX` (base), seuil d'anomalie, occurrence des
headers répétés. **Spec — zéro code tant que pas de GO.**
