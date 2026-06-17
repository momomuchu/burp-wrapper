# `bp` — Spec Phase 0 (SDD)

> **DRAFT — proposed, awaiting founder validation.**
> **No implementation until GO.**

Spec canonique reconstruite depuis la source
(`RestServer.kt` + `routes/*.kt`).
Énumération : **13 groupes · 69 endpoints ·
verdict COMPLETE**.
Généré 2026-06-16.

---

## Sommaire

1. Mission
2. Source-of-truth
3. Nom
4. Composants
5. Grammaire `--pos`
6. API — 13 groupes / 69 endpoints
7. Community vs Pro
8. Contrat Kotlin (sérialisation)
9. C4 Run Ledger
10. Architecture de test (TDD)
11. DDD
12. Roadmap couverture
13. Décisions ouvertes
14. Critères d'acceptation

---

## 1 · Mission

`bp` (alias `burpctl`) est une **CLI POSIX
autonome** qui pilote Burp Suite via son API
REST locale `:8089`. Elle offre un **fuzzing
flexible** (grammaire `--pos` multi-position +
4 attack-types) et une **observabilité** de
chaque opération. Cible : un produit
user-facing distribuable, pas un outil interne.
Config par défaut : `BURP_REST_URL =
http://127.0.0.1:8089`.

---

## 2 · Source-of-truth

Les 3 docs du repo se contredisent. **Un seul
dit la vérité.**

| Doc | Verdict |
|---|---|
| `spec.md` | **PÉRIMÉ** — port 9876, Python, wrapper MCP. Décrit l'archi pré-rewrite. |
| `README.md` | **PARTIEL** — ignore session/scan/utils/history ; mentionne des routes fantômes. |
| `RestServer.kt` | **VÉRITÉ** — le câblage réel `configureRouting()`. |

**Conséquence :** la spec est reconstruite depuis
la source, jamais depuis un doc. `spec.md` sera
marqué déprécié (archivé, pas supprimé).

### docMismatches critiques

- **CRITICAL** — `spec.md` dit port **9876** ;
  la réalité est **8089**. Tout client bâti
  sur `spec.md` tape le mauvais port et échoue.
- **HIGH** — `spec.md` décrit un wrapper
  Python/SSE/**MCP PortSwigger** ; la réalité
  est une extension **Kotlin/Ktor REST plate**
  (ni SSE, ni MCP).
- **HIGH** — `README` liste `/sequencer/*`,
  `/comparer/*`, `/logger/*`, `/search` comme
  actifs : **aucun n'est câblé** (endpoints
  fantômes).
- **MEDIUM** — `README` omet entièrement
  `/session/*`, `/scan/*`, `/utils/*` (3
  groupes pourtant fonctionnels).
- **LOW** — la spec OpenAPI embarquée à
  `/docs` déclare **0.2.0** alors que
  `/health` et `/version` renvoient **0.1.0** ;
  elle omet plusieurs endpoints réels.

---

## 3 · Nom

**`bp`** — 2 lettres, libre, mémorable.
**Alias : `burpctl`** (convention `*ctl` :
kubectl / systemctl).

| Écarté | Raison |
|---|---|
| `burp` | collision avec un backup tool existant. |
| `bx` | déjà pris (Ruby / bundler context). |

`bp` reste **à confirmer** (D-Nom, §13).

---

## 4 · Composants

| # | Composant | État |
|---|---|---|
| **C1** | Spec API (cette énumération source-grounded). | priorité |
| **C2** | CLI `bp` standalone — DX + AX, cœur = grammaire `--pos`. | priorité |
| **C3** | Adapter bug-bounty-mini (scope-check / wrap anti-injection). | **différé · optionnel** |
| **C4** | **Run Ledger** — chaque opération en DB locale, nommée, taguable, vérifiable (§9). | **NOUVEAU · à valider** |
| **W** | Méthodo SDD / TDD / DDD / spec-as-contract. | transverse |

> **C4 = la valeur ajoutée vs `curl`.** Sans
> ledger, `bp` est un wrapper HTTP de plus.
> Avec, c'est un outil **traçable / ISO**.

---

## 5 · Grammaire `--pos`

Cœur load-bearing du CLI. Marquer n'importe
quelle byte-range : header / cookie / body /
query / path, multi-position, 4 attack-types.

### Sélecteurs (cible)

| Sélecteur | Cible |
|---|---|
| `header:NAME` | valeur d'un header |
| `cookie:NAME` | valeur d'un cookie |
| `body:FIELD` | champ form / JSON |
| `query:NAME` | param d'URL |
| `path:INDEX` | segment de path |
| `offset:START-END` | byte-range brut |

### Attack-types (Intruder)

| Type | Combinaison |
|---|---|
| `sniper` | 1 payload set ; chaque position **tour à tour** (1 seule active à la fois). |
| `battering-ram` | **même** payload injecté dans **toutes** les positions simultanément. |
| `pitchfork` | N sets **parallèles** : set[i] ↔ position[i], itérés en lock-step (min des longueurs). |
| `cluster-bomb` | **produit cartésien** N-dimensionnel : toutes les combinaisons de tous les sets. |

### Fuzz matriciel (cluster-bomb)

`cluster-bomb` = **produit cartésien**. Avec
2 headers + 1 cookie, on a une **matrice 3D** :
`a × b × c` requêtes.

```
bp fuzz --id 42 \
  --pos 'header:X-Forwarded-For' \
  --pos 'header:X-Real-IP' \
  --pos 'cookie:role' \
  --type cluster-bomb \
  --payloads X-Forwarded-For=ips.txt \
  --payloads X-Real-IP=ips.txt \
  --payloads role=roles.txt \
  --throttle-ms 500 --anomalous-only
```

Si `ips.txt`=a lignes, `ips.txt`=b, `roles.txt`=c
→ **a × b × c** requêtes envoyées.

### Note clé — résolution d'offsets

> Les positions REST sont des **byte-offsets** :
> `PayloadPosition { start:Int, end:Int,
> name:String }` (les 3 requis, sans défaut).
> L'API n'accepte **que** des offsets bruts,
> pas des noms de paramètres.
>
> **Donc `bp` doit RÉSOUDRE** les sélecteurs
> sémantiques (`header:X`, `body:f`…) **en
> byte-ranges** en parsant la requête de base
> capturée. C'est le travail central du CLI.

**Caveats d'implémentation actuels de l'API
Intruder** (à exposer au user) :

- Seul `positions[0].name` est consommé en
  sniper.
- Toutes les valeurs de `payloads`
  (`Map<String,List<String>>`) sont **aplaties**
  (`values.flatten()`) en une liste — les clés
  map n'ont aucun rôle fonctionnel.
- Seul `sniper` est implémenté côté extension ;
  les 3 autres types sont **acceptés mais
  exécutent sniper**. `battering-ram` /
  `pitchfork` / `cluster-bomb` devront être
  réalisés **client-side par `bp`** (expansion
  de la matrice + envois multiples) ou par une
  extension Kotlin ultérieure.
- `options.throttleMs` actif ;
  `followRedirects` / `maxRetries` acceptés mais
  **non câblés**.

---

## 6 · API — 13 groupes / 69 endpoints

Verdict critique adverse : **COMPLETE** (69
handlers source = 69 énumérés, 0 manqué).
La source `routes/*.kt` est l'autorité unique —
aucun endpoint inventé.

Légende : **P** = Pro requis · **C** = Community
OK · **stub** = handler factice.

---

### 6.1 · health `/` — 3 endpoints · C

Introspection serveur pur. Aucun Montoya, aucune
Pro, aucune DB. Paths sans préfixe.

| Méthode | Path | Pro | Modèle requête | Usage hunter |
|---|---|---|---|---|
| GET | `/health` | C | — | poll au début de session : confirme l'extension up + uptime. |
| GET | `/version` | C | — | confirme la version déployée. |
| GET | `/docs` | C | — | récupère l'OpenAPI embarqué (⚠ incomplet, déclare 0.2.0). |

- **pré/post/err** : serveur Ktor en écoute ;
  HTTP 200 inconditionnel ; `INTERNAL_ERROR`
  500 seulement si Throwable inattendu.
- Réponses : `ApiResponse<HealthResponse>`
  {status:'ok', version:'0.1.0', uptime:Long,
  burpVersion:null}. `/docs` = JSON brut (**pas**
  enveloppé, `respondText()`).
- **Flag** : `burpVersion` jamais peuplé.

---

### 6.2 · proxy `/proxy` — 8 endpoints · C

⚠ **4 des 8 sont des stubs / hardcodés.**

| Méthode | Path | Pro | Modèle requête (champs · types Kotlin) | Usage hunter |
|---|---|---|---|---|
| GET | `/proxy/history` | C | query : `limit:Int?`, `offset:Int?=0`, `host:String?` | dump l'historique filtré par host + paginé. |
| GET | `/proxy/history/{id}` | C | path : `id:Int` (toIntOrNull) | une entrée par index absolu. |
| GET | `/proxy/websocket/history` | C | — | inspecte les messages WS (direction + payload). |
| GET | `/proxy/intercept` | C | — **stub** | toujours `{enabled:false}` — non fiable. |
| POST | `/proxy/intercept/enable` | C | — | active l'intercept avant nav manuelle. |
| POST | `/proxy/intercept/disable` | C | — | désactive après inspection. |
| POST | `/proxy/intercept/forward` | C | — **stub** | `{forwarded:true}` no-op. |
| POST | `/proxy/intercept/drop` | C | — **stub** | `{dropped:true}` no-op. |

- **Contrat clé** : `ProxyHistoryResponse.total`
  = taille filtrée avant pagination ; `id` =
  `start+idx` (offset-relatif → **instable**
  entre offsets). Utiliser `/{id}` (index
  absolu) pour la stabilité.
- **err** : `/{id}` non-entier → `INVALID_PARAM` ;
  hors bornes → 500 Ktor (non mappé).
- **Flags** : `listenerInterface`, `clientIp`,
  `timestamp` (HTTP) toujours null. WS
  `timestamp` = `Instant.now()` à l'appel (pas
  capture). `forward`/`drop` **absents de
  `/docs`**.

---

### 6.3 · repeater `/repeater` — 3 endpoints · C · **fuzz-critique**

`/send` + `/send/batch` pilotent
`http().sendRequest()` (moteur HTTP, **pas**
l'UI). `/tab/create` ouvre un onglet UI sans
trafic. DB optionnelle (enregistrement
silencieusement skippé si init échoue).

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/repeater/send` | C | `SendRequest` { request:HttpRequestData?=null, requestId:Int?=null, modifications:RequestModifications?=null } — **exactement un** de request/requestId | rejeu/craft avec overrides à la volée ; renvoie req+resp+timing. |
| POST | `/repeater/send/batch` | C | `BatchSendRequest` { requests:List\<SendRequest\> } | plusieurs requêtes en un appel (séquentiel). |
| POST | `/repeater/tab/create` | C | `CreateTabRequest` { name:String?=null, request:HttpRequestData?=null, requestId:Int?=null } | pousse une requête dans l'UI Repeater. |

- **pré/post/err** : `/send` exactement un de
  request/requestId ; row history (source=
  'repeater') + upsert sitemap si DB.
  `INVALID_REQUEST` 400 (ni l'un ni l'autre /
  hors bornes / JSON malformé),
  `SERVICE_UNAVAILABLE` 503, `INTERNAL_ERROR`
  500. `/send/batch` strictement séquentiel ;
  échec sur item N → **abort total**, aucun
  partiel. `/tab/create` aucun trafic, aucune
  DB ; si request ET requestId null → **fallback
  silencieux** `https://example.com`.

#### fuzzModels — repeater

```
SendRequest (inline + modifications) :
{ "request":{"method":"POST","url":"https://t/api",
   "headers":[{"name":"Authorization","value":"Bearer T"}],
   "body":"{...}"},
  "requestId":null,
  "modifications":{"headers":{"X-Role":"admin"},
   "body":"FUZZ","method":"POST","path":"/api?x=FUZZ"} }

SendRequest (rejeu history) :
{ "requestId":42, "modifications":{"body":"FUZZ"} }

RequestModifications {
  headers:Map<String,String>?  // replace (remove+add)
  body:String?                 // remplace tout le body
  method:String?               // remplace le verbe
  path:String?                 // remplace le path (pas l'URL)
}  // 4 champs indépendants, seuls les non-null s'appliquent
```

> Pas de marqueurs positionnels ici : le fuzz
> repeater se fait via le payload complet dans
> `body`/`path`. **Pour le fuzz positionnel →
> Intruder.**

---

### 6.4 · intruder `/intruder` — 8 endpoints · C(limité) · **fuzz-critique**

État d'attaque en mémoire (ConcurrentHashMap,
perdu au reload). `/quick-fuzz` synchrone ;
`/attack/create`+`/start` async (thread de
fond). ⚠ **Seul sniper implémenté.**

> Pro : l'Intruder de Burp Pro n'est **pas**
> utilisé directement — l'envoi est délégué à
> RepeaterService (moteur HTTP). Donc cette
> surface tourne en **Community** (pas de
> throttling Community Intruder), mais reste
> limitée à sniper côté serveur.

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/intruder/attack/create` | C | `CreateAttackRequest` { requestId:Int?=null, request:HttpRequestData?=null, attackType:String="sniper", positions:List\<PayloadPosition\>=[], payloads:Map\<String,List\<String\>\>={}, options:AttackOptions=() } | crée l'attaque, renvoie `attackId`. |
| POST | `/intruder/attack/{id}/start` | C | path : `id:String` | lance le thread de fond. |
| GET | `/intruder/attack/{id}/status` | C | path : `id:String` | poll progress 0-100 / isComplete. |
| GET | `/intruder/attack/{id}/results` | C | path `id:String` ; query `offset:Int=0`, `limit:Int=0` (0=tout) | inspecte statusCode/length/anomalous. |
| POST | `/intruder/attack/{id}/pause` | C | path : `id:String` | pause coopérative. |
| POST | `/intruder/attack/{id}/resume` | C | path : `id:String` | reprend. |
| POST | `/intruder/attack/{id}/stop` | C | path : `id:String` | stoppe (pas d'interrupt). |
| POST | `/intruder/quick-fuzz` | C | `QuickFuzzRequest` { requestId:Int?=null, request:HttpRequestData?=null, param:String (requis), payloads:List\<String\> (requis non-vide), options:AttackOptions=() } | fuzz synchrone 1 param + baseline + anomalous. |

- **Contrat clé** : `attackId:String` (8-char
  UUID) ; `requestId:Int` (index history 0-based).
- **pré/post/err** : `create` ne valide **pas**
  request/requestId (validé au `/start`).
  `/start` démarre un **nouveau Thread à chaque
  appel** → race si attaque déjà running.
  `isComplete` = status ∈ {completed, stopped,
  error}. `quick-fuzz` : baseline = 1er résultat
  `error==null` ; `anomalous` si statusCode≠ OU
  |Δlength| > max(length·0.2, 20) OU
  contentType≠. 400 si param blank / payloads
  vide / ni request ni requestId.

#### fuzzModels — intruder (load-bearing `--pos`)

```
PayloadPosition { "start":42, "end":52, "name":"username" }
// start/end = offsets (Int, requis, sans défaut).
// name = clé de substitution. Seul positions[0].name en sniper.

CreateAttackRequest {
  "requestId":3,                  // OU "request" inline
  "attackType":"sniper",          // seul sniper implémenté
  "positions":[{"start":42,"end":52,"name":"username"}],
  "payloads":{"set1":["admin","root","' OR 1=1--"]},
                                   // TOUTES les valeurs aplaties
  "options":{"followRedirects":true,"maxRetries":0,"throttleMs":100} }

QuickFuzzRequest {
  "requestId":3, "param":"q",     // param String requis non-blank
  "payloads":["<script>alert(1)</script>","' OR '1'='1"],
  "options":{"throttleMs":0} }

AttackResultEntry {  // analyse différentielle
  index, payload, statusCode (0 si err), length, durationMs,
  error:String?, contentType:String?, bodyPreview:String?,
  anomalous:Boolean }  // anomalous seulement en quick-fuzz
```

**6 modes de substitution** (substitutePayload) :
URL `{param}` · query `?param=*` · body
`{param}` · form `param=*` · JSON
`"param":"*"` · header dont le nom == param
(case-insensitive).

---

### 6.5 · collaborator `/collaborator` — 4 endpoints · **P**

⚠ **Burp Suite Professional requis** (Community
n'a pas l'API Collaborator). État en mémoire
(perdu au restart).

| Méthode | Path | Pro | Modèle requête | Usage hunter |
|---|---|---|---|---|
| POST | `/collaborator/generate` | **P** | — | génère 1 payload OAST (SSRF/XXE/OOB blind). |
| POST | `/collaborator/generate/batch` | **P** | `BatchGenerateRequest` { count:Int=1 } | N payloads distincts en un appel. |
| GET | `/collaborator/poll` | **P** | — | sweep de toutes les interactions de la session. |
| GET | `/collaborator/poll/{id}` | **P** | path : `id:String` | poll scopé à un payload précis. |

- **err** : `SERVICE_UNAVAILABLE` 503 si API
  Collaborator null (Community / serveur non
  configuré) ou client non créable.
- **Flags** : `interactionId == id` (clé locale,
  pas un UUID Burp). `timestamp` =
  `Instant.now()` au poll. Erreurs de poll
  **silencieusement avalées** → `found=false`
  (HTTP 200), impossible de distinguer "id
  inconnu" de "pas encore d'interaction".
  `Interaction.type` = `.name` enum Burp
  (DNS/HTTP/SMTP). `/generate/batch` et
  `/poll/{id}` **absents de `/docs`**.

#### fuzzModels — collaborator

```
BatchGenerateRequest { "count":<Int> }
// fuzz : 0, négatifs, très grands, omis (→1), non-entier (→ erreur deser)
Interaction.type : "DNS" | "HTTP" | "SMTP"
```

---

### 6.6 · scanner `/scanner` — 9 endpoints · **P**

⚠ **Burp Suite Professional requis** pour les 3
start (crawl/audit/crawl-and-audit). État en
mémoire.

| Méthode | Path | Pro | Modèle requête | Usage hunter |
|---|---|---|---|---|
| POST | `/scanner/crawl` | **P** | `ScanRequest` { url:String, config:ScanConfig=() } | spider l'app, map les endpoints. |
| POST | `/scanner/audit` | **P** | `ScanRequest` (⚠ url **ignoré**) | active checks (LEGACY_ACTIVE) — scope = scope Burp. |
| POST | `/scanner/crawl-and-audit` | **P** | `ScanRequest` | scan complet en un appel. |
| GET | `/scanner/{id}/status` | **P** | path : `id:String` | issueCount (crawl/auditProgress = stub 0). |
| GET | `/scanner/{id}/issues` | **P** | path : `id:String` | liste des vulns (name/url/severity/confidence). |
| POST | `/scanner/{id}/pause` | **P** | path : `id:String` — **stub** | ne met PAS en pause (renvoie status). |
| POST | `/scanner/{id}/resume` | **P** | path : `id:String` — **stub** | ne reprend rien. |
| POST | `/scanner/{id}/stop` | **P** | path : `id:String` | retire du map ; **n'arrête PAS** le scan Burp. |
| GET | `/scanner/issue-definitions` | C | — | définitions d'issues depuis le sitemap (dégradé gracieux). |

- **err** : `IllegalStateException` 500 sur
  Community (message explicite "requires Burp
  Suite Professional"). Beaucoup d'exceptions
  **avalées** → HTTP 200 avec `status='error'`
  ou liste vide.
- **Flags** : `audit` n'utilise **pas** `url` ;
  `pause`/`resume` stubs ; `stop` découple
  tracking et exécution (la tâche Burp continue) ;
  `crawl/auditProgress` toujours 0 ;
  `typeIndex` toujours 0L. **Groupe entier
  absent du `/docs`.**
- `severity` : HIGH/MEDIUM/LOW/INFORMATION/
  FALSE_POSITIVE. `confidence` : CERTAIN/FIRM/
  TENTATIVE.

> `/scanner/issue-definitions` lit le sitemap →
> **dégrade en Community** (liste vide si
> indisponible), donc le seul endpoint du groupe
> exploitable sans Pro.

---

### 6.7 · securityscan `/scan` — 5 endpoints · C

Scanner custom (≠ ScannerRoutes Pro). Toutes les
probes passent par `SessionService.send()` +
moteur HTTP Burp. **Une session active est
requise** pour les probes auth. Synchrone /
bloquant.

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/scan/auth-bypass` | C | `AuthBypassRequest` { endpoints:List\<String\> (requis), baseUrl:String (requis), method:String="GET" } | triple-probe (withAuth/withoutAuth/cookieOnly) → accès non authentifié. |
| POST | `/scan/idor` | C | `IdorRequest` { endpoint, param, ownValues:List\<String\>, targetValues:List\<String\> (tous requis), method="GET", body:String?, extraHeaders:Map?\} | accès cross-account (>5% delta length, status 2xx). |
| POST | `/scan/headers` | C | `HeadersBypassRequest` { url:String (requis), method="GET", body:String? } | 16 headers IP-spoof/URL-override → bypass 403. |
| POST | `/scan/cors` | C | `CorsRequest` { url:String (requis), method="GET" } | 8 origins craftés → CORS crédentialé exploitable. |
| POST | `/scan/endpoints` | C **+DB** | `EndpointsScanRequest` { host:String (requis), tests:List\<String\>=["auth-bypass","method-switch"], limit:Int=100 } | scan en masse de l'history proxy par host. |

- **pré/post/err** : `INVALID_REQUEST` 400 sur
  listes vides / JSON malformé ; `INTERNAL_ERROR`
  500. `/scan/endpoints` exige la **DB SQLite**
  (sinon `SERVICE_UNAVAILABLE` 503).
- **Flags** : filtre SPA HTML catch-all
  (body `<!` et >50000 → status 302/length 0).
  `headers` = 16 entrées fixes. `cors` = 8
  origins fixes. Probes no-auth **non
  enregistrées** dans l'history. **Groupe entier
  absent du `/docs`.**

#### fuzzModels — securityscan

```
AuthBypassRequest {"endpoints":["/api/admin"],"baseUrl":"https://t","method":"GET"}
IdorRequest {"endpoint":"https://t/orders/{id}","param":"id",
  "ownValues":["123"],"targetValues":["124","125"],"method":"GET"}
HeadersBypassRequest {"url":"https://t/admin","method":"GET"}
CorsRequest {"url":"https://t/api/data","method":"GET"}
EndpointsScanRequest {"host":"t.com","tests":["auth-bypass","method-switch"],"limit":100}
```

---

### 6.8 · target `/target` — 6 endpoints · C

Scope tracké **en mémoire** (heap JVM, reset au
restart). `/scope/check` délègue au moteur de
scope Burp (reflète l'UI).

| Méthode | Path | Pro | Modèle requête | Usage hunter |
|---|---|---|---|---|
| GET | `/target/sitemap` | C | query : `url:String?` (prefix) | dump le sitemap Burp (wordlist / endpoints cachés). |
| GET | `/target/scope` | C | — | lit le scope in-memory (≠ UI Burp). |
| POST | `/target/scope` | C | `SetScopeRequest` { includes:List\<String\> (requis), excludes:List\<String\>=[] } | **remplace** (clear+set) tout le scope. |
| POST | `/target/scope/add` | C | `AddScopeRequest` { url:String (requis) } | ajoute 1 URL. |
| POST | `/target/scope/remove` | C | `AddScopeRequest` { url:String } | exclut 1 URL (même DTO que add). |
| GET | `/target/scope/check` | C | query : `url:String` (requis) | verdict scope autoritaire (moteur Burp). |

- **Flags** : `POST /target/scope` est un
  **full replace** — `includes=[]` efface tout
  le scope. `GET /target/scope` ne voit **pas**
  le scope configuré dans l'UI ; `/scope/check`
  oui. `/scope/check` sans url → `INVALID_PARAM`
  dans une enveloppe **HTTP 200** (early-return).
  `ScopeCheckRequest` = DTO **mort** (non
  utilisé).

#### fuzzModels — target

```
SetScopeRequest {"includes":["https://ex.com"],"excludes":["https://ex.com/logout"]}
AddScopeRequest {"url":"https://ex.com/api"}  // add ET remove
SitemapEntry {"url":"...","method":"GET","statusCode":200,"mimeType":"HTML"}
// statusCode/mimeType nullables → apparaissent en null (encodeDefaults=true)
```

---

### 6.9 · decoder `/decoder` — 4 endpoints · C

Pur JVM (Base64/URL/hex/HTML + MessageDigest).
Aucun Montoya, aucune Pro.

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/decoder/encode` | C | `EncodeRequest` { data:String, encoding:String } — encoding ∈ {base64,url,hex,html} | encode un payload pour survivre un WAF. |
| POST | `/decoder/decode` | C | `DecodeRequest` { data:String, encoding:String?=null } — null → auto-détect | décode cookie/token ; auto si encoding omis. |
| POST | `/decoder/hash` | C | `HashRequest` { data:String, algorithm:String } — md5/sha1/sha256/384/512 | compare un token à un hash candidat. |
| POST | `/decoder/smart-decode` | C | `DecodeRequest` (encoding **ignoré**) | pèle jusqu'à 10 couches + trace par étape. |

- **err** : `INVALID_REQUEST` 400 (encoding hors
  set / base64 invalide / hex impair / JSON
  malformé). `INTERNAL_ERROR` 500.
- **Flags** : `html` encode seulement 5 entités
  (`& < > " '`). `smart-decode` **ignore**
  `encoding`. Auto-détect peut se tromper sur
  entrées courtes/ambiguës. `hash` echo
  l'algorithme demandé (pas le nom JVM
  normalisé).

#### fuzzModels — decoder

```
EncodeRequest {"data":"<s>","encoding":"base64|url|hex|html"}
DecodeRequest {"data":"<s>","encoding":"base64|url|hex|html|null"}
HashRequest {"data":"<s>","algorithm":"md5|sha1|sha-1|sha256|...|<raw-jvm>"}
DecodeStep (réponse) {"encoding":"<scheme>","result":"<intermediaire>"}
```

---

### 6.10 · config `/config` — 5 endpoints · C

⚠ **Les 4 `/config/*` sont des stubs** : GET
renvoie un map hardcodé `{"type":"..."}` ; PUT
echo le payload sans écrire dans Burp.

| Méthode | Path | Pro | Modèle requête | Usage hunter |
|---|---|---|---|---|
| GET | `/config/project` | C — **stub** | — | renvoie `{"type":"project"}`. |
| PUT | `/config/project` | C — **stub** | `ConfigUpdateRequest` { config:Map\<String,String\> } | echo (pas de write durable). |
| GET | `/config/user` | C — **stub** | — | renvoie `{"type":"user"}`. |
| PUT | `/config/user` | C — **stub** | `ConfigUpdateRequest` { config:Map } | echo. |
| GET | `/extensions` | C | — | self-metadata (filename) ; total **toujours 1**. |

- **Flag** : `/extensions` est monté à la racine
  (`/extensions`, **pas** `/config/extensions`)
  mais appartient au groupe config par
  ownership. Montoya ne permet d'inspecter que
  l'extension active → `total=1` hardcodé.

---

### 6.11 · session `/session` — 7 endpoints · C

Session singleton partagée. Cookies/headers
appliqués à tous les `/send`. Persistée via
SessionDao (SQLite `~/.burp-rest/burpdata`) si
DB dispo. Cookie-jar (Set-Cookie auto-capturés)
**distinct** des session cookies.

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/session/set` | C | `SetSessionRequest` { cookies:Map (requis), headers:Map?=null, name:String?=null } | charge cookies+headers d'auth (full **replace**). |
| GET | `/session/get` | C | — | inspecte la session active. |
| DELETE | `/session/clear` | C | — | reset cookies/headers (pas le cookie-jar). |
| POST | `/session/send` | C | `AuthenticatedRequest` { method="GET", url:String (requis), body:String?=null, extraHeaders:Map?=null } | requête authentifiée via Burp (apparaît dans l'history). |
| POST | `/session/send/batch` | C | `BatchAuthenticatedRequest` { requests:List\<AuthenticatedRequest\> } | séquence multi-step (workflow / IDOR). |
| GET | `/session/cookie-jar` | C | — | cookies auto-capturés par domaine. |
| DELETE | `/session/cookie-jar` | C | — | vide le cookie-jar (pas la session). |

- **Flags** : `/session/set` = full replace.
  `extraHeaders` **override** les session
  headers (pas additif). Cookie-jar in-memory
  (pas DB) ; survit à `clear`, wipé au reload.
  `/send/batch` séquentiel ; échec → abort
  total. **Groupe entier absent du `/docs`.**

---

### 6.12 · utils `/utils` — 2 endpoints · C

Dépend de SessionService (moteur HTTP Burp).
Pas de DB requise.

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| POST | `/utils/diff` | C | `DiffRequest` { a:DiffTarget, b:DiffTarget } — DiffTarget { url:String (requis), method="GET", body:String?, extraHeaders:Map? } | 2 requêtes live → diff status/length/headers (access-control). |
| POST | `/utils/extract-endpoints` | C | `ExtractEndpointsRequest` { url:String (requis) } | extrait les endpoints API du HTML + JS (regex). |

- **Flags** : `diff` body-diff = résumé
  set-based (pas unifié). `extract-endpoints`
  fetch jusqu'à **10 bundles JS** (cap), erreurs
  par bundle avalées, filtre les assets
  statiques + w3.org. **Groupe entier absent du
  `/docs`.**

---

### 6.13 · history `/history` — 5 endpoints · C · **CONDITIONNEL DB**

> ⚠ **Groupe registré UNIQUEMENT si
> `historyDao != null && sitemapDao != null`.**
> Si l'init DB (`~/.burp-rest/burpdata`)
> échoue, **les 5 endpoints renvoient 404** —
> le groupe est silencieusement absent.
> **`bp` doit gérer cette absence** (probe +
> dégradation).

| Méthode | Path | Pro | Modèle requête (types Kotlin) | Usage hunter |
|---|---|---|---|---|
| GET | `/history` | C+DB | `HistoryFilter` (query) : host?, method?, statusCode:Int?, source?, search?, since?, until?, page:Int=0, pageSize:Int=50 | pagine tout le trafic ; grep secrets/JWT. |
| GET | `/history/{id}` | C+DB | path : `id:Long` (toLongOrNull) | une entrée complète (req+resp). |
| GET | `/history/sitemap` | C+DB | query : `host:String?` | tuples host+path+method uniques + hitCount. |
| POST | `/history/{id}/replay` | C+DB | path : `id:Long` | rejoue verbatim une entrée (live via Burp). |
| DELETE | `/history` | C+DB | — | **destructif** : wipe history + sitemap. |

- **Contrat clé** : `HistoryEntryResponse.id` =
  **Long** ; `HistoryPageResponse.total` =
  **Long** ; `SitemapListResponse.total` =
  **Int** (incohérence de type assumée).
  Entries triées id DESC. Bodies tronqués à
  **1 Mo** à l'insert.
- **err** : id non-Long → `INVALID_REQUEST` 400 ;
  id absent → 400 ; DB échouée → **404** (route
  absente).
- **Flags** : `replay` non persisté (id=0,
  source='replay') mais RepeaterService peut
  réinsérer. `?search=` = SQL LIKE non-échappé
  (`%`/`_` = wildcards). `DELETE` **irréversible,
  sans confirmation**, non transactionnel entre
  les 2 tables.

#### fuzzModels — history

```
HistoryFilter (query) :
host&method&statusCode=<int>&source=proxy|repeater|replay|intruder
&search&since=<ISO8601>&until=<ISO8601>&page=0&pageSize=50
// fuzz : statusCode=abc (ignoré), page=-1, pageSize=0, search=%25
HistoryEntryResponse : nullables = reqBody, statusCode, resHeaders, resBody
```

---

## 7 · Matrice Community vs Pro

`bp` doit **dégrader gracieusement** : détecter
Pro/Community au runtime et désactiver/avertir
sur les groupes Pro.

| Groupe | Pro requis ? | Détail |
|---|---|---|
| health | **Non (C)** | introspection pure. |
| proxy | **Non (C)** | Montoya proxy dispo en Community ; 4 stubs. |
| repeater | **Non (C)** | moteur HTTP, dispo Community. |
| intruder | **Non (C)** | délégué à Repeater (pas l'Intruder Pro) ; **sniper only** côté serveur. |
| collaborator | **OUI (P)** | API Collaborator = **Pro only** → 503 en Community. |
| scanner | **OUI (P)** | crawl/audit = Pro → 500 en Community. `issue-definitions` dégrade (C). |
| securityscan `/scan` | **Non (C)** | probes via moteur HTTP + session ; `/scan/endpoints` exige la DB. |
| target | **Non (C)** | scope API dispo Community. |
| decoder | **Non (C)** | pur JVM. |
| config | **Non (C)** | stubs. |
| session | **Non (C)** | moteur HTTP. |
| utils | **Non (C)** | moteur HTTP. |
| history | **Non (C)** mais **+DB** | conditionnel à l'init SQLite. |

**Synthèse** : seuls **collaborator** et
**scanner (start)** sont strictement Pro
(dérivé de `conditional`/`caveats` de la
source). Tout le reste tourne en Community. Le
seul "à confirmer" est l'intruder : la source
montre qu'il **n'utilise pas** l'Intruder Pro
(envoi délégué à Repeater), donc Community —
**à confirmer** par test live.

---

## 8 · Contrat Kotlin (sérialisation)

Config Json globale (RestServer.configurePlugins) :

```
Json {
  prettyPrint = false
  isLenient = true
  ignoreUnknownKeys = true
  encodeDefaults = true
}
```

**Implications client (`bp`)** :

- `prettyPrint=false` → réponses compactes
  mono-ligne.
- `isLenient=true` → le serveur tolère du JSON
  légèrement invalide en entrée (clés non
  quotées, virgules traînantes).
- `ignoreUnknownKeys=true` → `bp` peut envoyer
  un **sur-ensemble** de champs sans erreur ;
  les champs inconnus sont **silencieusement
  droppés**.
- `encodeDefaults=true` → les réponses
  **incluent toujours** chaque champ même
  null/défaut. `bp` peut se fier à la présence
  de tous les champs déclarés (pas de clé
  manquante à gérer).

**Enveloppe** : `ApiResponse<T>` { success:
Boolean, data:T?=null, error:ApiError?=null } ;
`ApiError` { code:String, message:String }.
Exceptions : `/docs` (JSON brut) et les stubs
proxy (`Map<String,Boolean>` inline) **ne sont
pas** enveloppés.

**Mapping StatusPages** :

| Exception | HTTP | code |
|---|---|---|
| BadRequestException | 400 | INVALID_REQUEST |
| SerializationException | 400 | INVALID_REQUEST |
| IllegalArgumentException | 400 | INVALID_REQUEST |
| IllegalStateException | 503 | SERVICE_UNAVAILABLE |
| Throwable | 500 | INTERNAL_ERROR |

**Types d'id (load-bearing)** :

- `requestId` = **Int** (index history 0-based),
  partout (repeater, intruder, quick-fuzz).
- `attackId` / `scanId` / collaborator `id` =
  **String** (8-char UUID prefix).
- history `id` = **Long** (clé DB).
- `{id}` path proxy parsé via `toIntOrNull` →
  `INVALID_PARAM` (pas 404) si non-entier.

**Formes d'enums (toutes en String, pas d'enum
Kotlin `@Serializable`)** :

- `attackType` : "sniper" (impl.) | "battering-ram"
  | "pitchfork" | "cluster-bomb" (acceptés,
  exécutent sniper).
- attack `status` : created | running | paused |
  stopped | completed | error.
- WS `direction` / Interaction `type` : `.name`
  de l'enum Montoya (CLIENT_TO_SERVER ;
  DNS/HTTP/SMTP).
- scan `severity` : HIGH/MEDIUM/LOW/INFORMATION/
  FALSE_POSITIVE. `confidence` : CERTAIN/FIRM/
  TENTATIVE.

**Nullables / defaults notables** : `body`
omis-safe partout ; `headers=emptyList()`
sérialisé `[]` ; `method="GET"` toujours présent
(encodeDefaults) ; champs jamais peuplés rendus
`null` (burpVersion, listenerInterface,
clientIp, timestamp HTTP).

**Aucun `@SerialName`** dans tout le codebase →
les noms JSON = identifiants Kotlin (camelCase).

---

## 9 · C4 Run Ledger (observabilité / ISO)

> **Capacité NOUVELLE proposée — à valider.**
> C'est la différenciation de `bp` vs `curl`.

**Idée** : chaque opération `bp` (fuzz, send,
scan, collaborator…) est enregistrée dans une
**DB locale SQLite sous `~/.bp/`**, indépendante
de la DB de l'extension.

**Champs par entrée** :

- `id` (local), `name` / `tag` (libellé
  founder), `timestamp`, `target` (host/url),
  `command` (la ligne `bp` exécutée),
  `request_ref` / `response_ref`, `status`
  (ok/err), `burp_op` (endpoint REST appelé).

**Requêtable** :

- `bp log` — liste / filtre les runs.
- `bp tag <id> <label>` — annote a posteriori.
- `bp show <id>` — détail req/resp.

**Cadrage ISO / traçabilité** : un hunter ou un
audit peut **rejouer**, **prouver**, et
**dater** chaque action menée contre une cible —
ce que `curl` ne donne pas. Aligne `bp` sur une
exigence de traçabilité d'engagement.

**À valider** : périmètre (toutes les ops ou
seulement fuzz/scan ?), rétention, format
d'export (JSON/CSV), couplage optionnel avec C3.

---

## 10 · Architecture de test (TDD)

3 niveaux, RED d'abord pour l'unit.

| Niveau | Quoi | Burp requis ? |
|---|---|---|
| **Unit (purs)** | parser `--pos`, résolveur d'offset (sélecteur sémantique → byte-range), builder `CreateAttackRequest`. | Non. |
| **Contract-tests** | le JSON émis colle au contrat Kotlin (types, nullables, enums-as-String, id-types) figé depuis la source §8. | Non. |
| **Integration (live)** | smoke contre `:8089` réel, walk des endpoints. | **OUI — accepté (D1 résolu).** |

> **D1 résolu** : la dépendance "tests live ↔
> Burp lancé" est **acceptée** — Burp doit
> tourner pour la suite integration ; skip
> propre sinon.

---

## 11 · DDD

**Aggregates** :

- `FuzzPlan` — Positions[] + PayloadSets +
  AttackType. **Invariant** : un `cluster-bomb`
  exige ≥1 set par position.
- `CapturedRequest` — requestId, bytes de base
  (source de la résolution d'offsets).
- `AttackRun` — état created → running →
  completed + `AttackResultEntry[]`.
- `LedgerEntry` — une opération tracée (C4).

**Ubiquitous language** = celui de **Burp /
Intruder** (sniper, position, payload set,
collaborator, scope), **pas** un jargon
inventé.

---

## 12 · Roadmap couverture

**Non exposé aujourd'hui** (confirmé absent de
`configureRouting()`) :

| Surface | État source |
|---|---|
| **Sequencer** | `SequencerModels.kt` **orphelin** — modèles morts, aucune route, aucun service. |
| **Comparer** | jamais implémenté (`/utils/diff` ≠ Comparer complet). |
| **Logger** | jamais implémenté. |
| **Organizer** | jamais implémenté. |
| **Engagement** | jamais implémenté. |
| **Search** | jamais implémenté (listé fantôme dans README). |
| **Inspector** | jamais implémenté. |
| **Dashboard** | jamais implémenté. |
| **Clickbandit** | jamais implémenté. |

**Principe** : `bp` doit être **extensible**.
Exposer plus = **travail d'extension Kotlin**
côté serveur (nouveaux `*Routes.kt` +
`*Service.kt`) — **séquencé plus tard**, hors
Phase 0. `bp` ne peut piloter que ce que l'API
expose réellement.

---

## 13 · Décisions ouvertes

| # | Décision | État |
|---|---|---|
| **D1** | Tests live ↔ Burp lancé. | **RÉSOLU** — Burp requis, accepté. |
| **D-Nom** | `bp` (+ alias `burpctl`). | **à confirmer** (founder). |
| **D-C3** | Adapter bug-bounty-mini + 3 sous-choix (scope-check / log / wrap anti-injection). | **différé** — à expliquer plus tard. |
| **D-Intruder-Pro** | intruder = Community (envoi délégué à Repeater) ? | **à confirmer** par test live. |
| **D-Ledger** | périmètre / rétention / export du C4. | **à valider** (§9). |

---

## 14 · Critères d'acceptation

Chaque item porte ses 2 axes (importance ·
blocking).

### CRITICAL

- [CRITICAL][BLOCKS:high] La grammaire `--pos`
  couvre header / cookie / body / path / query +
  `offset:` + multi-position + 4 attack-types.
- [CRITICAL][BLOCKS:high] `bp` résout les
  sélecteurs sémantiques en **byte-offsets**
  (`start/end/name`) depuis la requête de base,
  car l'API Intruder n'accepte que des offsets
  bruts.
- [CRITICAL][BLOCKS:critical] La spec est
  **source-grounded** : 69 endpoints / 13
  groupes, aucun endpoint inventé, autorité =
  `routes/*.kt`.
- [CRITICAL][BLOCKS:high] `bp` cible
  `http://127.0.0.1:8089` (pas 9876) ;
  `spec.md` est traité comme **périmé**.

### HIGH

- [HIGH][BLOCKS:high] `bp` détecte
  Pro/Community et **dégrade gracieusement** :
  avertit/désactive collaborator et scanner
  (start) hors Pro.
- [HIGH][BLOCKS:high] `bp` gère l'**absence
  conditionnelle** du groupe `/history` (404 si
  DB non initialisée).
- [HIGH][BLOCKS:low] Le client respecte le
  contrat de sérialisation : enveloppe
  `ApiResponse<T>`, mapping StatusPages, id-types
  (requestId Int / attackId String / history
  Long), enums-as-String.
- [HIGH][BLOCKS:high] `cluster-bomb` /
  `pitchfork` / `battering-ram` sont réalisés
  **client-side** (expansion matricielle) tant
  que l'extension n'implémente que sniper.
- [HIGH][BLOCKS:low] Contract-tests figent le
  JSON émis contre les modèles Kotlin réels.

### MEDIUM

- [MEDIUM][BLOCKS:none] Le **Run Ledger (C4)**
  enregistre chaque op (id, name/tag, timestamp,
  target, refs, status) et est requêtable
  (`bp log`, `bp tag`).
- [MEDIUM][BLOCKS:none] `bp` expose les
  **caveats** des stubs (proxy intercept/forward/
  drop, scanner pause/resume, config) plutôt que
  de prétendre qu'ils fonctionnent.
- [MEDIUM][BLOCKS:none] La suite integration
  live tourne contre `:8089` (skip propre si
  Burp absent).

### LOW (convergence tail)

- [LOW][BLOCKS:none] `bp` signale que `/docs`
  (OpenAPI embarqué) est **incomplet** (déclare
  0.2.0, omet plusieurs groupes) et n'en dépend
  pas pour la découverte.
- [LOW][BLOCKS:none] Confirmer le nom `bp`
  (D-Nom) et cadrer C3 (D-C3).
- [LOW][BLOCKS:none] Confirmer le statut
  Community de l'intruder par test live
  (D-Intruder-Pro).

---

> **Rappel : DRAFT — proposed, awaiting founder
> validation. No implementation until GO.**
