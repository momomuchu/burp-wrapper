# Burp Suite AI Integration - Complete Tool Specifications
## Wrapper API pour agents IA (Claude Code, Gemini CLI, etc.)

**Version:** 1.0  
**Pour:** LO  
**Objectif:** Wrapper Python/JS qui expose TOUTES les fonctionnalités Burp Suite via l'API REST du MCP Server existant (port 9876)

---

## 1. Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     AGENT IA                                    │
│              (Claude Code / Gemini CLI / etc.)                  │
│                                                                 │
│   Utilise déjà: MCP Playwright (pour browser control)          │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            │ Tool calls directs (pas MCP)
                            ▼
┌────────────────────────────────────────────────────────────────┐
│              BURP WRAPPER (Python ou Node.js)                   │
│                                                                 │
│   • Classe/module simple avec méthodes pour chaque tool        │
│   • Appelle l'API SSE du MCP Server Burp existant              │
│   • Optimisé pour minimiser les tokens (responses concises)    │
│   • Peut être importé directement dans le code de l'agent      │
└───────────────────────────┬────────────────────────────────────┘
                            │
                            │ HTTP REST (localhost:9876)
                            ▼
┌────────────────────────────────────────────────────────────────┐
│           BURP SUITE PRO + MCP SERVER EXTENSION                 │
│                                                                 │
│   Extension officielle PortSwigger déjà installée               │
│   API SSE sur http://127.0.0.1:9876                            │
└────────────────────────────────────────────────────────────────┘
```

**Pourquoi un wrapper et pas MCP?**
- Moins de tokens (pas de protocol overhead MCP)
- Plus simple à intégrer dans du code existant
- Peut être utilisé comme simple module Python/JS
- L'agent peut faire `from burp_wrapper import BurpClient` et c'est parti

---

## 2. Liste Complète des Tools Burp Suite Pro

### Checklist de couverture (TOUS les tools)

| Tool Burp | Couvert | Priorité | Notes |
|-----------|---------|----------|-------|
| **Dashboard** | ✅ | P1 | Scans, tasks, issues |
| **Target** | ✅ | P1 | Sitemap, scope, issues |
| **Proxy** | ✅ | P1 | HTTP history, intercept, WebSocket |
| **Scanner** | ✅ | P1 | Crawl, audit, findings (Pro) |
| **Intruder** | ✅ | P1 | Attacks, payloads, results |
| **Repeater** | ✅ | P1 | Send, modify, analyze |
| **Sequencer** | ✅ | P2 | Token analysis |
| **Decoder** | ✅ | P1 | Encode/decode/hash |
| **Comparer** | ✅ | P2 | Diff requests/responses |
| **Logger** | ✅ | P2 | All traffic, filters |
| **Collaborator** | ✅ | P1 | OOB payloads (Pro) |
| **Organizer** | ✅ | P3 | Store/annotate messages |
| **DOM Invader** | ❌ | - | Browser extension, pas API |
| **Clickbandit** | ✅ | P3 | Generate PoC |
| **Infiltrator** | ❌ | - | Agent-based, pas API |
| **Inspector** | ✅ | P2 | Parse/edit messages |
| **Engagement Tools** | ✅ | P2 | Target analyzer, content discovery |
| **Search** | ✅ | P2 | Search across project |
| **Extensions** | ✅ | P3 | List/manage extensions |
| **Project/Config** | ✅ | P2 | Settings, export/import |

---

## 3. Spécifications Détaillées des Tools

---

### 3.1 PROXY

#### `proxy.get_history()`
```python
"""Récupère l'historique HTTP du proxy."""

Parameters:
    limit: int = 100              # Max entries
    offset: int = 0               # Pagination
    filter_host: str = None       # Regex sur host
    filter_path: str = None       # Regex sur path
    filter_method: str = None     # GET, POST, etc.
    filter_status: int = None     # 200, 404, 500...
    filter_mime: str = None       # application/json, text/html...
    filter_search: str = None     # Recherche dans req+resp
    in_scope_only: bool = False   # Seulement in-scope
    has_params: bool = None       # Seulement avec paramètres
    
Returns:
    {
        "total": int,
        "entries": [
            {
                "id": str,
                "index": int,
                "timestamp": str,           # ISO 8601
                "method": str,
                "url": str,
                "host": str,
                "path": str,
                "status_code": int,
                "response_length": int,
                "mime_type": str,
                "extension": str,
                "has_params": bool,
                "param_count": int,
                "in_scope": bool,
                "comment": str,
                "highlight": str            # none, red, orange, yellow, green, cyan, blue, pink, magenta, gray
            }
        ]
    }
```

#### `proxy.get_request(request_id)`
```python
"""Récupère le détail complet d'une requête."""

Parameters:
    request_id: str               # ID de l'entrée history

Returns:
    {
        "id": str,
        "request": {
            "raw": str,           # Requête HTTP brute complète
            "method": str,
            "url": str,
            "path": str,
            "http_version": str,
            "headers": [{"name": str, "value": str}],
            "cookies": [{"name": str, "value": str, "domain": str, "path": str}],
            "body": str,
            "body_base64": str,   # Si binaire
            "content_type": str,
            "parameters": [
                {
                    "name": str,
                    "value": str,
                    "type": str   # "url" | "body" | "cookie" | "json" | "xml" | "multipart"
                }
            ]
        },
        "response": {
            "raw": str,           # Réponse HTTP brute complète
            "status_code": int,
            "status_text": str,
            "http_version": str,
            "headers": [{"name": str, "value": str}],
            "cookies_set": [{"name": str, "value": str, "attributes": dict}],
            "body": str,
            "body_base64": str,   # Si binaire
            "mime_type": str,
            "length": int
        },
        "timing": {
            "request_time": str,
            "response_time": str,
            "duration_ms": int
        }
    }
```

#### `proxy.get_websocket_history()`
```python
"""Récupère l'historique WebSocket."""

Parameters:
    limit: int = 100
    filter_url: str = None
    
Returns:
    {
        "total": int,
        "connections": [
            {
                "id": str,
                "url": str,
                "status": str,        # "open" | "closed"
                "message_count": int,
                "messages": [
                    {
                        "id": str,
                        "direction": str,  # "outgoing" | "incoming"
                        "opcode": int,
                        "data": str,
                        "timestamp": str
                    }
                ]
            }
        ]
    }
```

#### `proxy.intercept_toggle(enabled)`
```python
"""Active/désactive l'interception."""

Parameters:
    enabled: bool
    
Returns:
    {"intercept_enabled": bool}
```

#### `proxy.intercept_get_message()`
```python
"""Récupère le message actuellement intercepté."""

Returns:
    {
        "has_message": bool,
        "message": {
            "id": str,
            "type": str,          # "request" | "response"
            "raw": str,
            "host": str,
            "method": str,
            "url": str
        } | None
    }
```

#### `proxy.intercept_forward(message_id, modified_raw=None)`
```python
"""Forward un message intercepté (optionnellement modifié)."""

Parameters:
    message_id: str
    modified_raw: str = None      # Si None, forward tel quel
    
Returns:
    {"success": bool}
```

#### `proxy.intercept_drop(message_id)`
```python
"""Drop un message intercepté."""

Parameters:
    message_id: str
    
Returns:
    {"success": bool}
```

#### `proxy.add_match_replace_rule(rule)`
```python
"""Ajoute une règle match & replace."""

Parameters:
    rule: {
        "enabled": bool,
        "rule_type": str,         # "request_header", "request_body", "response_header", "response_body", etc.
        "match": str,             # Regex ou string
        "replace": str,
        "is_regex": bool,
        "comment": str
    }
    
Returns:
    {"rule_id": str, "success": bool}
```

---

### 3.2 REPEATER

#### `repeater.send(request, host=None, port=None, https=None)`
```python
"""Envoie une requête et retourne la réponse."""

Parameters:
    # Option 1: Depuis un ID existant
    request_id: str
    
    # Option 2: Requête brute
    raw_request: str
    host: str
    port: int = 443
    https: bool = True
    
    # Options
    follow_redirects: bool = False
    timeout_ms: int = 30000
    
Returns:
    {
        "request_sent": str,          # Requête effectivement envoyée
        "response": {
            "raw": str,
            "status_code": int,
            "headers": [{"name": str, "value": str}],
            "body": str,
            "length": int
        },
        "timing": {
            "request_time": str,
            "response_time": str,
            "duration_ms": int
        },
        "new_request_id": str         # ID dans l'history
    }
```

#### `repeater.send_modified(request_id, modifications)`
```python
"""Renvoie une requête avec modifications."""

Parameters:
    request_id: str
    modifications: {
        "headers": {str: str},        # {header_name: new_value} (None pour supprimer)
        "params": {str: str},         # {param_name: new_value}
        "body": str,                  # Remplace tout le body
        "method": str,                # Change la méthode
        "path": str                   # Change le path
    }
    follow_redirects: bool = False
    
Returns:
    # Same as repeater.send()
```

#### `repeater.send_batch(request_id, variations)`
```python
"""Envoie plusieurs variations d'une requête."""

Parameters:
    request_id: str
    variations: [
        {
            "name": str,              # Identifiant de la variation
            "modifications": {...}    # Same as send_modified
        }
    ]
    parallel: bool = False
    delay_ms: int = 0                 # Délai entre requêtes si séquentiel
    
Returns:
    {
        "results": [
            {
                "variation_name": str,
                "response": {...},
                "duration_ms": int,
                "new_request_id": str
            }
        ]
    }
```

#### `repeater.create_tab(request_id, name=None)`
```python
"""Crée un nouveau tab Repeater dans l'UI."""

Parameters:
    request_id: str
    name: str = None                  # Nom du tab
    
Returns:
    {"tab_id": str, "success": bool}
```

---

### 3.3 INTRUDER

#### `intruder.create_attack(config)`
```python
"""Configure une nouvelle attaque Intruder."""

Parameters:
    config: {
        "request_id": str,            # Requête de base
        
        "attack_type": str,           # "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb"
        
        "positions": [
            {
                # Option 1: Par offset
                "start": int,
                "end": int,
                
                # Option 2: Par paramètre
                "param_name": str,
                "param_type": str     # "url" | "body" | "cookie" | "header" | "json"
            }
        ],
        
        "payloads": [
            {
                "position_index": int,    # Pour pitchfork/cluster_bomb
                "type": str,              # "simple_list" | "numbers" | "dates" | "brute_forcer" | "runtime_file" | "null_payloads"
                
                # Pour simple_list:
                "values": [str],
                
                # Pour numbers:
                "from": int,
                "to": int,
                "step": int,
                "format": str,            # "decimal" | "hex"
                
                # Pour brute_forcer:
                "charset": str,
                "min_length": int,
                "max_length": int
            }
        ],
        
        "payload_processing": [
            {
                "type": str,              # "add_prefix" | "add_suffix" | "match_replace" | "encode" | "decode" | "hash" | "case"
                "value": str,
                "options": dict
            }
        ],
        
        "grep_match": [str],              # Strings à matcher dans les réponses
        "grep_extract": [
            {
                "name": str,
                "start": str,
                "end": str,
                "group": int              # Si regex
            }
        ],
        
        "options": {
            "follow_redirects": bool,
            "concurrent_requests": int,
            "request_delay_ms": int,
            "start_index": int,
            "end_index": int
        }
    }
    
Returns:
    {
        "attack_id": str,
        "total_requests": int,
        "estimated_time_seconds": int
    }
```

#### `intruder.start(attack_id)`
```python
"""Lance une attaque configurée."""

Parameters:
    attack_id: str
    
Returns:
    {"status": str, "attack_id": str}  # status: "started" | "queued"
```

#### `intruder.quick_fuzz(request_id, param_name, payloads)`
```python
"""Raccourci: fuzz rapide d'un paramètre."""

Parameters:
    request_id: str
    param_name: str
    payloads: [str]
    concurrent: int = 5
    
Returns:
    # Lance l'attaque et retourne directement les résultats
    {
        "results": [
            {
                "index": int,
                "payload": str,
                "status_code": int,
                "response_length": int,
                "response_time_ms": int,
                "grep_matches": [str],
                "error": str | None
            }
        ],
        "statistics": {
            "total": int,
            "by_status": {int: int},
            "anomalies": int,
            "errors": int
        }
    }
```

#### `intruder.status(attack_id)`
```python
"""Vérifie le statut d'une attaque."""

Parameters:
    attack_id: str
    
Returns:
    {
        "status": str,                # "running" | "paused" | "completed" | "cancelled"
        "progress": {
            "current": int,
            "total": int,
            "percentage": float
        },
        "speed": {
            "requests_per_second": float,
            "elapsed_seconds": int,
            "eta_seconds": int
        },
        "issues_found": int
    }
```

#### `intruder.results(attack_id, filters=None)`
```python
"""Récupère les résultats d'une attaque."""

Parameters:
    attack_id: str
    filters: {
        "status_code": int,
        "min_length": int,
        "max_length": int,
        "grep_match": str,
        "anomaly_only": bool,         # Longueurs anormales seulement
        "error_only": bool
    }
    limit: int = 1000
    offset: int = 0
    sort_by: str = "index"            # "index" | "status" | "length" | "time"
    
Returns:
    {
        "total": int,
        "results": [
            {
                "index": int,
                "payload": str | [str], # Array pour cluster_bomb
                "status_code": int,
                "response_length": int,
                "response_time_ms": int,
                "grep_matches": [str],
                "grep_extracts": {str: str},
                "is_anomaly": bool,
                "error": str | None,
                "request_id": str       # Pour voir le détail
            }
        ],
        "statistics": {
            "total_requests": int,
            "completed": int,
            "errors": int,
            "by_status_code": {int: int},
            "avg_response_time_ms": float,
            "avg_response_length": float,
            "length_std_dev": float     # Pour détecter anomalies
        }
    }
```

#### `intruder.pause(attack_id)`
```python
"""Met en pause une attaque."""

Returns:
    {"success": bool}
```

#### `intruder.resume(attack_id)`
```python
"""Reprend une attaque en pause."""

Returns:
    {"success": bool}
```

#### `intruder.stop(attack_id)`
```python
"""Arrête définitivement une attaque."""

Returns:
    {"success": bool, "requests_completed": int}
```

---

### 3.4 SCANNER (Pro Only)

#### `scanner.crawl(target, config=None)`
```python
"""Lance un crawl."""

Parameters:
    target: str | [str]               # URL(s) de départ
    config: {
        "max_crawl_depth": int,
        "max_link_depth": int,
        "crawl_strategy": str,        # "fastest" | "more_complete" | "most_complete"
        "crawl_limits": {
            "max_unique_locations": int,
            "max_requests": int,
            "max_time_minutes": int
        },
        "login_credentials": {
            "username": str,
            "password": str
        },
        "recorded_login": str,        # Sequence enregistrée
        "scope": {
            "include": [str],         # Regex patterns
            "exclude": [str]
        }
    }
    
Returns:
    {"scan_id": str, "status": str}
```

#### `scanner.audit(target_or_request, config=None)`
```python
"""Lance un audit (scan de vulnérabilités)."""

Parameters:
    # Option 1: Sur une URL
    target: str | [str]
    
    # Option 2: Sur une requête spécifique
    request_id: str
    
    config: {
        "audit_optimization": str,    # "fast" | "normal" | "thorough"
        
        "insertion_points": {
            "url_params": bool,
            "body_params": bool,
            "cookies": bool,
            "headers": bool,
            "entire_body": bool,
            "param_name": bool,
            "amf": bool,
            "json": bool,
            "xml": bool
        },
        
        "audit_checks": {
            "sql_injection": bool,
            "xss": bool,
            "xxe": bool,
            "ssrf": bool,
            "path_traversal": bool,
            "os_command": bool,
            "ssti": bool,
            "header_injection": bool,
            "open_redirect": bool,
            "deserialization": bool,
            "file_upload": bool,
            "http_smuggling": bool,
            "web_cache_deception": bool,
            "prototype_pollution": bool
        },
        
        "handling": {
            "follow_redirects": bool,
            "consolidate_issues": bool
        }
    }
    
Returns:
    {"scan_id": str, "status": str}
```

#### `scanner.crawl_and_audit(target, config=None)`
```python
"""Lance crawl + audit combinés."""

# Combine les configs de crawl et audit
```

#### `scanner.status(scan_id)`
```python
"""Statut d'un scan."""

Returns:
    {
        "scan_id": str,
        "status": str,                # "crawling" | "auditing" | "paused" | "completed" | "failed"
        "crawl_progress": {
            "requests_made": int,
            "unique_locations": int,
            "forms_discovered": int
        },
        "audit_progress": {
            "requests_made": int,
            "items_completed": int,
            "items_total": int,
            "percentage": float
        },
        "issues_found": {
            "high": int,
            "medium": int,
            "low": int,
            "info": int
        },
        "elapsed_seconds": int
    }
```

#### `scanner.issues(scan_id=None, filters=None)`
```python
"""Récupère les issues trouvées."""

Parameters:
    scan_id: str = None               # Si None, toutes les issues du projet
    filters: {
        "severity": str,              # "high" | "medium" | "low" | "info"
        "confidence": str,            # "certain" | "firm" | "tentative"
        "type": str,                  # Type d'issue
        "host": str,
        "path": str
    }
    
Returns:
    {
        "issues": [
            {
                "id": str,
                "type": str,
                "name": str,
                "severity": str,
                "confidence": str,
                "url": str,
                "path": str,
                "host": str,
                "detail": str,            # Description HTML
                "background": str,        # Background de la vuln
                "remediation": str,
                "remediation_background": str,
                "references": [str],
                "evidence": {
                    "request": str,
                    "response": str,
                    "highlight_markers": [
                        {"start": int, "end": int}
                    ]
                },
                "request_id": str
            }
        ]
    }
```

#### `scanner.pause(scan_id)`
#### `scanner.resume(scan_id)`
#### `scanner.stop(scan_id)`

#### `scanner.get_issue_definitions()`
```python
"""Liste tous les types d'issues que Burp peut détecter."""

Returns:
    {
        "definitions": [
            {
                "type_index": int,
                "name": str,
                "severity": str,
                "description": str,
                "remediation": str,
                "references": [str],
                "vulnerability_classifications": [str]
            }
        ]
    }
```

---

### 3.5 SEQUENCER

#### `sequencer.start_live_capture(request_id, token_config)`
```python
"""Démarre une capture live de tokens."""

Parameters:
    request_id: str                   # Requête qui génère le token
    token_config: {
        "location": str,              # "cookie" | "header" | "body"
        "name": str,                  # Nom du cookie/header
        "start_regex": str,           # Si body: délimiteur début
        "end_regex": str              # Si body: délimiteur fin
    }
    sample_count: int = 200           # Minimum recommandé: 100
    
Returns:
    {"capture_id": str, "status": str}
```

#### `sequencer.capture_status(capture_id)`
```python
"""Statut de la capture."""

Returns:
    {
        "status": str,                # "capturing" | "completed" | "failed"
        "samples_collected": int,
        "samples_target": int
    }
```

#### `sequencer.analyze(capture_id)`
```python
"""Lance l'analyse sur les tokens capturés."""

Returns:
    {"analysis_id": str}
```

#### `sequencer.analyze_manual(tokens)`
```python
"""Analyse une liste de tokens fournie manuellement."""

Parameters:
    tokens: [str]
    
Returns:
    {"analysis_id": str}
```

#### `sequencer.results(analysis_id)`
```python
"""Résultats de l'analyse Sequencer."""

Returns:
    {
        "overall_result": str,        # "excellent" | "reasonable" | "poor" | "failed"
        "effective_entropy_bits": float,
        "reliability_percentage": float,
        
        "character_level_analysis": {
            "character_set": str,
            "character_set_size": int,
            "characters_analyzed": int,
            "significant_characters": int,
            "position_analysis": [
                {
                    "position": int,
                    "entropy_bits": float,
                    "is_significant": bool
                }
            ]
        },
        
        "bit_level_analysis": {
            "bits_analyzed": int,
            "significant_bits": int,
            "bit_analysis": [
                {
                    "bit_position": int,
                    "entropy": float,
                    "is_significant": bool
                }
            ]
        },
        
        "fips_tests": {
            "monobit": {"passed": bool, "value": float},
            "poker": {"passed": bool, "value": float},
            "runs": {"passed": bool, "value": float},
            "long_runs": {"passed": bool, "value": float},
            "overall_passed": bool
        },
        
        "correlation_analysis": {
            "same_position": float,
            "different_position": float
        },
        
        "samples_analyzed": int,
        "recommendation": str
    }
```

---

### 3.6 DECODER

#### `decoder.encode(data, encoding)`
```python
"""Encode des données."""

Parameters:
    data: str
    encoding: str                     # Voir liste ci-dessous
    
Encodings supportés:
    - "url"                          # URL encode (standard)
    - "url_all"                      # URL encode tous les caractères
    - "base64"
    - "base64_url"                   # Base64 URL-safe
    - "html"                         # HTML entities
    - "html_all"                     # HTML encode tous les caractères
    - "hex"
    - "ascii_hex"
    - "octal"
    - "unicode_escape"               # \uXXXX
    - "gzip"                         # Retourne base64 du gzip
    - "deflate"
    
Returns:
    {"result": str, "encoding": str}
```

#### `decoder.decode(data, encoding=None)`
```python
"""Décode des données."""

Parameters:
    data: str
    encoding: str = None              # Si None, auto-detect
    
Returns:
    {
        "result": str,
        "encoding_detected": str,
        "success": bool
    }
```

#### `decoder.smart_decode(data, max_iterations=10)`
```python
"""Décodage automatique multi-couches."""

Parameters:
    data: str
    max_iterations: int = 10
    
Returns:
    {
        "final_result": str,
        "iterations": int,
        "steps": [
            {
                "input": str,
                "encoding_detected": str,
                "output": str
            }
        ]
    }
```

#### `decoder.hash(data, algorithm)`
```python
"""Hash des données."""

Parameters:
    data: str
    algorithm: str                    # "md5" | "sha1" | "sha256" | "sha384" | "sha512"
    
Returns:
    {"hash": str, "algorithm": str}
```

#### `decoder.hash_all(data)`
```python
"""Calcule tous les hashes."""

Returns:
    {
        "md5": str,
        "sha1": str,
        "sha256": str,
        "sha384": str,
        "sha512": str
    }
```

---

### 3.7 COMPARER

#### `comparer.diff(item1, item2, options=None)`
```python
"""Compare deux items."""

Parameters:
    # Sources (plusieurs options)
    request_id_1: str                 # ID d'une requête
    request_id_2: str
    
    # OU textes bruts
    text1: str
    text2: str
    
    options: {
        "compare": str,               # "request" | "response" | "both"
        "mode": str,                  # "words" | "bytes"
        "ignore_whitespace": bool,
        "ignore_case": bool
    }
    
Returns:
    {
        "similarity_percentage": float,
        "comparison_mode": str,
        
        "summary": {
            "total_items": int,       # Mots ou bytes selon mode
            "matching": int,
            "added": int,
            "removed": int,
            "modified": int
        },
        
        "differences": [
            {
                "type": str,          # "added" | "removed" | "modified"
                "position": int,
                "item1": str,
                "item2": str,
                "context_before": str,
                "context_after": str
            }
        ],
        
        "highlighted_text1": str,     # Avec markers pour UI
        "highlighted_text2": str
    }
```

#### `comparer.diff_responses(request_ids)`
```python
"""Compare les réponses de plusieurs requêtes."""

Parameters:
    request_ids: [str]                # 2 ou plus
    
Returns:
    {
        "comparisons": [
            {
                "pair": [str, str],   # IDs comparés
                "similarity": float,
                "key_differences": [str]
            }
        ],
        "common_content": str,
        "unique_per_request": {
            str: [str]                # request_id: [unique parts]
        }
    }
```

---

### 3.8 COLLABORATOR (Pro Only)

#### `collaborator.generate_payload()`
```python
"""Génère un payload Collaborator."""

Returns:
    {
        "payload": str,               # xxxxx.oastify.com
        "interaction_id": str,
        "polling_location": str
    }
```

#### `collaborator.generate_payloads(count)`
```python
"""Génère plusieurs payloads."""

Parameters:
    count: int
    
Returns:
    {
        "payloads": [
            {
                "payload": str,
                "interaction_id": str
            }
        ]
    }
```

#### `collaborator.poll(interaction_id=None)`
```python
"""Poll pour les interactions."""

Parameters:
    interaction_id: str = None        # Si None, poll toutes
    
Returns:
    {
        "interactions": [
            {
                "interaction_id": str,
                "type": str,          # "dns" | "http" | "smtp"
                "timestamp": str,
                "client_ip": str,
                "protocol": str,
                
                # Pour DNS:
                "query_type": str,
                "query_domain": str,
                
                # Pour HTTP:
                "request": str,
                "response": str,
                
                # Pour SMTP:
                "conversation": str
            }
        ]
    }
```

#### `collaborator.poll_until(interaction_id, timeout_seconds=30)`
```python
"""Poll jusqu'à interaction ou timeout."""

Returns:
    {
        "found": bool,
        "interaction": {...} | None,
        "elapsed_seconds": int
    }
```

---

### 3.9 TARGET

#### `target.get_sitemap(root_url=None)`
```python
"""Récupère le sitemap."""

Parameters:
    root_url: str = None              # Filtrer par URL racine
    include_responses: bool = False
    
Returns:
    {
        "hosts": [
            {
                "host": str,
                "port": int,
                "protocol": str,
                "in_scope": bool,
                "items": [
                    {
                        "url": str,
                        "method": str,
                        "status_code": int,
                        "mime_type": str,
                        "has_response": bool,
                        "response_length": int,
                        "issue_count": int,
                        "request_id": str
                    }
                ]
            }
        ]
    }
```

#### `target.get_scope()`
```python
"""Récupère la configuration du scope."""

Returns:
    {
        "include": [
            {
                "enabled": bool,
                "protocol": str,      # "any" | "http" | "https"
                "host": str,          # Regex
                "port": str,          # "any" ou numéro
                "file": str           # Regex path
            }
        ],
        "exclude": [...]              # Même structure
    }
```

#### `target.set_scope(config)`
```python
"""Configure le scope."""

Parameters:
    config: {
        "include": [...],
        "exclude": [...]
    }
    
Returns:
    {"success": bool}
```

#### `target.add_to_scope(url)`
```python
"""Ajoute une URL au scope (shortcut)."""

Parameters:
    url: str
    
Returns:
    {"success": bool}
```

#### `target.is_in_scope(url)`
```python
"""Vérifie si une URL est in-scope."""

Returns:
    {"in_scope": bool}
```

#### `target.get_issues(host=None)`
```python
"""Issues du sitemap (passive)."""

# Same as scanner.issues() mais pour issues passives
```

---

### 3.10 LOGGER

#### `logger.query(filters)`
```python
"""Query avancée sur le logger."""

Parameters:
    filters: {
        "tools": [str],               # ["proxy", "repeater", "intruder", "scanner", "extensions"]
        "hosts": [str],
        "methods": [str],
        "status_codes": [int],
        "mime_types": [str],
        "extensions": [str],
        "search_request": str,
        "search_response": str,
        "is_regex": bool,
        "from_timestamp": str,
        "to_timestamp": str,
        "in_scope_only": bool,
        "has_params": bool,
        "has_response": bool
    }
    sort_by: str = "timestamp"        # "timestamp" | "host" | "method" | "status" | "length"
    sort_order: str = "desc"
    limit: int = 100
    offset: int = 0
    
Returns:
    {
        "total": int,
        "entries": [
            {
                "id": str,
                "tool": str,
                "timestamp": str,
                "method": str,
                "url": str,
                "host": str,
                "status_code": int,
                "response_length": int,
                "mime_type": str,
                "comment": str,
                "highlight": str
            }
        ]
    }
```

#### `logger.annotate(request_id, comment=None, highlight=None)`
```python
"""Ajoute une annotation."""

Parameters:
    request_id: str
    comment: str = None
    highlight: str = None             # "red" | "orange" | "yellow" | "green" | "cyan" | "blue" | "pink" | "magenta" | "gray" | "none"
    
Returns:
    {"success": bool}
```

#### `logger.export(request_ids, format)`
```python
"""Exporte des requêtes."""

Parameters:
    request_ids: [str]
    format: str                       # "xml" | "json" | "har" | "curl"
    
Returns:
    {"data": str}                     # Contenu exporté
```

---

### 3.11 ORGANIZER

#### `organizer.add(request_id, collection=None)`
```python
"""Ajoute une requête à l'Organizer."""

Parameters:
    request_id: str
    collection: str = None            # Nom de la collection
    
Returns:
    {"organizer_id": str}
```

#### `organizer.list(collection=None)`
```python
"""Liste les items de l'Organizer."""

Returns:
    {
        "items": [
            {
                "id": str,
                "request_id": str,
                "url": str,
                "method": str,
                "collection": str,
                "notes": str,
                "timestamp_added": str
            }
        ]
    }
```

#### `organizer.annotate(organizer_id, notes)`
```python
"""Ajoute des notes à un item."""

Returns:
    {"success": bool}
```

#### `organizer.get_collections()`
```python
"""Liste les collections."""

Returns:
    {"collections": [str]}
```

#### `organizer.create_collection(name)`
```python
"""Crée une collection."""

Returns:
    {"success": bool}
```

---

### 3.12 ENGAGEMENT TOOLS (Pro Only)

#### `engagement.analyze_target(url)`
```python
"""Lance le Target Analyzer."""

Parameters:
    url: str
    
Returns:
    {
        "summary": {
            "total_links": int,
            "total_forms": int,
            "total_params": int,
            "static_urls": int,
            "dynamic_urls": int
        },
        "parameters": [
            {
                "name": str,
                "type": str,
                "url_count": int,
                "values_seen": [str]
            }
        ],
        "forms": [
            {
                "action": str,
                "method": str,
                "fields": [str]
            }
        ]
    }
```

#### `engagement.discover_content(url, wordlist=None)`
```python
"""Lance Content Discovery."""

Parameters:
    url: str
    wordlist: str = None              # Chemin ou "default"
    config: {
        "extensions": [str],
        "depth": int,
        "threads": int
    }
    
Returns:
    {"task_id": str}
```

#### `engagement.content_discovery_results(task_id)`
```python
"""Résultats du Content Discovery."""

Returns:
    {
        "status": str,
        "discovered": [
            {
                "url": str,
                "status_code": int,
                "response_length": int,
                "content_type": str
            }
        ]
    }
```

#### `engagement.generate_csrf_poc(request_id)`
```python
"""Génère un PoC CSRF."""

Parameters:
    request_id: str
    
Returns:
    {
        "html": str,                  # HTML du PoC
        "auto_submit": bool
    }
```

---

### 3.13 SEARCH

#### `search.find(query, scope=None)`
```python
"""Recherche dans tout le projet."""

Parameters:
    query: str
    scope: {
        "tools": [str],               # ["proxy", "repeater", "intruder", "sitemap", "scanner"]
        "search_in": [str],           # ["request", "response", "comments"]
        "is_regex": bool,
        "case_sensitive": bool
    }
    limit: int = 100
    
Returns:
    {
        "total_matches": int,
        "results": [
            {
                "tool": str,
                "request_id": str,
                "url": str,
                "match_location": str,  # "request_header" | "request_body" | "response_header" | "response_body" | "comment"
                "match_context": str,   # Texte autour du match
                "match_position": {"start": int, "end": int}
            }
        ]
    }
```

---

### 3.14 CLICKBANDIT

#### `clickbandit.generate(url, config=None)`
```python
"""Génère un PoC Clickjacking."""

Parameters:
    url: str
    config: {
        "transparency": int,          # 0-100
        "frame_position": {"x": int, "y": int},
        "click_sequence": [{"x": int, "y": int, "delay_ms": int}]
    }
    
Returns:
    {
        "html": str,                  # HTML du PoC
        "interactive": bool
    }
```

---

### 3.15 INSPECTOR

#### `inspector.parse_request(raw_request)`
```python
"""Parse une requête en composants."""

Parameters:
    raw_request: str
    
Returns:
    {
        "method": str,
        "path": str,
        "http_version": str,
        "headers": [{"name": str, "value": str}],
        "cookies": [{"name": str, "value": str}],
        "body": str,
        "content_type": str,
        
        "parameters": {
            "query": [{"name": str, "value": str}],
            "body": [{"name": str, "value": str}],
            "json": dict | None,
            "xml": dict | None
        },
        
        "attributes": {
            "has_body": bool,
            "is_json": bool,
            "is_xml": bool,
            "is_multipart": bool
        }
    }
```

#### `inspector.parse_response(raw_response)`
```python
"""Parse une réponse en composants."""

Returns:
    {
        "status_code": int,
        "status_text": str,
        "http_version": str,
        "headers": [{"name": str, "value": str}],
        "cookies_set": [{"name": str, "value": str, "attributes": dict}],
        "body": str,
        "content_type": str,
        
        "attributes": {
            "is_json": bool,
            "is_html": bool,
            "is_xml": bool,
            "is_binary": bool,
            "encoding": str,
            "length": int
        }
    }
```

#### `inspector.build_request(components)`
```python
"""Construit une requête à partir de composants."""

Parameters:
    components: {
        "method": str,
        "path": str,
        "host": str,
        "headers": [{"name": str, "value": str}],
        "body": str
    }
    
Returns:
    {"raw_request": str}
```

---

### 3.16 EXTENSIONS

#### `extensions.list()`
```python
"""Liste les extensions installées."""

Returns:
    {
        "extensions": [
            {
                "name": str,
                "enabled": bool,
                "type": str,          # "java" | "python" | "ruby"
                "filename": str,
                "errors": [str]
            }
        ]
    }
```

#### `extensions.enable(name)`
#### `extensions.disable(name)`
#### `extensions.reload(name)`

---

### 3.17 PROJECT & CONFIG

#### `config.get_project()`
```python
"""Récupère la config projet."""

Returns:
    {
        "project_name": str,
        "project_file": str,
        "config": dict                # JSON config complète
    }
```

#### `config.get_user()`
```python
"""Récupère la config utilisateur."""

Returns:
    {"config": dict}
```

#### `config.export_project()`
```python
"""Exporte la config projet en JSON."""

Returns:
    {"json": str}
```

#### `config.import_project(json_config)`
```python
"""Importe une config projet."""

Parameters:
    json_config: str
    
Returns:
    {"success": bool}
```

---

### 3.18 DASHBOARD

#### `dashboard.get_tasks()`
```python
"""Liste les tâches actives."""

Returns:
    {
        "tasks": [
            {
                "id": str,
                "type": str,          # "scan" | "live_audit" | "live_passive"
                "status": str,
                "target": str,
                "progress": float,
                "issues_found": int,
                "start_time": str
            }
        ]
    }
```

#### `dashboard.get_issues_summary()`
```python
"""Résumé des issues du projet."""

Returns:
    {
        "total": int,
        "by_severity": {
            "high": int,
            "medium": int,
            "low": int,
            "info": int
        },
        "by_confidence": {
            "certain": int,
            "firm": int,
            "tentative": int
        },
        "recent": [
            {
                "name": str,
                "url": str,
                "severity": str,
                "timestamp": str
            }
        ]
    }
```

---

## 4. Utility Functions

#### `utils.generate_random_string(length, charset=None)`
```python
"""Génère une string aléatoire."""

Parameters:
    length: int
    charset: str = None               # "alpha" | "numeric" | "alphanumeric" | "hex" | custom string
    
Returns:
    {"value": str}
```

#### `utils.timestamp()`
```python
"""Timestamp actuel."""

Returns:
    {"timestamp": str, "unix": int}
```

---

## 5. Notes d'Implémentation

### 5.1 Structure du Wrapper

```python
# burp_client.py

import httpx
from typing import Optional, List, Dict, Any

class BurpClient:
    def __init__(self, base_url: str = "http://127.0.0.1:9876"):
        self.base_url = base_url
        self.client = httpx.Client(timeout=30.0)
    
    # Sous-modules
    @property
    def proxy(self) -> ProxyTools:
        return ProxyTools(self)
    
    @property
    def repeater(self) -> RepeaterTools:
        return RepeaterTools(self)
    
    # etc.
    
    def _call(self, method: str, params: dict = None) -> dict:
        """Appel à l'API MCP."""
        # Implémentation SSE ou REST selon ce que le MCP expose
        pass


class ProxyTools:
    def __init__(self, client: BurpClient):
        self._client = client
    
    def get_history(self, limit: int = 100, **filters) -> dict:
        return self._client._call("proxy.getHistory", {"limit": limit, **filters})
    
    # etc.
```

### 5.2 Utilisation par l'Agent

```python
# Dans le code de l'agent
from burp_client import BurpClient

burp = BurpClient()

# Récupérer l'historique
history = burp.proxy.get_history(limit=50, filter_host="target.com")

# Envoyer via Repeater
response = burp.repeater.send(request_id="xxx")

# Fuzz un paramètre
results = burp.intruder.quick_fuzz(
    request_id="xxx",
    param_name="username",
    payloads=["admin", "test", "' OR 1=1--"]
)

# Générer un payload Collaborator
collab = burp.collaborator.generate_payload()
print(f"Inject this: {collab['payload']}")

# Poll pour interactions
interactions = burp.collaborator.poll_until(collab['interaction_id'], timeout_seconds=30)
```

### 5.3 Optimisation Tokens

Pour minimiser les tokens:
1. **Responses concises**: Ne retourne que les champs demandés
2. **Pagination par défaut**: Limites raisonnables
3. **Pas de verbose logging**: Juste les données
4. **Format compact**: JSON minifié si possible

---

## 6. Mapping avec MCP Existant

Le MCP Burp officiel expose déjà certains tools. Voici le mapping:

| Notre Tool | MCP Existant | À Implémenter |
|------------|--------------|---------------|
| proxy.get_history | ✅ Existe | Non |
| proxy.intercept_* | ✅ Existe | Non |
| repeater.send | ✅ Existe | Non |
| repeater.create_tab | ✅ Existe | Non |
| intruder.* | ❌ Partiel | Oui (complet) |
| scanner.* | ❌ Non | Oui |
| sequencer.* | ❌ Non | Oui |
| decoder.* | ✅ Partiel (URL, Base64) | Compléter |
| comparer.* | ❌ Non | Oui |
| collaborator.* | ✅ Existe | Non |
| target.sitemap | ❌ Non | Oui |
| target.scope | ✅ Existe | Non |
| logger.* | ❌ Non | Oui |
| search.* | ❌ Non | Oui |
| engagement.* | ❌ Non | Oui |
| config.* | ✅ Existe | Non |

**Conclusion**: Il faut étendre le MCP existant avec ~15 tools supplémentaires, ou créer un wrapper qui combine MCP + appels directs à la Montoya API via une extension custom.

---

## 7. Prochaines Étapes

1. **Tester le MCP existant** pour confirmer ce qui marche
2. **Choisir l'approche**:
   - Fork MCP + ajouter tools en Kotlin
   - Wrapper Python qui utilise MCP + extension custom pour le reste
3. **Implémenter** par priorité (P1 d'abord)
4. **Tester** avec Claude Code sur un target de test

---

*Specs complètes par ENI pour LO* ♡