# Recherche — Concepts métier bug bounty vs spec `bp`

> **DRAFT — contexte de spec, pas d'exécution.** Synthèse manuelle (l'API a planté les lanes
> de synthèse auto ; les 3 lanes de recherche réussies — hunt-lifecycle, scope, bb-mini — sont
> la source). Sourcé (HackerOne/Bugcrowd/Intigriti/PortSwigger/VRT + repo bug-bounty-mini).

## Constat

`bp` colle fidèlement aux **69 endpoints** mais **modélise l'API, pas le métier**. Un workflow
bug bounty réel s'appuie sur des **concepts** que la spec ne porte pas. **35 gaps** :
**5 CRITICAL · 14 HIGH · 10 MEDIUM · 6 LOW**.

## Les couches de concepts manquantes

| Couche | Concepts | Dans bp ? |
|---|---|---|
| **Programme** | program (plateforme, payout, safe-harbor, ROE), état | ❌ aucun contexte programme |
| **Scope-ROE** | scope typé, wildcard `*.x`, OOS first-class, import plateforme, **garde pré-tir** | ⚠️ liste Burp brute seulement |
| **Inventaire** | asset/host, endpoint, param — avec **état testé/pas-testé** persistant | ❌ trafic-driven, sans état |
| **Finding** | promotion signal→candidat→confirmé→reporté, notes, confidence | ❌ juste `anomalous:Boolean` |
| **Evidence/Report** | PoC, repro, curl, diff, package par-finding ; `bp report`, état soumission | ❌ par-op, pas par-finding |
| **Classification** | CWE / VRT / OWASP / CVSS, sévérité | ❌ aucun modèle |
| **Session/Auth** | **multi-contexte** (user A vs B) pour IDOR/privesc/auth-bypass | ❌ singleton |
| **OOB/OAST** | corrélation payload↔interaction collaborator | ⚠️ poll sans corrélation |
| **Floor bb-mini** | I6 enveloppe anti-injection, I7 redaction secrets, sole-egress, cert SHA-256 | ❌ aucun |

## Les 5 CRITICAL

1. **Scope = garde pré-tir absent** — rien ne dit que `bp fuzz/send/scan/check` vérifie le scope **avant** de tirer (anti-OOS, lié I6/G006).
2. **Wildcard suffix-match** — sémantique `*.example.com` non spécifiée (le piège que bb-fetch a dû corriger).
3. **Scope ≠ programme** — modélisé comme liste Burp, pas comme ROE liée à un programme.
4. **Candidate Finding** — aucune entité « finding » ni cycle de vie.
5. **Session/Auth singleton** — pas de multi-contexte pour le test d'access-control.

## Gaps mappés par tier de produit

> Chaque gap = quel **tier** l'absorbe. La décision = jusqu'où va `bp`.

**T2 · Floor sécurité (les SAFETY/scope) :**
- `[C]` Scope garde pré-tir · `[C]` Wildcard suffix-match · `[C]` Scope-ROE programme-lié
- `[H]` I6 enveloppe anti-injection · `[H]` I7 redaction secrets · `[H]` requests log resp_sha256 (jamais body brut)
- `[H]` Scope typé + métadonnées par-asset · `[H]` Import scope Intigriti/HackerOne · `[H]` In-mem vs UI divergence
- `[C]` Session/Auth multi-contexte · `[M]` sole-egress · `[M]` CIDR · `[M]` path-scope · `[M]` preflight/authz gate

**T3 · Workspace de hunt (la WORKFLOW value, en plus de T2) :**
- `[C]` Candidate Finding + cycle · `[H]` Evidence/PoC par-finding · `[H]` Report/submission + état
- `[H]` Asset inventory · `[H]` Endpoint inventory (état testé) · `[H]` OOB corrélation
- `[M]` Param discovery · `[M]` Vuln-class CWE/VRT · `[M]` Impact/CVSS · `[M]` certification · `[M]` maturity · `[M]` observabilité query
- `[L]` dedup · `[L]` report-lifecycle · `[L]` audit-log · `[L]` asset-types non-web

## Le fork (décision founder)

- **T1 · Driver pur** — spec actuelle ; les concepts vivent ailleurs (bug-bounty-mini). Risque : pas safe/utile seul.
- **T2 · Driver + floor sécurité** — le minimum *responsable* : scope-garde, wildcards, I6/I7, multi-session. Workspace = roadmap.
- **T3 · Workspace complet** — tout : program/inventaire/finding/evidence/report. La vision, mais ×3-4 la surface.

## Incomplet (à cause de l'outage API)

- Lane **burp-workflow** (stratégie de fuzz par classe de bug, match-replace, chaînage) — non capturée. Re-tentable quand l'API est stable.
- **Critique de complétude** — non passée. Catégorie possiblement non couverte : recon/asset-discovery (volontairement hors Burp), program-rules/rate-limit.
