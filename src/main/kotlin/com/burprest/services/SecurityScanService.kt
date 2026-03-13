package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.db.HistoryDao
import com.burprest.db.HistoryFilter
import com.burprest.models.*
import java.net.URI

class SecurityScanService(
    private val api: MontoyaApi,
    private val sessionService: SessionService,
    private val historyDao: HistoryDao?,
) {

    fun authBypass(request: AuthBypassRequest): AuthBypassResponse {
        require(request.endpoints.isNotEmpty()) { "endpoints list must not be empty" }

        val results = request.endpoints.map { endpoint ->
            val url = request.baseUrl.trimEnd('/') + endpoint

            // Probe 1: with full session auth
            val withAuth = probeWithAuth(url, request.method)

            // Probe 2: no auth at all (bypass SessionService entirely)
            val withoutAuth = probeNoAuth(url, request.method)

            // Probe 3: cookies only (no extra session headers like x-group-id)
            val cookieOnly = probeCookieOnly(url, request.method)

            val vulnerable = withoutAuth.status in 200..299 && withoutAuth.length > 0

            AuthBypassEndpointResult(
                endpoint = endpoint,
                withAuth = withAuth,
                withoutAuth = withoutAuth,
                cookieOnly = cookieOnly,
                vulnerable = vulnerable,
            )
        }

        return AuthBypassResponse(
            results = results,
            totalScanned = results.size,
            vulnerableCount = results.count { it.vulnerable },
        )
    }

    fun idor(request: IdorRequest): IdorResponse {
        require(request.ownValues.isNotEmpty()) { "ownValues must not be empty" }
        require(request.targetValues.isNotEmpty()) { "targetValues must not be empty" }

        // Baseline: use first own value
        val baselineUrl = substituteParam(request.endpoint, request.param, request.ownValues.first())
        val baselineResp = sessionService.send(AuthenticatedRequest(
            method = request.method, url = baselineUrl, body = request.body,
            extraHeaders = request.extraHeaders,
        ))

        val baseline = IdorProbeResult(
            value = request.ownValues.first(),
            status = baselineResp.statusCode,
            length = baselineResp.body?.length ?: 0,
            bodyPreview = baselineResp.body?.take(200),
            sameAsBaseline = true,
            vulnerable = false,
        )

        // Test each target value
        val results = request.targetValues.map { targetValue ->
            val url = substituteParam(request.endpoint, request.param, targetValue)
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = url, body = request.body,
                extraHeaders = request.extraHeaders,
            ))

            val length = resp.body?.length ?: 0
            val sameAsBaseline = resp.statusCode == baseline.status &&
                kotlin.math.abs(length - baseline.length) < (baseline.length * 0.05).toInt().coerceAtLeast(10)

            val vulnerable = !sameAsBaseline && resp.statusCode in 200..299 && length > 0

            IdorProbeResult(
                value = targetValue,
                status = resp.statusCode,
                length = length,
                bodyPreview = resp.body?.take(200),
                sameAsBaseline = sameAsBaseline,
                vulnerable = vulnerable,
            )
        }

        return IdorResponse(
            baseline = baseline,
            results = results,
            vulnerableCount = results.count { it.vulnerable },
        )
    }

    fun headersBypass(request: HeadersBypassRequest): HeadersBypassResponse {
        // Baseline request
        val baselineResp = sessionService.send(AuthenticatedRequest(
            method = request.method, url = request.url, body = request.body,
        ))
        val baseline = AuthBypassProbeResult(
            status = baselineResp.statusCode,
            length = baselineResp.body?.length ?: 0,
            durationMs = baselineResp.durationMs,
        )

        val results = BYPASS_HEADERS.map { (header, value) ->
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = request.url, body = request.body,
                extraHeaders = mapOf(header to value),
            ))
            val status = resp.statusCode
            val length = resp.body?.length ?: 0
            val anomalous = status != baseline.status ||
                kotlin.math.abs(length - baseline.length) > (baseline.length * 0.1).toInt().coerceAtLeast(50)

            HeadersBypassResult(
                header = header, value = value,
                status = status, length = length, anomalous = anomalous,
            )
        }

        return HeadersBypassResponse(
            baseline = baseline,
            results = results,
            anomalousCount = results.count { it.anomalous },
        )
    }

    fun cors(request: CorsRequest): CorsResponse {
        val host = try { URI(request.url).host ?: "unknown" } catch (_: Exception) { "unknown" }

        val origins = listOf(
            "https://evil.com",
            "null",
            "https://$host.evil.com",
            "https://evil.$host",
            "https://${host}evil.com",
            "https://evil.com%40$host",
            "https://$host%60.evil.com",
            "https://sub.$host",
        )

        val results = origins.map { origin ->
            val resp = sessionService.send(AuthenticatedRequest(
                method = request.method, url = request.url,
                extraHeaders = mapOf("Origin" to origin),
            ))
            val acao = resp.headers.find { it.name.equals("Access-Control-Allow-Origin", ignoreCase = true) }?.value
            val acac = resp.headers.find { it.name.equals("Access-Control-Allow-Credentials", ignoreCase = true) }?.value

            // Vulnerable if origin is reflected AND credentials allowed
            val vulnerable = acao != null && acao != "*" && acac?.equals("true", ignoreCase = true) == true

            CorsProbeResult(origin = origin, acao = acao, acac = acac, vulnerable = vulnerable)
        }

        return CorsResponse(results = results, vulnerableCount = results.count { it.vulnerable })
    }

    fun scanEndpoints(request: EndpointsScanRequest): EndpointsScanResponse {
        val dao = historyDao ?: throw IllegalStateException("Database required for endpoint scanning")
        val start = System.currentTimeMillis()

        val entries = dao.search(HistoryFilter(host = request.host, pageSize = request.limit))
        val uniqueEndpoints = entries.map { it.method to it.url }.distinct()
        val findings = mutableListOf<EndpointFinding>()

        if ("auth-bypass" in request.tests) {
            // Group URLs, test auth bypass
            val urls = uniqueEndpoints.map { it.second }.distinct()
            for (url in urls) {
                val withAuth = probeWithAuth(url, "GET")
                val withoutAuth = probeNoAuth(url, "GET")
                if (withoutAuth.status in 200..299 && withoutAuth.length > 0) {
                    findings.add(EndpointFinding(
                        endpoint = url, method = "GET", test = "auth-bypass",
                        detail = "Accessible without auth: ${withoutAuth.status} (${withoutAuth.length} bytes)",
                        severity = "high",
                    ))
                }
            }
        }

        if ("method-switch" in request.tests) {
            val altMethods = listOf("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
            val urlsByMethod = uniqueEndpoints.groupBy({ it.second }, { it.first })

            for ((url, knownMethods) in urlsByMethod) {
                for (method in altMethods) {
                    if (method in knownMethods) continue
                    val resp = try {
                        sessionService.send(AuthenticatedRequest(method = method, url = url))
                    } catch (_: Exception) { continue }
                    if (resp.statusCode in 200..299 && resp.body?.let { it.length > 0 && !it.trimStart().startsWith("<!") } == true) {
                        findings.add(EndpointFinding(
                            endpoint = url, method = method, test = "method-switch",
                            detail = "Method $method returns ${resp.statusCode} (${resp.body?.length ?: 0} bytes) — not tested before",
                            severity = "medium",
                        ))
                    }
                }
            }
        }

        return EndpointsScanResponse(
            scanned = uniqueEndpoints.size,
            findings = findings,
            durationMs = System.currentTimeMillis() - start,
        )
    }

    // --- Internal helpers ---

    private fun probeWithAuth(url: String, method: String): AuthBypassProbeResult {
        val start = System.currentTimeMillis()
        val resp = sessionService.send(AuthenticatedRequest(method = method, url = url))
        return AuthBypassProbeResult(
            status = resp.statusCode,
            length = resp.body?.length ?: 0,
            durationMs = System.currentTimeMillis() - start,
        )
    }

    /**
     * Send request with NO auth at all — bypasses SessionService entirely.
     * Not recorded in history (intentional: avoids polluting session history with unauth probes).
     */
    private fun probeNoAuth(url: String, method: String): AuthBypassProbeResult {
        return try {
            val start = System.currentTimeMillis()
            val req = HttpRequest.httpRequestFromUrl(url).withMethod(method)
            val httpResponse = api.http().sendRequest(req)
            val resp = httpResponse.response()
            val body = if (resp.body().length() > 0) resp.bodyToString() else ""
            // Filter out SPA HTML catch-all (returns 200 with HTML for any unknown route)
            val isSpaHtml = body.trimStart().startsWith("<!") && body.length > 50000
            AuthBypassProbeResult(
                status = if (isSpaHtml) 302 else resp.statusCode().toInt(), // Treat SPA HTML as redirect
                length = if (isSpaHtml) 0 else body.length,
                durationMs = System.currentTimeMillis() - start,
            )
        } catch (e: Exception) {
            AuthBypassProbeResult(status = 0, length = 0, durationMs = 0)
        }
    }

    private fun probeCookieOnly(url: String, method: String): AuthBypassProbeResult {
        return try {
            val start = System.currentTimeMillis()
            val session = sessionService.getSession()
            val cookieHeader = session.cookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
            var req = HttpRequest.httpRequestFromUrl(url).withMethod(method)
            if (cookieHeader.isNotEmpty()) {
                req = req.withAddedHeader("Cookie", cookieHeader)
            }
            val httpResponse = api.http().sendRequest(req)
            val resp = httpResponse.response()
            AuthBypassProbeResult(
                status = resp.statusCode().toInt(),
                length = if (resp.body().length() > 0) resp.bodyToString().length else 0,
                durationMs = System.currentTimeMillis() - start,
            )
        } catch (e: Exception) {
            AuthBypassProbeResult(status = 0, length = 0, durationMs = 0)
        }
    }

    private fun substituteParam(urlTemplate: String, param: String, value: String): String {
        // Template substitution: {param} -> value
        var url = urlTemplate.replace("{$param}", value)
        // Query parameter substitution: param=oldvalue -> param=value
        val queryParamRegex = Regex("([?&])${Regex.escape(param)}=([^&#]*)")
        url = queryParamRegex.replace(url) { match ->
            "${match.groupValues[1]}$param=$value"
        }
        return url
    }

    companion object {
        private val BYPASS_HEADERS = listOf(
            "X-Forwarded-For" to "127.0.0.1",
            "X-Forwarded-For" to "0.0.0.0",
            "X-Real-IP" to "127.0.0.1",
            "X-Original-URL" to "/admin",
            "X-Rewrite-URL" to "/admin",
            "X-Custom-IP-Authorization" to "127.0.0.1",
            "X-Forwarded-Host" to "127.0.0.1",
            "X-Remote-IP" to "127.0.0.1",
            "X-Remote-Addr" to "127.0.0.1",
            "X-ProxyUser-Ip" to "127.0.0.1",
            "X-Original-Remote-Addr" to "127.0.0.1",
            "Client-IP" to "127.0.0.1",
            "True-Client-IP" to "127.0.0.1",
            "X-Forwarded-Proto" to "https",
            "X-Forwarded-Port" to "443",
            "X-Host" to "127.0.0.1",
        )
    }
}
