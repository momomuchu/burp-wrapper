package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.models.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class IntruderService(private val api: MontoyaApi, private val repeaterService: RepeaterService) {

    private val attacks = ConcurrentHashMap<String, AttackState>()

    data class AttackState(
        val id: String,
        val config: CreateAttackRequest,
        var status: String = "created",
        var progress: Int = 0,
        var requestCount: Int = 0,
        var errorCount: Int = 0,
        val results: MutableList<AttackResultEntry> = mutableListOf(),
        var thread: Thread? = null,
    )

    fun createAttack(request: CreateAttackRequest): CreateAttackResponse {
        val id = UUID.randomUUID().toString().take(8)
        attacks[id] = AttackState(id = id, config = request)
        return CreateAttackResponse(attackId = id, status = "created")
    }

    fun startAttack(id: String): AttackStatusResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        attack.status = "running"

        // Execute attack in background thread
        attack.thread = Thread {
            try {
                executeAttack(attack)
            } catch (e: InterruptedException) {
                attack.status = "stopped"
            } catch (e: Exception) {
                attack.status = "error"
                attack.errorCount++
            }
        }.apply {
            isDaemon = true
            name = "intruder-attack-$id"
            start()
        }

        return attackStatus(id)
    }

    private fun executeAttack(attack: AttackState) {
        val config = attack.config
        val baseRequest = resolveBaseRequest(config.request, config.requestId)

        // Sniper mode: iterate through each position with each payload
        val payloadSets = config.payloads.values.flatten()
        val totalRequests = payloadSets.size
        var idx = 0

        for (payload in payloadSets) {
            if (attack.status == "stopped" || attack.status == "paused") {
                while (attack.status == "paused") {
                    Thread.sleep(500)
                }
                if (attack.status == "stopped") break
            }

            try {
                val modifiedRequest = substitutePayload(baseRequest, config.positions.firstOrNull()?.name ?: "FUZZ", payload)
                val sendReq = SendRequest(request = modifiedRequest)
                val resp = repeaterService.send(sendReq)

                val ct = resp.response.headers.find { it.name.equals("Content-Type", ignoreCase = true) }?.value
                attack.results.add(
                    AttackResultEntry(
                        index = idx,
                        payload = payload,
                        statusCode = resp.response.statusCode,
                        length = resp.response.body?.length ?: 0,
                        durationMs = resp.durationMs,
                        contentType = ct,
                        bodyPreview = resp.response.body?.take(200),
                    )
                )
                attack.requestCount++
            } catch (e: Exception) {
                attack.results.add(
                    AttackResultEntry(
                        index = idx,
                        payload = payload,
                        statusCode = 0,
                        length = 0,
                        durationMs = 0,
                        error = e.message,
                    )
                )
                attack.errorCount++
            }

            idx++
            attack.progress = ((idx.toDouble() / totalRequests) * 100).toInt()

            if (config.options.throttleMs > 0) {
                Thread.sleep(config.options.throttleMs)
            }
        }

        if (attack.status == "running") {
            attack.status = "completed"
            attack.progress = 100
        }
    }

    private fun resolveBaseRequest(request: HttpRequestData?, requestId: Int?): HttpRequestData {
        if (request != null) return request
        if (requestId != null) {
            val history = api.proxy().history()
            require(requestId in history.indices) { "Request ID $requestId not found in proxy history" }
            val req = history[requestId].finalRequest()
            return HttpRequestData(
                method = req.method(),
                url = req.url(),
                headers = req.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (req.body().length() > 0) req.bodyToString() else null,
            )
        }
        throw IllegalArgumentException("Either 'request' or 'requestId' required")
    }

    fun attackStatus(id: String): AttackStatusResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        val done = attack.status in listOf("completed", "stopped", "error")
        return AttackStatusResponse(
            attackId = id,
            status = attack.status,
            progress = attack.progress,
            requestCount = attack.requestCount,
            errorCount = attack.errorCount,
            isComplete = done,
        )
    }

    fun attackResults(id: String, offset: Int = 0, limit: Int = 0): AttackResultsResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        val all = attack.results.toList()
        val sliced = if (limit > 0) all.drop(offset).take(limit) else all.drop(offset)
        return AttackResultsResponse(
            attackId = id,
            results = sliced,
            total = all.size,
        )
    }

    fun pauseAttack(id: String): AttackStatusResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        attack.status = "paused"
        return attackStatus(id)
    }

    fun resumeAttack(id: String): AttackStatusResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        attack.status = "running"
        return attackStatus(id)
    }

    fun stopAttack(id: String): AttackStatusResponse {
        val attack = attacks[id] ?: throw IllegalArgumentException("Attack not found: $id")
        attack.status = "stopped"
        return attackStatus(id)
    }

    /**
     * Substitute a payload into a request. Supports:
     * 1. Template syntax: {param} in URL or body
     * 2. Query param: param=oldvalue -> param=payload
     * 3. Path segment: /param/oldvalue -> /param/payload (not implemented, use template)
     */
    private fun substitutePayload(baseRequest: HttpRequestData, param: String, payload: String): HttpRequestData {
        var url = baseRequest.url

        // 1. Template substitution: {param}
        url = url.replace("{$param}", payload)

        // 2. Query parameter substitution: param=value -> param=payload
        val queryParamRegex = Regex("([?&])${Regex.escape(param)}=([^&#]*)")
        url = queryParamRegex.replace(url) { match ->
            "${match.groupValues[1]}$param=$payload"
        }

        // 3. Body substitution (template + form-encoded)
        var body = baseRequest.body
        if (body != null) {
            body = body.replace("{$param}", payload)
            val bodyParamRegex = Regex("(^|&)${Regex.escape(param)}=([^&]*)")
            body = bodyParamRegex.replace(body) { match ->
                "${match.groupValues[1]}$param=$payload"
            }
            // JSON body substitution: "param":"oldvalue" -> "param":"payload"
            val jsonRegex = Regex(""""${Regex.escape(param)}"\s*:\s*"[^"]*"""")
            body = jsonRegex.replace(body) { "\"$param\":\"$payload\"" }
        }

        // 4. Header substitution (if header name matches param)
        val headers = baseRequest.headers.map { h ->
            if (h.name.equals(param, ignoreCase = true)) HttpHeader(h.name, payload) else h
        }

        return baseRequest.copy(url = url, body = body, headers = headers)
    }

    fun quickFuzz(request: QuickFuzzRequest): QuickFuzzResponse {
        require(request.payloads.isNotEmpty()) { "payloads list must not be empty" }
        require(request.param.isNotBlank()) { "param must not be blank" }
        require(request.request != null || request.requestId != null) { "Either 'request' or 'requestId' is required" }

        val results = mutableListOf<AttackResultEntry>()
        val start = System.currentTimeMillis()
        val baseRequest = resolveBaseRequest(request.request, request.requestId)

        request.payloads.forEachIndexed { idx, payload ->
            try {
                val modifiedRequest = substitutePayload(baseRequest, request.param, payload)
                val sendReq = SendRequest(request = modifiedRequest)
                val resp = repeaterService.send(sendReq)
                val ct = resp.response.headers.find { it.name.equals("Content-Type", ignoreCase = true) }?.value

                results.add(
                    AttackResultEntry(
                        index = idx,
                        payload = payload,
                        statusCode = resp.response.statusCode,
                        length = resp.response.body?.length ?: 0,
                        durationMs = resp.durationMs,
                        contentType = ct,
                        bodyPreview = resp.response.body?.take(200),
                    )
                )

                if (request.options.throttleMs > 0) {
                    Thread.sleep(request.options.throttleMs)
                }
            } catch (e: Exception) {
                results.add(
                    AttackResultEntry(
                        index = idx,
                        payload = payload,
                        statusCode = 0,
                        length = 0,
                        durationMs = 0,
                        error = e.message,
                    )
                )
            }
        }

        // Compute baseline from first successful result and flag anomalies
        val firstOk = results.firstOrNull { it.error == null }
        val baseline = firstOk?.let { QuickFuzzBaseline(it.statusCode, it.length, it.contentType) }

        val flagged = if (baseline != null) {
            results.map { r ->
                if (r.error != null) r
                else {
                    val anomalous = r.statusCode != baseline.statusCode ||
                        kotlin.math.abs(r.length - baseline.length) > (baseline.length * 0.2).toInt().coerceAtLeast(20) ||
                        r.contentType != baseline.contentType
                    r.copy(anomalous = anomalous)
                }
            }
        } else results

        return QuickFuzzResponse(
            results = flagged,
            total = flagged.size,
            durationMs = System.currentTimeMillis() - start,
            baseline = baseline,
        )
    }
}
