package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.burprest.models.*

class RepeaterService(private val api: MontoyaApi) {

    fun send(request: SendRequest): SendResponse {
        val httpRequest = resolveRequest(request)

        val start = System.currentTimeMillis()
        val httpResponse = api.http().sendRequest(httpRequest)
        val duration = System.currentTimeMillis() - start

        val resp = httpResponse.response()
        return SendResponse(
            request = HttpRequestData(
                method = httpRequest.method(),
                url = httpRequest.url(),
                headers = httpRequest.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (httpRequest.body().length() > 0) httpRequest.bodyToString() else null,
            ),
            response = HttpResponseData(
                statusCode = resp.statusCode().toInt(),
                headers = resp.headers().map { HttpHeader(it.name(), it.value()) },
                body = if (resp.body().length() > 0) resp.bodyToString() else null,
            ),
            durationMs = duration,
        )
    }

    fun sendBatch(batch: BatchSendRequest): BatchSendResponse {
        val start = System.currentTimeMillis()
        val results = batch.requests.map { send(it) }
        val totalDuration = System.currentTimeMillis() - start

        return BatchSendResponse(
            results = results,
            totalDurationMs = totalDuration,
        )
    }

    fun createTab(request: CreateTabRequest): CreateTabResponse {
        val name = request.name ?: "REST API Tab"
        val httpRequest = if (request.request != null) {
            buildRequest(request.request)
        } else if (request.requestId != null) {
            getHistoryRequest(request.requestId)
        } else {
            HttpRequest.httpRequestFromUrl("https://example.com")
        }

        api.repeater().sendToRepeater(httpRequest, name)

        return CreateTabResponse(name = name, created = true)
    }

    private fun resolveRequest(request: SendRequest): HttpRequest {
        val base = if (request.request != null) {
            buildRequest(request.request)
        } else if (request.requestId != null) {
            getHistoryRequest(request.requestId)
        } else {
            throw IllegalArgumentException("Either 'request' or 'requestId' is required")
        }

        return applyModifications(base, request.modifications)
    }

    private fun applyModifications(base: HttpRequest, mods: RequestModifications?): HttpRequest {
        if (mods == null) return base
        var req = base

        mods.method?.let { req = req.withMethod(it) }
        mods.path?.let { req = req.withPath(it) }
        mods.body?.let { req = req.withBody(it) }
        mods.headers?.forEach { (name, value) ->
            req = req.withRemovedHeader(name).withAddedHeader(name, value)
        }

        return req
    }

    internal fun buildRequest(data: HttpRequestData): HttpRequest {
        var req = HttpRequest.httpRequestFromUrl(data.url)
            .withMethod(data.method)

        data.headers.forEach { h ->
            req = req.withAddedHeader(h.name, h.value)
        }

        data.body?.let { req = req.withBody(it) }

        return req
    }

    private fun getHistoryRequest(id: Int): HttpRequest {
        val history = api.proxy().history()
        require(id in history.indices) { "Invalid history entry ID: $id" }
        return history[id].finalRequest()
    }
}
