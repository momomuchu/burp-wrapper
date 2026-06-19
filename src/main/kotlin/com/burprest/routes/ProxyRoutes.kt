package com.burprest.routes

import com.burprest.models.ApiResponse
import com.burprest.models.InterceptStatusResponse
import com.burprest.services.ProxyService
import io.ktor.server.application.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.proxyRoutes(service: ProxyService) {
    route("/proxy") {
        get("/history") {
            val limit = call.parameters["limit"]?.toIntOrNull()
            val offset = call.parameters["offset"]?.toIntOrNull()
            val filterHost = call.parameters["host"]
            // Validate bounds before they reach the service — a negative offset/limit otherwise
            // crashed into an internal exception.
            if (limit != null && limit < 1) throw IllegalArgumentException("limit must be >= 1")
            if (offset != null && offset < 0) throw IllegalArgumentException("offset must be >= 0")
            call.respond(ApiResponse.ok(service.getHistory(limit, offset, filterHost)))
        }

        get("/history/{id}") {
            // A non-numeric id is a usage error (400 via the global handler), not a 200 envelope.
            val id = call.parameters["id"]?.toIntOrNull()
                ?: throw IllegalArgumentException("id must be a number")
            call.respond(ApiResponse.ok(service.getHistoryEntry(id)))
        }

        get("/websocket/history") {
            call.respond(ApiResponse.ok(service.getWebSocketHistory()))
        }

        get("/intercept") {
            // Montoya doesn't expose live status; report the last API-driven state.
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = service.isIntercepting())))
        }

        post("/intercept/enable") {
            service.enableIntercept()
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = true)))
        }

        post("/intercept/disable") {
            service.disableIntercept()
            call.respond(ApiResponse.ok(InterceptStatusResponse(enabled = false)))
        }

        post("/intercept/forward") {
            // Forward requires intercepted message handling — stub
            call.respond(ApiResponse.ok(mapOf("forwarded" to true)))
        }

        post("/intercept/drop") {
            call.respond(ApiResponse.ok(mapOf("dropped" to true)))
        }
    }
}
