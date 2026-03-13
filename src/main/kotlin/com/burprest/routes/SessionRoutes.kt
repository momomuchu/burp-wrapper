package com.burprest.routes

import com.burprest.models.*
import com.burprest.services.SessionService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.sessionRoutes(service: SessionService) {
    route("/session") {
        post("/set") {
            val request = call.receive<SetSessionRequest>()
            call.respond(ApiResponse.ok(service.setSession(request)))
        }

        get("/get") {
            call.respond(ApiResponse.ok(service.getSession()))
        }

        delete("/clear") {
            call.respond(ApiResponse.ok(service.clearSession()))
        }

        post("/send") {
            val request = call.receive<AuthenticatedRequest>()
            call.respond(ApiResponse.ok(service.send(request)))
        }

        post("/send/batch") {
            val batch = call.receive<BatchAuthenticatedRequest>()
            call.respond(ApiResponse.ok(service.sendBatch(batch)))
        }

        get("/cookie-jar") {
            call.respond(ApiResponse.ok(service.getCookieJar()))
        }

        delete("/cookie-jar") {
            call.respond(ApiResponse.ok(service.clearCookieJar()))
        }
    }
}
