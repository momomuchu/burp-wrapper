package com.burprest.routes

import com.burprest.models.*
import com.burprest.services.SecurityScanService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.securityScanRoutes(service: SecurityScanService) {
    route("/scan") {
        post("/auth-bypass") {
            val req = call.receive<AuthBypassRequest>()
            call.respond(ApiResponse.ok(service.authBypass(req)))
        }

        post("/idor") {
            val req = call.receive<IdorRequest>()
            call.respond(ApiResponse.ok(service.idor(req)))
        }

        post("/headers") {
            val req = call.receive<HeadersBypassRequest>()
            call.respond(ApiResponse.ok(service.headersBypass(req)))
        }

        post("/cors") {
            val req = call.receive<CorsRequest>()
            call.respond(ApiResponse.ok(service.cors(req)))
        }

        post("/endpoints") {
            val req = call.receive<EndpointsScanRequest>()
            call.respond(ApiResponse.ok(service.scanEndpoints(req)))
        }
    }
}
