package com.burprest.routes

import com.burprest.models.*
import com.burprest.services.UtilsService
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.utilsRoutes(service: UtilsService) {
    route("/utils") {
        post("/diff") {
            val req = call.receive<DiffRequest>()
            call.respond(ApiResponse.ok(service.diff(req)))
        }

        post("/extract-endpoints") {
            val req = call.receive<ExtractEndpointsRequest>()
            call.respond(ApiResponse.ok(service.extractEndpoints(req)))
        }
    }
}
