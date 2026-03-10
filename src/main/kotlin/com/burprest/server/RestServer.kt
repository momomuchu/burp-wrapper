package com.burprest.server

import burp.api.montoya.MontoyaApi
import com.burprest.models.ApiResponse
import com.burprest.routes.*
import com.burprest.services.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.Json
import java.time.Instant
import java.time.format.DateTimeFormatter

class RestServer(private val api: MontoyaApi, private val port: Int = 8089) {

    private var server: ApplicationEngine? = null
    private val startTime = System.currentTimeMillis()

    // Services
    private val proxyService = ProxyService(api)
    private val repeaterService = RepeaterService(api)
    private val collaboratorService = CollaboratorService(api)
    private val intruderService = IntruderService(api, repeaterService)
    private val scannerService = ScannerService(api)
    private val targetService = TargetService(api)
    private val decoderService = DecoderService()
    private val configService = ConfigService(api)

    fun start() {
        server = embeddedServer(Netty, port = port, host = "127.0.0.1") {
            configurePlugins()
            configureRouting()
        }.start(wait = false)

        api.logging().logToOutput("[burp-rest] Server started on http://127.0.0.1:$port")
    }

    fun stop() {
        server?.stop(1000, 2000)
        api.logging().logToOutput("[burp-rest] Server stopped")
    }

    private fun Application.configurePlugins() {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = false
                isLenient = true
                ignoreUnknownKeys = true
                encodeDefaults = true
            })
        }

        install(CORS) {
            anyHost()
            allowMethod(HttpMethod.Get)
            allowMethod(HttpMethod.Post)
            allowMethod(HttpMethod.Put)
            allowMethod(HttpMethod.Delete)
            allowMethod(HttpMethod.Options)
            allowHeader(HttpHeaders.ContentType)
            allowHeader(HttpHeaders.Authorization)
            allowHeader("X-API-Key")
        }

        install(StatusPages) {
            exception<IllegalArgumentException> { call, cause ->
                call.respond(
                    HttpStatusCode.BadRequest,
                    ApiResponse.error<Unit>("INVALID_REQUEST", cause.message ?: "Bad request"),
                )
            }
            exception<IllegalStateException> { call, cause ->
                api.logging().logToError("[burp-rest] State error: ${cause.message}")
                call.respond(
                    HttpStatusCode.ServiceUnavailable,
                    ApiResponse.error<Unit>("SERVICE_UNAVAILABLE", cause.message ?: "Service unavailable"),
                )
            }
            exception<Throwable> { call, cause ->
                val stackTrace = cause.stackTraceToString().take(500)
                api.logging().logToError("[burp-rest] Error: ${cause::class.simpleName}: ${cause.message}\n$stackTrace")
                call.respond(
                    HttpStatusCode.InternalServerError,
                    ApiResponse.error<Unit>("INTERNAL_ERROR", "${cause::class.simpleName}: ${cause.message}"),
                )
            }
        }
    }

    private fun Application.configureRouting() {
        routing {
            // Request logging interceptor
            intercept(ApplicationCallPipeline.Monitoring) {
                val start = System.currentTimeMillis()
                proceed()
                val duration = System.currentTimeMillis() - start
                val method = call.request.local.method.value
                val uri = call.request.local.uri
                val status = call.response.status()?.value ?: 0
                val ts = DateTimeFormatter.ISO_INSTANT.format(Instant.now())
                api.logging().logToOutput("[$ts] $method $uri $status ${duration}ms")
            }

            healthRoutes(startTime)
            proxyRoutes(proxyService)
            repeaterRoutes(repeaterService)
            collaboratorRoutes(collaboratorService)
            intruderRoutes(intruderService)
            scannerRoutes(scannerService)
            targetRoutes(targetService)
            decoderRoutes(decoderService)
            configRoutes(configService)
        }
    }
}
