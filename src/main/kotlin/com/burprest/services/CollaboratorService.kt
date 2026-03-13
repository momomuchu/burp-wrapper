package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.InteractionFilter
import com.burprest.models.*
import java.time.Instant
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class CollaboratorService(private val api: MontoyaApi) {

    private var client: CollaboratorClient? = null
    private val payloads = ConcurrentHashMap<String, burp.api.montoya.collaborator.CollaboratorPayload>()

    private fun ensureClient(): CollaboratorClient {
        if (client == null) {
            val collaborator = try {
                api.collaborator()
            } catch (e: Throwable) {
                throw IllegalStateException(
                    "Burp Collaborator API not available. This requires Burp Suite Professional. " +
                    "Community Edition does not support Collaborator. Error: ${e::class.simpleName}: ${e.message}"
                )
            } ?: throw IllegalStateException(
                "Burp Collaborator API returned null. This requires Burp Suite Professional " +
                "with Collaborator server configured (Project Options > Misc > Burp Collaborator Server)."
            )
            try {
                client = collaborator.createClient()
            } catch (e: Throwable) {
                throw IllegalStateException(
                    "Failed to create Collaborator client. Ensure Collaborator server is configured " +
                    "and reachable. Error: ${e::class.simpleName}: ${e.message}"
                )
            }
        }
        return client!!
    }

    fun generatePayload(): GeneratePayloadResponse {
        val c = ensureClient()
        val payload = try {
            c.generatePayload()
        } catch (e: Throwable) {
            throw IllegalStateException("Failed to generate Collaborator payload: ${e::class.simpleName}: ${e.message}")
        }
        val id = UUID.randomUUID().toString().take(8)
        payloads[id] = payload

        return GeneratePayloadResponse(
            payload = CollaboratorPayload(
                id = id,
                payload = payload.toString(),
                interactionId = id,
            ),
        )
    }

    fun generateBatch(count: Int): BatchGenerateResponse {
        val results = (1..count).map { generatePayload().payload }
        return BatchGenerateResponse(payloads = results)
    }

    fun poll(): PollResponse {
        val c = ensureClient()
        return try {
            val interactions = c.getAllInteractions()
            PollResponse(
                found = interactions.isNotEmpty(),
                interactions = interactions.map { interaction ->
                    Interaction(
                        id = interaction.id().toString(),
                        type = interaction.type().name,
                        clientIp = interaction.clientIp().toString(),
                        timestamp = Instant.now().toString(),
                    )
                },
            )
        } catch (e: Throwable) {
            PollResponse(found = false, interactions = emptyList())
        }
    }

    fun pollById(id: String): PollResponse {
        val payload = payloads[id]
            ?: return PollResponse(found = false, interactions = emptyList())

        val c = ensureClient()
        return try {
            val interactions = c.getInteractions(InteractionFilter.interactionPayloadFilter(payload.toString()))
            PollResponse(
                found = interactions.isNotEmpty(),
                interactions = interactions.map { interaction ->
                    Interaction(
                        id = interaction.id().toString(),
                        type = interaction.type().name,
                        clientIp = interaction.clientIp().toString(),
                        timestamp = Instant.now().toString(),
                    )
                },
            )
        } catch (e: Throwable) {
            PollResponse(found = false, interactions = emptyList())
        }
    }
}
