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
            try {
                client = api.collaborator().createClient()
            } catch (e: Exception) {
                throw IllegalStateException("Burp Collaborator not available. Ensure Burp Suite Pro has Collaborator configured: ${e.message}")
            }
        }
        return client!!
    }

    fun generatePayload(): GeneratePayloadResponse {
        val c = ensureClient()
        val payload = c.generatePayload()
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
        val interactions = c.getAllInteractions()
        return PollResponse(
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
    }

    fun pollById(id: String): PollResponse {
        val payload = payloads[id]
            ?: return PollResponse(found = false, interactions = emptyList())

        val c = ensureClient()
        val interactions = c.getInteractions(InteractionFilter.interactionPayloadFilter(payload.toString()))
        return PollResponse(
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
    }
}
