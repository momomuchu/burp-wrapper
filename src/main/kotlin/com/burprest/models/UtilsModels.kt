package com.burprest.models

import kotlinx.serialization.Serializable

// --- /utils/diff ---

@Serializable
data class DiffTarget(
    val method: String = "GET",
    val url: String,
    val body: String? = null,
    val extraHeaders: Map<String, String>? = null,
)

@Serializable
data class DiffRequest(
    val a: DiffTarget,
    val b: DiffTarget,
)

@Serializable
data class HeaderDiff(
    val name: String,
    val aValue: String?,
    val bValue: String?,
)

@Serializable
data class DiffResponse(
    val statusMatch: Boolean,
    val statusA: Int,
    val statusB: Int,
    val lengthA: Int,
    val lengthB: Int,
    val lengthDiff: Int,
    val headerDiffs: List<HeaderDiff>,
    val bodyDiff: String?,
)

// --- /utils/extract-endpoints ---

@Serializable
data class ExtractEndpointsRequest(
    val url: String,
)

@Serializable
data class ExtractEndpointsResponse(
    val endpoints: List<String>,
    val total: Int,
)
