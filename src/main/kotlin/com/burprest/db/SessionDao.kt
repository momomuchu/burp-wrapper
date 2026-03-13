package com.burprest.db

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

data class PersistedSession(
    val name: String,
    val cookies: Map<String, String>,
    val headers: Map<String, String>,
)

class SessionDao(private val db: DatabaseManager) {

    private val json = Json { ignoreUnknownKeys = true }

    @Synchronized
    fun save(name: String, cookies: Map<String, String>, headers: Map<String, String>) {
        upsert("name", name)
        upsert("cookies", json.encodeToString(cookies))
        upsert("headers", json.encodeToString(headers))
    }

    fun load(): PersistedSession? {
        val name = get("name") ?: return null
        val cookies: Map<String, String> = get("cookies")?.let {
            try { json.decodeFromString(it) } catch (_: Exception) { emptyMap() }
        } ?: emptyMap()
        val headers: Map<String, String> = get("headers")?.let {
            try { json.decodeFromString(it) } catch (_: Exception) { emptyMap() }
        } ?: emptyMap()
        return PersistedSession(name, cookies, headers)
    }

    @Synchronized
    fun clear() {
        db.connection.createStatement().execute("DELETE FROM session_store")
    }

    private fun upsert(key: String, value: String) {
        val stmt = db.connection.prepareStatement(
            """MERGE INTO session_store ("key", "value") KEY ("key") VALUES (?, ?)"""
        )
        stmt.setString(1, key)
        stmt.setString(2, value)
        stmt.executeUpdate()
    }

    private fun get(key: String): String? {
        val stmt = db.connection.prepareStatement("""SELECT "value" FROM session_store WHERE "key" = ?""")
        stmt.setString(1, key)
        val rs = stmt.executeQuery()
        return if (rs.next()) rs.getString("value") else null
    }
}
