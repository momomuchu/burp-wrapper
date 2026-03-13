package com.burprest.db

import com.burprest.models.HttpHeader
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.net.URI
import java.time.Instant
import java.time.format.DateTimeFormatter

data class HistoryEntry(
    val id: Long = 0,
    val source: String,
    val method: String,
    val url: String,
    val host: String,
    val reqHeaders: List<HttpHeader>,
    val reqBody: String?,
    val statusCode: Int?,
    val resHeaders: List<HttpHeader>?,
    val resBody: String?,
    val durationMs: Long,
    val timestamp: String,
)

data class HistoryFilter(
    val host: String? = null,
    val method: String? = null,
    val statusCode: Int? = null,
    val source: String? = null,
    val search: String? = null,
    val since: String? = null,
    val until: String? = null,
    val page: Int = 0,
    val pageSize: Int = 50,
)

class HistoryDao(private val db: DatabaseManager) {

    private val json = Json { ignoreUnknownKeys = true }
    private val maxBodySize = 1_048_576 // 1MB

    @Synchronized
    fun insert(
        source: String,
        method: String,
        url: String,
        reqHeaders: List<HttpHeader>,
        reqBody: String?,
        statusCode: Int?,
        resHeaders: List<HttpHeader>?,
        resBody: String?,
        durationMs: Long,
    ): Long {
        val host = try { URI(url).host ?: "unknown" } catch (_: Exception) { "unknown" }
        val ts = DateTimeFormatter.ISO_INSTANT.format(Instant.now())

        val stmt = db.connection.prepareStatement(
            """INSERT INTO request_history
               (source, method, url, host, req_headers, req_body, status_code, res_headers, res_body, duration_ms, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            java.sql.Statement.RETURN_GENERATED_KEYS,
        )
        stmt.setString(1, source)
        stmt.setString(2, method)
        stmt.setString(3, url)
        stmt.setString(4, host)
        stmt.setString(5, json.encodeToString(reqHeaders))
        stmt.setString(6, reqBody?.take(maxBodySize))
        if (statusCode != null) stmt.setInt(7, statusCode) else stmt.setNull(7, java.sql.Types.INTEGER)
        stmt.setString(8, resHeaders?.let { json.encodeToString(it) })
        stmt.setString(9, resBody?.take(maxBodySize))
        stmt.setLong(10, durationMs)
        stmt.setString(11, ts)
        stmt.executeUpdate()

        val keys = stmt.generatedKeys
        return if (keys.next()) keys.getLong(1) else 0
    }

    fun search(filter: HistoryFilter): List<HistoryEntry> {
        val (where, params) = buildWhere(filter)
        val sql = "SELECT * FROM request_history $where ORDER BY id DESC LIMIT ? OFFSET ?"
        val stmt = db.connection.prepareStatement(sql)
        var idx = 1
        for (p in params) {
            when (p) {
                is String -> stmt.setString(idx++, p)
                is Int -> stmt.setInt(idx++, p)
            }
        }
        stmt.setInt(idx++, filter.pageSize)
        stmt.setInt(idx, filter.page * filter.pageSize)

        val rs = stmt.executeQuery()
        val results = mutableListOf<HistoryEntry>()
        while (rs.next()) {
            results.add(rowToEntry(rs))
        }
        return results
    }

    fun getById(id: Long): HistoryEntry? {
        val stmt = db.connection.prepareStatement("SELECT * FROM request_history WHERE id = ?")
        stmt.setLong(1, id)
        val rs = stmt.executeQuery()
        return if (rs.next()) rowToEntry(rs) else null
    }

    fun count(filter: HistoryFilter): Long {
        val (where, params) = buildWhere(filter)
        val stmt = db.connection.prepareStatement("SELECT COUNT(*) FROM request_history $where")
        var idx = 1
        for (p in params) {
            when (p) {
                is String -> stmt.setString(idx++, p)
                is Int -> stmt.setInt(idx++, p)
            }
        }
        val rs = stmt.executeQuery()
        return if (rs.next()) rs.getLong(1) else 0
    }

    @Synchronized
    fun clear() {
        db.connection.createStatement().execute("DELETE FROM request_history")
    }

    private fun buildWhere(filter: HistoryFilter): Pair<String, List<Any>> {
        val clauses = mutableListOf<String>()
        val params = mutableListOf<Any>()

        filter.host?.let { clauses.add("host = ?"); params.add(it) }
        filter.method?.let { clauses.add("method = ?"); params.add(it) }
        filter.statusCode?.let { clauses.add("status_code = ?"); params.add(it) }
        filter.source?.let { clauses.add("source = ?"); params.add(it) }
        filter.search?.let { clauses.add("(url LIKE ? OR req_body LIKE ? OR res_body LIKE ?)"); params.add("%$it%"); params.add("%$it%"); params.add("%$it%") }
        filter.since?.let { clauses.add("timestamp >= ?"); params.add(it) }
        filter.until?.let { clauses.add("timestamp <= ?"); params.add(it) }

        return if (clauses.isEmpty()) "" to emptyList()
        else "WHERE ${clauses.joinToString(" AND ")}" to params
    }

    private fun rowToEntry(rs: java.sql.ResultSet): HistoryEntry {
        return HistoryEntry(
            id = rs.getLong("id"),
            source = rs.getString("source"),
            method = rs.getString("method"),
            url = rs.getString("url"),
            host = rs.getString("host"),
            reqHeaders = try { json.decodeFromString(rs.getString("req_headers")) } catch (_: Exception) { emptyList() },
            reqBody = rs.getString("req_body"),
            statusCode = rs.getInt("status_code").let { if (rs.wasNull()) null else it },
            resHeaders = rs.getString("res_headers")?.let { try { json.decodeFromString(it) } catch (_: Exception) { null } },
            resBody = rs.getString("res_body"),
            durationMs = rs.getLong("duration_ms"),
            timestamp = rs.getString("timestamp"),
        )
    }
}
