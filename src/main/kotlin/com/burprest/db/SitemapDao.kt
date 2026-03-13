package com.burprest.db

import java.net.URI
import java.time.Instant
import java.time.format.DateTimeFormatter

data class SitemapRow(
    val host: String,
    val path: String,
    val method: String,
    val lastSeen: String,
    val hitCount: Int,
)

class SitemapDao(private val db: DatabaseManager) {

    @Synchronized
    fun upsert(url: String, method: String) {
        val uri = try { URI(url) } catch (_: Exception) { return }
        val host = uri.host ?: return
        val path = uri.rawPath ?: "/"
        val ts = DateTimeFormatter.ISO_INSTANT.format(Instant.now())

        // H2: Use MERGE for upsert
        val stmt = db.connection.prepareStatement(
            """MERGE INTO sitemap (host, path, method, last_seen, hit_count)
               KEY (host, path, method)
               VALUES (?, ?, ?, ?, COALESCE((SELECT hit_count + 1 FROM sitemap WHERE host = ? AND path = ? AND method = ?), 1))"""
        )
        stmt.setString(1, host)
        stmt.setString(2, path)
        stmt.setString(3, method)
        stmt.setString(4, ts)
        stmt.setString(5, host)
        stmt.setString(6, path)
        stmt.setString(7, method)
        stmt.executeUpdate()
    }

    fun list(host: String? = null): List<SitemapRow> {
        val sql = if (host != null) {
            "SELECT * FROM sitemap WHERE host = ? ORDER BY path"
        } else {
            "SELECT * FROM sitemap ORDER BY host, path"
        }
        val stmt = db.connection.prepareStatement(sql)
        if (host != null) stmt.setString(1, host)

        val rs = stmt.executeQuery()
        val results = mutableListOf<SitemapRow>()
        while (rs.next()) {
            results.add(
                SitemapRow(
                    host = rs.getString("host"),
                    path = rs.getString("path"),
                    method = rs.getString("method"),
                    lastSeen = rs.getString("last_seen"),
                    hitCount = rs.getInt("hit_count"),
                )
            )
        }
        return results
    }

    @Synchronized
    fun clear() {
        db.connection.createStatement().execute("DELETE FROM sitemap")
    }
}
