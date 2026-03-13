package com.burprest.db

import java.io.Closeable
import java.io.File
import java.sql.Connection
import java.sql.DriverManager

class DatabaseManager(dbPath: String) : Closeable {

    val connection: Connection

    init {
        Class.forName("org.h2.Driver")
        File(dbPath).parentFile?.mkdirs()
        // H2 file-based database with auto-create, MVStore engine
        val h2Path = dbPath.removeSuffix(".db").removeSuffix(".mv")
        connection = DriverManager.getConnection("jdbc:h2:file:$h2Path")
        createTables()
    }

    private fun createTables() {
        connection.createStatement().execute(
            """
            CREATE TABLE IF NOT EXISTS request_history (
                id          IDENTITY PRIMARY KEY,
                source      VARCHAR NOT NULL,
                method      VARCHAR NOT NULL,
                url         VARCHAR NOT NULL,
                host        VARCHAR NOT NULL,
                req_headers CLOB NOT NULL,
                req_body    CLOB,
                status_code INTEGER,
                res_headers CLOB,
                res_body    CLOB,
                duration_ms BIGINT,
                timestamp   VARCHAR NOT NULL
            )
            """.trimIndent()
        )
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_history_host ON request_history(host)")
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_history_status ON request_history(status_code)")
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_history_method ON request_history(method)")
        connection.createStatement().execute("CREATE INDEX IF NOT EXISTS idx_history_ts ON request_history(timestamp)")

        connection.createStatement().execute(
            """
            CREATE TABLE IF NOT EXISTS sitemap (
                host        VARCHAR NOT NULL,
                path        VARCHAR NOT NULL,
                method      VARCHAR NOT NULL,
                last_seen   VARCHAR NOT NULL,
                hit_count   INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (host, path, method)
            )
            """.trimIndent()
        )

        connection.createStatement().execute(
            """
            CREATE TABLE IF NOT EXISTS session_store (
                "key"   VARCHAR PRIMARY KEY,
                "value" CLOB NOT NULL
            )
            """.trimIndent()
        )
    }

    override fun close() {
        if (!connection.isClosed) {
            connection.close()
        }
    }
}
