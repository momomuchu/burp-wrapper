package com.burprest.services

import burp.api.montoya.MontoyaApi
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import burp.api.montoya.scanner.Crawl
import burp.api.montoya.scanner.audit.Audit
import com.burprest.models.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

class ScannerService(private val api: MontoyaApi) {

    private val scans = ConcurrentHashMap<String, ScanState>()

    sealed class ScanState(val id: String) {
        class CrawlState(id: String, val crawl: Crawl) : ScanState(id)
        class AuditState(id: String, val audit: Audit) : ScanState(id)
        class CrawlAndAuditState(id: String, val crawl: Crawl, val audit: Audit) : ScanState(id)
    }

    fun crawl(request: ScanRequest): ScanStartResponse {
        val id = UUID.randomUUID().toString().take(8)
        try {
            val crawlConfig = CrawlConfiguration.crawlConfiguration(request.url)
            val crawl = api.scanner().startCrawl(crawlConfig)
            scans[id] = ScanState.CrawlState(id, crawl)
            return ScanStartResponse(scanId = id, status = "running")
        } catch (e: Throwable) {
            throw IllegalStateException(
                "Failed to start crawl. This requires Burp Suite Professional with Scanner enabled. " +
                "Ensure the target URL is in scope. Error: ${e::class.simpleName}: ${e.message}"
            )
        }
    }

    fun audit(request: ScanRequest): ScanStartResponse {
        val id = UUID.randomUUID().toString().take(8)
        try {
            val auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            val audit = api.scanner().startAudit(auditConfig)
            scans[id] = ScanState.AuditState(id, audit)
            return ScanStartResponse(scanId = id, status = "running")
        } catch (e: Throwable) {
            throw IllegalStateException(
                "Failed to start audit. Active scanning requires Burp Suite Professional. " +
                "Community Edition only supports passive scanning. Error: ${e::class.simpleName}: ${e.message}"
            )
        }
    }

    fun crawlAndAudit(request: ScanRequest): ScanStartResponse {
        val id = UUID.randomUUID().toString().take(8)
        try {
            val crawlConfig = CrawlConfiguration.crawlConfiguration(request.url)
            val auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS)
            val crawl = api.scanner().startCrawl(crawlConfig)
            val audit = api.scanner().startAudit(auditConfig)
            scans[id] = ScanState.CrawlAndAuditState(id, crawl, audit)
            return ScanStartResponse(scanId = id, status = "running")
        } catch (e: Throwable) {
            throw IllegalStateException(
                "Failed to start crawl+audit. This requires Burp Suite Professional. " +
                "Error: ${e::class.simpleName}: ${e.message}"
            )
        }
    }

    fun status(scanId: String): ScanStatusResponse {
        val scan = scans[scanId] ?: throw IllegalArgumentException("Scan not found: $scanId")
        return try {
            ScanStatusResponse(
                scanId = scanId,
                status = "running",
                issueCount = getIssueCount(scan),
            )
        } catch (e: Throwable) {
            ScanStatusResponse(scanId = scanId, status = "error", issueCount = 0)
        }
    }

    fun issues(scanId: String): ScanIssuesResponse {
        val scan = scans[scanId] ?: throw IllegalArgumentException("Scan not found: $scanId")
        return try {
            val auditIssues = when (scan) {
                is ScanState.AuditState -> scan.audit.issues()
                is ScanState.CrawlAndAuditState -> scan.audit.issues()
                else -> emptyList()
            }

            ScanIssuesResponse(
                scanId = scanId,
                issues = auditIssues.map {
                    ScanIssue(
                        name = it.name(),
                        url = it.baseUrl(),
                        severity = it.severity().name,
                        confidence = it.confidence().name,
                        detail = it.detail(),
                        remediation = it.remediation(),
                    )
                },
                total = auditIssues.size,
            )
        } catch (e: Throwable) {
            ScanIssuesResponse(scanId = scanId, issues = emptyList(), total = 0)
        }
    }

    fun pause(scanId: String): ScanStatusResponse {
        return status(scanId)
    }

    fun resume(scanId: String): ScanStatusResponse {
        return status(scanId)
    }

    fun stop(scanId: String): ScanStatusResponse {
        scans.remove(scanId)
        return ScanStatusResponse(scanId = scanId, status = "stopped")
    }

    fun issueDefinitions(): IssueDefinitionsResponse {
        return try {
            val issues = api.siteMap().issues()
            val uniqueNames = mutableSetOf<String>()
            val defs = issues.mapNotNull {
                val name = it.name()
                if (uniqueNames.add(name)) {
                    IssueDefinition(
                        name = name,
                        typeIndex = 0L,
                        description = it.detail() ?: "",
                        remediation = it.remediation() ?: "",
                    )
                } else null
            }
            IssueDefinitionsResponse(definitions = defs, total = defs.size)
        } catch (e: Throwable) {
            IssueDefinitionsResponse(definitions = emptyList(), total = 0)
        }
    }

    private fun getIssueCount(scan: ScanState): Int = try {
        when (scan) {
            is ScanState.AuditState -> scan.audit.issues().size
            is ScanState.CrawlAndAuditState -> scan.audit.issues().size
            else -> 0
        }
    } catch (_: Throwable) { 0 }
}
