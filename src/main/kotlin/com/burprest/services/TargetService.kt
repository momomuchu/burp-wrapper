package com.burprest.services

import burp.api.montoya.MontoyaApi
import com.burprest.models.*

class TargetService(private val api: MontoyaApi) {

    // Track scope internally since Montoya API doesn't expose scope listing
    private val scopeIncludes = mutableSetOf<String>()
    private val scopeExcludes = mutableSetOf<String>()

    fun getSitemap(urlPrefix: String? = null): SitemapResponse {
        val entries = if (urlPrefix != null) {
            api.siteMap().requestResponses(burp.api.montoya.sitemap.SiteMapFilter.prefixFilter(urlPrefix))
        } else {
            api.siteMap().requestResponses()
        }

        return SitemapResponse(
            entries = entries.map {
                SitemapEntry(
                    url = it.request().url(),
                    method = it.request().method(),
                    statusCode = it.response()?.statusCode()?.toInt(),
                    mimeType = it.response()?.statedMimeType()?.name,
                )
            },
            total = entries.size,
        )
    }

    fun getScope(): ScopeResponse {
        return ScopeResponse(
            includes = scopeIncludes.toList(),
            excludes = scopeExcludes.toList(),
        )
    }

    fun setScope(request: SetScopeRequest): ScopeResponse {
        scopeIncludes.clear()
        scopeExcludes.clear()
        request.includes.forEach { url ->
            api.scope().includeInScope(url)
            scopeIncludes.add(url)
        }
        request.excludes.forEach { url ->
            api.scope().excludeFromScope(url)
            scopeExcludes.add(url)
        }
        return getScope()
    }

    fun addToScope(request: AddScopeRequest): ScopeCheckResponse {
        api.scope().includeInScope(request.url)
        scopeIncludes.add(request.url)
        scopeExcludes.remove(request.url)
        return ScopeCheckResponse(url = request.url, inScope = true)
    }

    fun removeFromScope(request: AddScopeRequest): ScopeCheckResponse {
        api.scope().excludeFromScope(request.url)
        scopeExcludes.add(request.url)
        scopeIncludes.remove(request.url)
        return ScopeCheckResponse(url = request.url, inScope = false)
    }

    fun isInScope(url: String): ScopeCheckResponse {
        val inScope = api.scope().isInScope(url)
        return ScopeCheckResponse(url = url, inScope = inScope)
    }
}
