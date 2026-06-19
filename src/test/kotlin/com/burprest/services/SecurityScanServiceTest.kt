package com.burprest.services

import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals

class SecurityScanServiceTest {

    private val svc = SecurityScanService(mockk(relaxed = true), mockk(relaxed = true), mockk(relaxed = true))

    @Test
    fun `substituteParam replaces a {param} placeholder`() {
        assertEquals("http://t/orders/42", svc.substituteParam("http://t/orders/{id}", "id", "42"))
    }

    @Test
    fun `substituteParam replaces an existing query value`() {
        assertEquals("http://t/u?id=42&x=1", svc.substituteParam("http://t/u?id=1&x=1", "id", "42"))
    }

    @Test
    fun `substituteParam appends the param when absent (avoids the IDOR false negative)`() {
        // No {param} placeholder and no existing ?id= -> must append, not return the URL unchanged.
        assertEquals("http://t/u?id=42", svc.substituteParam("http://t/u", "id", "42"))
        assertEquals("http://t/u?a=1&id=42", svc.substituteParam("http://t/u?a=1", "id", "42"))
    }

    @Test
    fun `substituteParam preserves a fragment when appending`() {
        assertEquals("http://t/u?id=42#frag", svc.substituteParam("http://t/u#frag", "id", "42"))
    }
}
