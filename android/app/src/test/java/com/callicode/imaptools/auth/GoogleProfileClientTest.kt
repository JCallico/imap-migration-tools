package com.callicode.imaptools.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

class GoogleProfileClientTest {
    @Test
    fun `profile email is normalized`() {
        assertEquals("user@example.com", parseGoogleProfileEmail("""{"emailAddress":" user@example.com "}"""))
    }

    @Test
    fun `missing profile email is rejected`() {
        assertThrows(IOException::class.java) { parseGoogleProfileEmail("{}") }
    }
}
