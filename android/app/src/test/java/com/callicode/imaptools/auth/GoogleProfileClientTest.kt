package com.callicode.imaptools.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
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

    @Test
    fun `revoked authorization asks the user to connect again`() {
        val error = GoogleProfileHttpException(401)

        assertTrue(isExpiredGoogleAuthorization(error))
        assertEquals("Google access needs to be renewed. Connect Google again.", googleProfileFailureMessage(error))
    }

    @Test
    fun `temporary profile failures remain retryable`() {
        val error = GoogleProfileHttpException(503)

        assertFalse(isExpiredGoogleAuthorization(error))
        assertEquals("Google account details are temporarily unavailable. Try again.", googleProfileFailureMessage(error))
    }
}
