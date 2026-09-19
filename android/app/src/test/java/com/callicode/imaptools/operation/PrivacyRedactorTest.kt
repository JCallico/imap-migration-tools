package com.callicode.imaptools.operation

import com.callicode.imaptools.model.OperationEvent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class PrivacyRedactorTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun removesCredentialsAccountsPrivatePathsAndMessageDetails() {
        val request = """
            {"source":{"username":"person@example.com","password":"pw","oauthAccountId":"provider-id",
            "oauth2":{"accessToken":"access-token","clientSecret":"client-secret"}}}
        """.trimIndent()
        val redactor = PrivacyRedactor(request, temporaryFolder.root)
        val input = "person@example.com pw provider-id access-token client-secret ${temporaryFolder.root}/mail " +
            "[INBOX] COPIED | 12 KB | Private subject"

        val output = redactor.event(OperationEvent("migrate", "progress", input)).message

        listOf("person@example.com", "pw", "provider-id", "access-token", "client-secret", "Private subject")
            .forEach { assertFalse(output.contains(it)) }
        assertFalse(output.contains(temporaryFolder.root.absolutePath))
        assertTrue(output.contains("[account hidden]"))
        assertTrue(output.contains("[message details hidden]"))
    }

    @Test
    fun removesEmailAddressesNotPresentInRequestAndEmlFilenames() {
        val redactor = PrivacyRedactor("{}", temporaryFolder.root)

        val output = redactor.event(
            OperationEvent("backup", "progress", "owner@example.net SAVED | 123_private-subject.eml"),
        ).message

        assertFalse(output.contains("owner@example.net"))
        assertFalse(output.contains("private-subject"))
    }
}
