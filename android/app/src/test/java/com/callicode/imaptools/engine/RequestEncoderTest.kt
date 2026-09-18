package com.callicode.imaptools.engine

import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationOptions
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File

class RequestEncoderTest {
    @Test
    fun backupIncludesEverySupportedOption() {
        val request = JSONObject(
            RequestEncoder.encode(
                AppConfiguration(
                    operation = Operation.BACKUP,
                    source = AccountState("imap.example.com", "person@example.com", password = "secret"),
                    backupName = "My mail/2026",
                    options = OperationOptions(
                        folder = "Inbox",
                        workers = 7,
                        batchSize = 22,
                        preserveFlags = true,
                        preserveLabels = true,
                        gmailMode = true,
                        manifestOnly = true,
                    ),
                ),
                File("/workspace"),
            ),
        )

        assertEquals("backup", request.getString("operation"))
        assertEquals("person@example.com", request.getJSONObject("source").getString("username"))
        assertEquals("/workspace/My_mail_2026", request.getString("backupPath"))
        assertEquals(7, request.getJSONObject("options").getInt("workers"))
        assertEquals(true, request.getJSONObject("options").getBoolean("manifestOnly"))
    }

    @Test
    fun oauthRequestDoesNotIncludePassword() {
        val request = JSONObject(
            RequestEncoder.encode(
                AppConfiguration(
                    operation = Operation.MIGRATE,
                    source = AccountState(
                        "imap.gmail.com",
                        "source@example.com",
                        Authentication.GOOGLE,
                        password = "must-not-leak",
                        oauthAccessToken = "token",
                        oauthAccountId = "source@example.com",
                        oauthEmail = "source@example.com",
                    ),
                    destination = AccountState("imap.example.com", "destination@example.com", password = "pw"),
                ),
                File("/workspace"),
            ),
        )

        val source = request.getJSONObject("source")
        assertFalse(source.has("password"))
        assertEquals("token", source.getJSONObject("oauth2").getString("accessToken"))
        assertEquals("google", source.getJSONObject("oauth2").getString("provider"))
        assertEquals("source", source.getString("tokenSlot"))
        assertEquals("source@example.com", source.getString("oauthAccountId"))
    }

    @Test
    fun unsafeAndEmptyWorkspaceNamesAreNormalized() {
        assertEquals("default", RequestEncoder.safeBackupName("../"))
        assertEquals("mail_backup", RequestEncoder.safeBackupName("mail backup"))
    }

    @Test
    fun migrationCacheIsPartitionedByBothAccountEndpoints() {
        fun cacheFor(source: String): String {
            val configuration = AppConfiguration(
                operation = Operation.MIGRATE,
                source = AccountState("imap.example.com", source, password = "source-password"),
                destination = AccountState("imap.example.com", "destination@example.com", password = "dest-password"),
            )
            return JSONObject(RequestEncoder.encode(configuration, File("/workspace")))
                .getJSONObject("options")
                .getString("cachePath")
        }

        assertFalse(cacheFor("first@example.com") == cacheFor("second@example.com"))
        assertFalse(cacheFor("first@example.com").contains("first@example.com"))
    }
}
