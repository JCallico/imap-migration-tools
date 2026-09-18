package com.callicode.imaptools.project

import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationOptions
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ProjectStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun dotenvRoundTripPreservesEscapedValues() {
        val file = temporaryFolder.newFile(".env")
        val values = linkedMapOf(
            "ANDROID_PROJECT_NAME" to "Client \"A\"",
            "DEST_FOLDER_PREFIX" to "Archive\\2026\nPriority",
        )

        DotenvCodec.write(file, values)

        assertEquals(values, DotenvCodec.read(file))
    }

    @Test
    fun configurationRoundTripExcludesSecrets() {
        val configuration = AppConfiguration(
            operation = Operation.MIGRATE,
            source = AccountState(
                host = "outlook.office365.com",
                username = "person@example.com",
                authentication = Authentication.MICROSOFT,
                password = "password-must-not-persist",
                oauthAccountId = "account-id",
                oauthEmail = "person@example.com",
                oauthAccessToken = "token-must-not-persist",
            ),
            options = OperationOptions(workers = 7, preserveFlags = true, destinationFolderPrefix = "Imported"),
        )

        val encoded = ProjectConfigurationCodec.encode("Customer", configuration)
        val decoded = ProjectConfigurationCodec.decode(encoded)

        assertFalse(encoded.keys.any { it.contains("PASSWORD") || it.contains("TOKEN") })
        assertFalse(encoded.values.contains("password-must-not-persist"))
        assertFalse(encoded.values.contains("token-must-not-persist"))
        assertEquals(configuration.copy(source = configuration.source.copy(password = "", oauthAccessToken = "")), decoded)
    }
}
