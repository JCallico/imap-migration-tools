package com.callicode.imaptools.project

import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationOptions
import com.callicode.imaptools.model.ProjectProfile
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class ProjectStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private val preferences = FakePreferences()

    private fun store(root: File = File(temporaryFolder.root, "projects")) = ProjectStore(root, preferences)

    @Test
    fun dotenvRoundTripPreservesEscapedValues() {
        val file = temporaryFolder.newFile(".env")
        val values = linkedMapOf(
            "SRC_IMAP_USERNAME" to "Client \"A\"",
            "DEST_FOLDER_PREFIX" to "Archive\\2026\nPriority",
        )

        DotenvCodec.write(file, values)

        assertEquals(values, DotenvCodec.read(file))
    }

    @Test
    fun configurationRoundTripExcludesSecretsAndName() {
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

        val encoded = ProjectConfigurationCodec.encode(configuration)
        val decoded = ProjectConfigurationCodec.decode(encoded)

        assertFalse(encoded.keys.any { it.contains("PASSWORD") || it.contains("TOKEN") })
        assertFalse(encoded.containsKey("ANDROID_PROJECT_NAME"))
        assertFalse(encoded.values.contains("password-must-not-persist"))
        assertFalse(encoded.values.contains("token-must-not-persist"))
        assertEquals(configuration.copy(source = configuration.source.copy(password = "", oauthAccessToken = "")), decoded)
    }

    @Test
    fun freshInstallCreatesDefaultEnvFromLegacyConfiguration() {
        val root = File(temporaryFolder.root, "projects")
        val legacy = AppConfiguration(source = AccountState(host = "imap.example.com"))

        val (active, configuration) = store(root).initialize(legacy)

        assertEquals(ProjectProfile.DEFAULT, active)
        assertEquals("imap.example.com", configuration.source.host)
        assertTrue(File(root, ".env").isFile)
        assertEquals(listOf(ProjectProfile.DEFAULT), store(root).projects())
    }

    @Test
    fun projectsAreEnvFilesNamedAfterTheProject() {
        val root = File(temporaryFolder.root, "projects")
        val store = store(root)
        store.initialize(AppConfiguration())

        val (zeta, _) = store.create("zeta")
        store.create(" Alpha ")

        assertTrue(File(root, "zeta.env").isFile)
        assertTrue(File(root, "Alpha.env").isFile)
        assertEquals(listOf("default", "Alpha", "zeta"), store.projects().map { it.name })
        assertEquals("Alpha", preferences.getString("active_project_name", null))
        store.select(zeta)
        assertEquals(zeta, store(root).initialize(AppConfiguration()).first)
    }

    @Test
    fun namesFollowTheDesktopRules() {
        val store = store()
        store.initialize(AppConfiguration())
        store.create("acme")

        listOf("", "a".repeat(61), "a/b", ".hidden", "Default", "LOCAL", "con", "ACME").forEach { name ->
            assertThrows(IllegalArgumentException::class.java) { store.create(name) }
        }
    }

    @Test
    fun renameMovesTheSingleFileAndFollowsTheActiveSelection() {
        val root = File(temporaryFolder.root, "projects")
        val store = store(root)
        store.initialize(AppConfiguration())
        val (acme, _) = store.create("acme")
        store.save(acme, AppConfiguration(source = AccountState(host = "imap.acme.example")))

        val renamed = store.rename(acme, "Acme Corp")

        assertFalse(File(root, "acme.env").exists())
        assertEquals("imap.acme.example", store.load(renamed).source.host)
        assertEquals("Acme Corp", preferences.getString("active_project_name", null))
        assertEquals(listOf("default", "Acme Corp"), store.projects().map { it.name })

        store.revertRename(renamed, acme)
        assertTrue(File(root, "acme.env").isFile)
        assertEquals("acme", preferences.getString("active_project_name", null))
    }

    @Test
    fun defaultProjectCannotBeRenamedOrDeleted() {
        val store = store()
        store.initialize(AppConfiguration())
        assertThrows(IllegalArgumentException::class.java) { store.rename(ProjectProfile.DEFAULT, "other") }
        assertThrows(IllegalArgumentException::class.java) { store.delete(ProjectProfile.DEFAULT) }
    }

    @Test
    fun conditionalSaveDoesNotRecreateARenamedProject() {
        val root = File(temporaryFolder.root, "projects")
        val store = store(root)
        store.initialize(AppConfiguration())
        val (acme, configuration) = store.create("acme")
        store.rename(acme, "renamed")

        store.saveIf({ false }, acme, configuration)

        assertFalse(File(root, "acme.env").exists())
    }

    @Test
    fun legacyUuidDirectoriesMigrateToNamedEnvFiles() {
        val root = File(temporaryFolder.root, "projects")
        fun legacy(id: String, name: String, host: String) = File(root, "$id/.env").apply {
            parentFile.mkdirs()
            DotenvCodec.write(this, mapOf("ANDROID_PROJECT_NAME" to name, "SRC_IMAP_HOST" to host))
        }
        legacy("11111111-aaaa", "Default", "default.example")
        legacy("22222222-bbbb", "Client: A/B", "client.example")
        legacy("33333333-cccc", "client_ a_b", "second.example")
        legacy("44444444-dddd", "local", "local.example")
        preferences.edit().putString("active_project_id", "22222222-bbbb").apply()

        val migrating = store(root)
        val (active, configuration) = migrating.initialize(AppConfiguration())

        assertEquals(
            listOf("default", "Client_ A_B", "client_ a_b (2)", "local project"),
            store(root).projects().map { it.name },
        )
        assertEquals(ProjectProfile("Client_ A_B"), active)
        assertEquals("client.example", configuration.source.host)
        assertEquals("default.example", DotenvCodec.read(File(root, ".env"))["SRC_IMAP_HOST"])
        assertFalse(DotenvCodec.read(File(root, ".env")).containsKey("ANDROID_PROJECT_NAME"))
        assertFalse(File(root, "11111111-aaaa").exists())
        assertEquals(null, preferences.getString("active_project_id", null))
        assertEquals(
            mapOf(
                "11111111-aaaa" to ProjectProfile.DEFAULT,
                "22222222-bbbb" to ProjectProfile("Client_ A_B"),
                "33333333-cccc" to ProjectProfile("client_ a_b (2)"),
                "44444444-dddd" to ProjectProfile("local project"),
            ),
            migrating.migratedProjects,
        )
    }
}
