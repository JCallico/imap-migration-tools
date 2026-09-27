package com.callicode.imaptools.storage

import com.callicode.imaptools.model.ProjectProfile
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BackupWorkspaceStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun retainedWorkspacesRemainDiscoverableAndFreeTheProjectName() {
        val root = temporaryFolder.newFolder("backups")
        val store = BackupWorkspaceStore(root)
        val customer = ProjectProfile("Customer mail")
        workspace(store.projectRoot(customer), "mail")

        assertTrue(store.retain(customer))
        val restoredStore = BackupWorkspaceStore(root)
        val group = restoredStore.retainedGroups().single()
        assertEquals(RetainedBackupGroup(group.groupId, "Customer mail", listOf("mail")), group)
        assertTrue(restoredStore.projectWorkspaceNames(customer).isEmpty())

        restoredStore.deleteRetainedWorkspace(group.groupId, "mail")

        assertTrue(restoredStore.retainedGroups().isEmpty())
        assertFalse(File(root, "retained/${group.groupId}").exists())
    }

    @Test
    fun deletingProjectWorkspacesRemovesOnlyTheSelectedOwner() {
        val store = BackupWorkspaceStore(temporaryFolder.newFolder("backups"))
        val selected = workspace(store.projectRoot(ProjectProfile("one")), "mail")
        val other = workspace(store.projectRoot(ProjectProfile("two")), "mail")

        store.deleteProjectWorkspaces(ProjectProfile("one"))

        assertFalse(selected.exists())
        assertTrue(other.exists())
    }

    @Test
    fun renamingMovesWorkspacesAndRefusesToMergeOwners() {
        val store = BackupWorkspaceStore(temporaryFolder.newFolder("backups"))
        workspace(store.projectRoot(ProjectProfile("acme")), "mail")
        workspace(store.projectRoot(ProjectProfile("taken")), "mail")

        store.renameProject(ProjectProfile("acme"), ProjectProfile("Acme Corp"))
        store.renameProject(ProjectProfile("missing"), ProjectProfile("anything"))

        assertEquals(listOf("mail"), store.projectWorkspaceNames(ProjectProfile("Acme Corp")))
        assertTrue(store.projectWorkspaceNames(ProjectProfile("acme")).isEmpty())
        assertThrows(IllegalStateException::class.java) {
            store.renameProject(ProjectProfile("Acme Corp"), ProjectProfile("taken"))
        }
    }

    @Test
    fun ownerNamesCannotEscapeTheBackupsDirectory() {
        val store = BackupWorkspaceStore(temporaryFolder.newFolder("backups"))
        assertThrows(IllegalArgumentException::class.java) { store.projectRoot(ProjectProfile("../outside")) }
        assertThrows(IllegalArgumentException::class.java) { store.retainedOwnerRoot("../outside") }
    }

    @Test
    fun legacyIdentifierLayoutMigratesToNamedAndRetainedFolders() {
        val root = temporaryFolder.newFolder("backups")
        workspace(File(root, "id-active"), "mail")
        workspace(File(root, "id-retained"), "archive")
        File(root, "id-retained/.retained-project").writeText("Old client")
        workspace(root, "loose")

        val store = BackupWorkspaceStore(root)
        store.migrateLegacyLayout(mapOf("id-active" to ProjectProfile("Client")), ProjectProfile.DEFAULT)

        assertEquals(listOf("mail"), store.projectWorkspaceNames(ProjectProfile("Client")))
        assertEquals(listOf("loose"), store.projectWorkspaceNames(ProjectProfile.DEFAULT))
        assertEquals(
            listOf(RetainedBackupGroup("id-retained", "Old client", listOf("archive"))),
            store.retainedGroups(),
        )
        assertEquals(setOf("projects", "retained"), root.list().orEmpty().toSet())
    }

    private fun workspace(owner: File, name: String): File =
        File(owner, name).apply {
            mkdirs()
            File(this, "message.eml").writeText("message")
        }
}
