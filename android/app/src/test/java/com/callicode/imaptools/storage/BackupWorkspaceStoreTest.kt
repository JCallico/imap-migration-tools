package com.callicode.imaptools.storage

import com.callicode.imaptools.model.ProjectProfile
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class BackupWorkspaceStoreTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun retainedWorkspacesRemainDiscoverableAndCanBeDeletedIndividually() {
        val root = temporaryFolder.newFolder("backups")
        val workspace = workspace(root, "project-1", "mail")
        val store = BackupWorkspaceStore(root)

        assertTrue(store.retain(ProjectProfile("project-1", "Customer mail")))
        val restoredStore = BackupWorkspaceStore(root)
        assertEquals(
            listOf(RetainedBackupGroup("project-1", "Customer mail", listOf("mail"))),
            restoredStore.retainedGroups(),
        )

        restoredStore.deleteRetainedWorkspace("project-1", "mail")

        assertFalse(workspace.exists())
        assertTrue(restoredStore.retainedGroups().isEmpty())
        assertFalse(File(root, "project-1").exists())
    }

    @Test
    fun deletingProjectWorkspacesRemovesOnlyTheSelectedOwner() {
        val root = temporaryFolder.newFolder("backups")
        val selected = workspace(root, "project-1", "mail")
        val other = workspace(root, "project-2", "mail")
        val store = BackupWorkspaceStore(root)

        store.deleteProjectWorkspaces("project-1")

        assertFalse(selected.exists())
        assertTrue(other.exists())
    }

    private fun workspace(root: File, projectId: String, name: String): File =
        File(root, "$projectId/$name").apply {
            mkdirs()
            File(this, "message.eml").writeText("message")
        }
}
