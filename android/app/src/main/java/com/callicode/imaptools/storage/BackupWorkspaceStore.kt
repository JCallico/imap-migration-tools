package com.callicode.imaptools.storage

import com.callicode.imaptools.model.ProjectProfile
import java.io.File

data class RetainedBackupGroup(
    val projectId: String,
    val projectName: String,
    val workspaces: List<String>,
)

class BackupWorkspaceStore(private val root: File) {
    init {
        root.mkdirs()
        root.ownerOnlyDirectory()
    }

    fun retain(project: ProjectProfile): Boolean {
        val owner = ownerRoot(project.id)
        if (workspaces(owner).isEmpty()) {
            if (owner.isDirectory) owner.deleteRecursively()
            return false
        }
        File(owner, RETAINED_MARKER).writeText(project.name)
        return true
    }

    fun retainedGroups(): List<RetainedBackupGroup> = root.listFiles()
        .orEmpty()
        .filter(File::isDirectory)
        .mapNotNull { owner ->
            val marker = File(owner, RETAINED_MARKER)
            if (!marker.isFile) return@mapNotNull null
            val workspaces = workspaces(owner)
            if (workspaces.isEmpty()) return@mapNotNull null
            RetainedBackupGroup(
                projectId = owner.name,
                projectName = marker.readText().ifBlank { "Deleted project" },
                workspaces = workspaces.map(File::getName),
            )
        }
        .sortedBy { it.projectName.lowercase() }

    fun projectWorkspaceNames(projectId: String): List<String> = workspaces(ownerRoot(projectId)).map(File::getName)

    fun deleteProjectWorkspaces(projectId: String) {
        val owner = ownerRoot(projectId)
        check(!owner.exists() || owner.deleteRecursively()) { "Unable to delete the project's backup workspaces" }
    }

    fun deleteRetainedWorkspace(projectId: String, workspaceName: String) {
        val owner = retainedOwnerRoot(projectId)
        val workspace = File(owner, workspaceName)
        require(workspace.isDirectory && workspace.parentFile?.canonicalFile == owner.canonicalFile) {
            "Retained backup workspace does not exist"
        }
        check(workspace.deleteRecursively()) { "Unable to delete the retained backup workspace" }
        if (workspaces(owner).isEmpty()) {
            check(owner.deleteRecursively()) { "Unable to finish deleting the retained backup group" }
        }
    }

    fun retainedOwnerRoot(projectId: String): File {
        val owner = ownerRoot(projectId)
        require(File(owner, RETAINED_MARKER).isFile) { "Retained backup group does not exist" }
        return owner
    }

    private fun ownerRoot(projectId: String): File {
        require(projectId.matches(Regex("[A-Za-z0-9-]+"))) { "Invalid backup owner" }
        return File(root, projectId)
    }

    private fun workspaces(owner: File): List<File> = owner.listFiles()
        .orEmpty()
        .filter { it.isDirectory && !it.name.startsWith(".") }
        .sortedBy { it.name.lowercase() }

    companion object {
        private const val RETAINED_MARKER = ".retained-project"
    }

    private fun File.ownerOnlyDirectory() {
        setReadable(false, false)
        setWritable(false, false)
        setExecutable(false, false)
        setReadable(true, true)
        setWritable(true, true)
        setExecutable(true, true)
    }
}
