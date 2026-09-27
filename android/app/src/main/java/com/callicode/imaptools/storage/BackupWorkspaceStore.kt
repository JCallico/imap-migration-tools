package com.callicode.imaptools.storage

import com.callicode.imaptools.model.ProjectProfile
import java.io.File
import java.util.UUID

data class RetainedBackupGroup(
    val groupId: String,
    val projectName: String,
    val workspaces: List<String>,
)

/**
 * Backup workspaces owned by a project live in `projects/<project name>/`. Workspaces kept when their project is
 * deleted move to `retained/<group id>/`, so a later project with the same name starts with its own empty folder.
 */
class BackupWorkspaceStore(private val root: File) {
    private val projectsRoot = File(root, PROJECTS)
    private val retainedRoot = File(root, RETAINED)

    init {
        listOf(root, projectsRoot, retainedRoot).forEach {
            it.mkdirs()
            it.ownerOnlyDirectory()
        }
    }

    fun projectRoot(project: ProjectProfile): File = ownerRoot(projectsRoot, project.name).apply {
        mkdirs()
        ownerOnlyDirectory()
    }

    fun retain(project: ProjectProfile): Boolean {
        val owner = ownerRoot(projectsRoot, project.name)
        if (workspaces(owner).isEmpty()) {
            if (owner.isDirectory) owner.deleteRecursively()
            return false
        }
        val group = File(retainedRoot, UUID.randomUUID().toString())
        check(owner.renameTo(group)) { "Unable to retain the project's backup workspaces" }
        File(group, RETAINED_MARKER).writeText(project.name)
        return true
    }

    /** Move a project's workspaces with its new name; nothing to move is a successful no-op. */
    fun renameProject(project: ProjectProfile, renamed: ProjectProfile) {
        val source = ownerRoot(projectsRoot, project.name)
        if (!source.exists()) return
        val target = ownerRoot(projectsRoot, renamed.name)
        check(!target.exists() || target.canonicalPath == source.canonicalPath) {
            "Backup workspaces for ${renamed.name} already exist"
        }
        check(source.renameTo(target)) { "Unable to move the project's backup workspaces" }
    }

    fun retainedGroups(): List<RetainedBackupGroup> = retainedRoot.listFiles()
        .orEmpty()
        .filter(File::isDirectory)
        .mapNotNull { owner ->
            val marker = File(owner, RETAINED_MARKER)
            if (!marker.isFile) return@mapNotNull null
            val workspaces = workspaces(owner)
            if (workspaces.isEmpty()) return@mapNotNull null
            RetainedBackupGroup(
                groupId = owner.name,
                projectName = marker.readText().ifBlank { "Deleted project" },
                workspaces = workspaces.map(File::getName),
            )
        }
        .sortedBy { it.projectName.lowercase() }

    fun projectWorkspaceNames(project: ProjectProfile): List<String> =
        workspaces(ownerRoot(projectsRoot, project.name)).map(File::getName)

    fun deleteProjectWorkspaces(project: ProjectProfile) {
        val owner = ownerRoot(projectsRoot, project.name)
        check(!owner.exists() || owner.deleteRecursively()) { "Unable to delete the project's backup workspaces" }
    }

    fun deleteRetainedWorkspace(groupId: String, workspaceName: String) {
        val owner = retainedOwnerRoot(groupId)
        val workspace = File(owner, workspaceName)
        require(workspace.isDirectory && workspace.parentFile?.canonicalFile == owner.canonicalFile) {
            "Retained backup workspace does not exist"
        }
        check(workspace.deleteRecursively()) { "Unable to delete the retained backup workspace" }
        if (workspaces(owner).isEmpty()) {
            check(owner.deleteRecursively()) { "Unable to finish deleting the retained backup group" }
        }
    }

    fun retainedOwnerRoot(groupId: String): File {
        require(groupId.matches(Regex("[A-Za-z0-9-]+"))) { "Invalid retained backup group" }
        val owner = File(retainedRoot, groupId)
        require(File(owner, RETAINED_MARKER).isFile) { "Retained backup group does not exist" }
        return owner
    }

    /**
     * Convert the identifier-keyed layout: retained `<id>/` groups move to `retained/<id>/`, active `<id>/` owners move
     * to `projects/<name>/` using [projects], and loose pre-project workspaces move into [fallback]'s folder.
     */
    fun migrateLegacyLayout(projects: Map<String, ProjectProfile>, fallback: ProjectProfile) {
        for (entry in root.listFiles().orEmpty()) {
            if (entry.name == PROJECTS || entry.name == RETAINED) continue
            val project = projects[entry.name]
            val target = when {
                entry.isDirectory && File(entry, RETAINED_MARKER).isFile -> File(retainedRoot, entry.name)
                project != null -> ownerRoot(projectsRoot, project.name)
                else -> File(projectRoot(fallback), entry.name)
            }
            if (!target.exists()) entry.renameTo(target)
        }
    }

    private fun ownerRoot(parent: File, name: String): File {
        val owner = File(parent, name)
        require(name.isNotBlank() && owner.canonicalFile.parentFile == parent.canonicalFile) { "Invalid backup owner" }
        return owner
    }

    private fun workspaces(owner: File): List<File> = owner.listFiles()
        .orEmpty()
        .filter { it.isDirectory && !it.name.startsWith(".") }
        .sortedBy { it.name.lowercase() }

    companion object {
        private const val PROJECTS = "projects"
        private const val RETAINED = "retained"
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
