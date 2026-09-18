package com.callicode.imaptools.project

import android.content.SharedPreferences
import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationOptions
import com.callicode.imaptools.model.ProjectProfile
import com.callicode.imaptools.model.TargetType
import java.io.File
import java.util.UUID

class ProjectStore(
    private val root: File,
    private val preferences: SharedPreferences,
) {
    fun initialize(legacyConfiguration: AppConfiguration): Pair<ProjectProfile, AppConfiguration> {
        root.mkdirs()
        val projects = projects()
        if (projects.isEmpty()) {
            return create("Default", legacyConfiguration)
        }
        val activeId = preferences.getString(ACTIVE_PROJECT, null)
        val active = projects.firstOrNull { it.id == activeId } ?: projects.first()
        preferences.edit().putString(ACTIVE_PROJECT, active.id).apply()
        return active to load(active)
    }

    fun projects(): List<ProjectProfile> = root.listFiles()
        .orEmpty()
        .filter { it.isDirectory && File(it, ENV_FILE).isFile }
        .mapNotNull { directory ->
            runCatching {
                val values = DotenvCodec.read(File(directory, ENV_FILE))
                ProjectProfile(directory.name, values[PROJECT_NAME]?.ifBlank { "Unnamed" } ?: "Unnamed")
            }.getOrNull()
        }
        .sortedBy { it.name.lowercase() }

    fun create(name: String, configuration: AppConfiguration = AppConfiguration()): Pair<ProjectProfile, AppConfiguration> {
        val project = ProjectProfile(UUID.randomUUID().toString(), name.trim())
        save(project, configuration)
        select(project)
        return project to configuration
    }

    fun load(project: ProjectProfile): AppConfiguration =
        ProjectConfigurationCodec.decode(DotenvCodec.read(envFile(project)))

    @Synchronized
    fun save(project: ProjectProfile, configuration: AppConfiguration) {
        val directory = File(root, project.id).apply { mkdirs() }
        DotenvCodec.write(File(directory, ENV_FILE), ProjectConfigurationCodec.encode(project.name, configuration))
    }

    fun select(project: ProjectProfile) {
        preferences.edit().putString(ACTIVE_PROJECT, project.id).apply()
    }

    @Synchronized
    fun delete(project: ProjectProfile) {
        val directory = File(root, project.id)
        File(directory, ENV_FILE).delete()
        directory.delete()
    }

    private fun envFile(project: ProjectProfile) = File(File(root, project.id), ENV_FILE)

    companion object {
        private const val ACTIVE_PROJECT = "active_project_id"
        private const val ENV_FILE = ".env"
        private const val PROJECT_NAME = "ANDROID_PROJECT_NAME"
    }
}

internal object ProjectConfigurationCodec {
    fun encode(name: String, value: AppConfiguration): LinkedHashMap<String, String> = linkedMapOf(
        "ANDROID_PROJECT_NAME" to name,
        "ANDROID_OPERATION" to value.operation.name,
        "ANDROID_COUNT_TARGET" to value.countTarget.name,
        "ANDROID_COMPARE_SOURCE" to value.compareSource.name,
        "ANDROID_COMPARE_DESTINATION" to value.compareDestination.name,
        "ANDROID_BACKUP_NAME" to value.backupName,
        "ANDROID_SOURCE_BACKUP_NAME" to value.sourceBackupName,
        "ANDROID_DESTINATION_BACKUP_NAME" to value.destinationBackupName,
        "SRC_IMAP_HOST" to value.source.host,
        "SRC_IMAP_USERNAME" to value.source.username,
        "ANDROID_SRC_AUTHENTICATION" to value.source.authentication.name,
        "ANDROID_SRC_OAUTH_ACCOUNT_ID" to value.source.oauthAccountId,
        "DEST_IMAP_HOST" to value.destination.host,
        "DEST_IMAP_USERNAME" to value.destination.username,
        "ANDROID_DEST_AUTHENTICATION" to value.destination.authentication.name,
        "ANDROID_DEST_OAUTH_ACCOUNT_ID" to value.destination.oauthAccountId,
        "MIGRATE_ONLY_FOLDER" to value.options.folder,
        "MAX_WORKERS" to value.options.workers.toString(),
        "BATCH_SIZE" to value.options.batchSize.toString(),
        "DELETE_FROM_SOURCE" to value.options.deleteSource.toString(),
        "DEST_DELETE" to value.options.deleteOrphans.toString(),
        "PRESERVE_FLAGS" to value.options.preserveFlags.toString(),
        "PRESERVE_LABELS" to value.options.preserveLabels.toString(),
        "GMAIL_MODE" to value.options.gmailMode.toString(),
        "MANIFEST_ONLY" to value.options.manifestOnly.toString(),
        "APPLY_LABELS" to value.options.applyLabels.toString(),
        "APPLY_FLAGS" to value.options.applyFlags.toString(),
        "FULL_RESTORE" to value.options.fullRestore.toString(),
        "FULL_MIGRATE" to value.options.fullMigrate.toString(),
        "DEST_FOLDER_PREFIX" to value.options.destinationFolderPrefix,
        "DEST_FOLDER_SEP" to value.options.destinationFolderSeparator,
    )

    fun decode(values: Map<String, String>): AppConfiguration {
        fun account(prefix: String, authenticationKey: String, accountIdKey: String): AccountState {
            val username = values["${prefix}_IMAP_USERNAME"].orEmpty()
            val authentication = enum(values[authenticationKey], Authentication.PASSWORD)
            return AccountState(
                host = values["${prefix}_IMAP_HOST"].orEmpty(),
                username = username,
                authentication = authentication,
                oauthAccountId = values[accountIdKey].orEmpty(),
                oauthEmail = if (authentication == Authentication.PASSWORD) "" else username,
            )
        }
        val defaults = OperationOptions()
        return AppConfiguration(
            operation = enum(values["ANDROID_OPERATION"], Operation.COUNT),
            source = account("SRC", "ANDROID_SRC_AUTHENTICATION", "ANDROID_SRC_OAUTH_ACCOUNT_ID"),
            destination = account("DEST", "ANDROID_DEST_AUTHENTICATION", "ANDROID_DEST_OAUTH_ACCOUNT_ID"),
            countTarget = enum(values["ANDROID_COUNT_TARGET"], TargetType.SOURCE_ACCOUNT),
            compareSource = enum(values["ANDROID_COMPARE_SOURCE"], TargetType.SOURCE_ACCOUNT),
            compareDestination = enum(values["ANDROID_COMPARE_DESTINATION"], TargetType.DESTINATION_ACCOUNT),
            backupName = values["ANDROID_BACKUP_NAME"] ?: "default",
            sourceBackupName = values["ANDROID_SOURCE_BACKUP_NAME"] ?: "source",
            destinationBackupName = values["ANDROID_DESTINATION_BACKUP_NAME"] ?: "destination",
            options = OperationOptions(
                folder = values["MIGRATE_ONLY_FOLDER"].orEmpty(),
                workers = positiveInt(values["MAX_WORKERS"], defaults.workers),
                batchSize = positiveInt(values["BATCH_SIZE"], defaults.batchSize),
                deleteSource = boolean(values["DELETE_FROM_SOURCE"], defaults.deleteSource),
                deleteOrphans = boolean(values["DEST_DELETE"], defaults.deleteOrphans),
                preserveFlags = boolean(values["PRESERVE_FLAGS"], defaults.preserveFlags),
                preserveLabels = boolean(values["PRESERVE_LABELS"], defaults.preserveLabels),
                gmailMode = boolean(values["GMAIL_MODE"], defaults.gmailMode),
                manifestOnly = boolean(values["MANIFEST_ONLY"], defaults.manifestOnly),
                applyLabels = boolean(values["APPLY_LABELS"], defaults.applyLabels),
                applyFlags = boolean(values["APPLY_FLAGS"], defaults.applyFlags),
                fullRestore = boolean(values["FULL_RESTORE"], defaults.fullRestore),
                fullMigrate = boolean(values["FULL_MIGRATE"], defaults.fullMigrate),
                destinationFolderPrefix = values["DEST_FOLDER_PREFIX"].orEmpty(),
                destinationFolderSeparator = values["DEST_FOLDER_SEP"].orEmpty(),
            ),
        )
    }

    private fun positiveInt(value: String?, default: Int): Int = value?.toIntOrNull()?.takeIf { it > 0 } ?: default

    private fun boolean(value: String?, default: Boolean): Boolean = value?.toBooleanStrictOrNull() ?: default

    private inline fun <reified T : Enum<T>> enum(value: String?, default: T): T =
        runCatching { enumValueOf<T>(value.orEmpty()) }.getOrDefault(default)
}

internal object DotenvCodec {
    fun read(file: File): Map<String, String> {
        if (!file.isFile) return emptyMap()
        return file.readLines().mapNotNull { line ->
            val content = line.trim()
            if (content.isEmpty() || content.startsWith("#")) return@mapNotNull null
            val separator = content.indexOf('=')
            if (separator <= 0) return@mapNotNull null
            val key = content.substring(0, separator).trim()
            val raw = content.substring(separator + 1).trim()
            key to unquote(raw)
        }.toMap()
    }

    fun write(file: File, values: Map<String, String>) {
        file.parentFile?.mkdirs()
        val temporary = File(file.parentFile, ".${file.name}.tmp")
        temporary.writeText(
            buildString {
                appendLine("# IMAP Migration Tools Android project")
                values.forEach { (key, value) -> appendLine("$key=${quote(value)}") }
            },
        )
        if (!temporary.renameTo(file)) {
            file.writeText(temporary.readText())
            temporary.delete()
        }
    }

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { character ->
            when (character) {
                '\\' -> append("\\\\")
                '"' -> append("\\\"")
                '\n' -> append("\\n")
                else -> append(character)
            }
        }
        append('"')
    }

    private fun unquote(value: String): String {
        if (value.length < 2 || value.first() != '"' || value.last() != '"') return value
        return buildString {
            var escaped = false
            value.substring(1, value.lastIndex).forEach { character ->
                if (escaped) {
                    append(if (character == 'n') '\n' else character)
                    escaped = false
                } else if (character == '\\') {
                    escaped = true
                } else {
                    append(character)
                }
            }
            if (escaped) append('\\')
        }
    }
}
