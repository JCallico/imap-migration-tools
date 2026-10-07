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

/**
 * Projects are `.env` files: `default` is `.env` and every other project is `<name>.env` in [root].
 * The same layout is used by the desktop terminal and GUI applications.
 */
class ProjectStore(
    private val root: File,
    private val preferences: SharedPreferences,
) {
    /** Legacy `<uuid>/.env` directories converted during [initialize], keyed by their former identifier. */
    var migratedProjects: Map<String, ProjectProfile> = emptyMap()
        private set

    @Synchronized
    fun initialize(legacyConfiguration: AppConfiguration): Pair<ProjectProfile, AppConfiguration> {
        root.mkdirs()
        migratedProjects = migrateLegacyDirectories()
        val default = ProjectProfile.DEFAULT
        if (!envFile(default).isFile && migratedProjects.isEmpty() && named().isEmpty()) {
            save(default, legacyConfiguration)
        }
        val legacyActive = preferences.getString(LEGACY_ACTIVE_PROJECT, null)?.let { migratedProjects[it]?.name }
        val remembered = preferences.getString(ACTIVE_PROJECT, null) ?: legacyActive
        val active = projects().firstOrNull { it.name == remembered } ?: default
        select(active)
        return active to load(active)
    }

    fun projects(): List<ProjectProfile> = listOf(ProjectProfile.DEFAULT) + named()

    private fun named(): List<ProjectProfile> = root.listFiles()
        .orEmpty()
        .filter { it.isFile && it.name.endsWith(ENV_SUFFIX) && it.name != ENV_FILE && !it.name.startsWith(".") }
        .map { ProjectProfile(it.name.removeSuffix(ENV_SUFFIX)) }
        .sortedBy { it.name.lowercase() }

    @Synchronized
    fun create(name: String, configuration: AppConfiguration = AppConfiguration()): Pair<ProjectProfile, AppConfiguration> {
        val project = ProjectProfile(available(ProjectNames.validate(name)))
        check(envFile(project).createNewFile()) { "A project named ${project.name} already exists" }
        save(project, configuration)
        select(project)
        return project to configuration
    }

    @Synchronized
    fun rename(project: ProjectProfile, name: String): ProjectProfile {
        require(!project.isDefault) { "The default project cannot be renamed" }
        val normalized = ProjectNames.validate(name)
        if (normalized == project.name) return project
        val renamed = ProjectProfile(available(normalized, ignore = project))
        val source = envFile(project)
        val target = envFile(renamed)
        check(source.isFile) { "The ${project.name} project file no longer exists" }
        check(!target.exists() || target.canonicalPath == source.canonicalPath) {
            "A project named ${renamed.name} already exists"
        }
        check(source.renameTo(target)) { "Unable to rename the project" }
        if (preferences.getString(ACTIVE_PROJECT, null) == project.name) select(renamed)
        return renamed
    }

    /** Undo a [rename] whose dependent storage could not follow the new name. */
    @Synchronized
    fun revertRename(renamed: ProjectProfile, original: ProjectProfile) {
        check(envFile(renamed).renameTo(envFile(original))) { "Unable to restore the project name" }
        if (preferences.getString(ACTIVE_PROJECT, null) == renamed.name) select(original)
    }

    fun load(project: ProjectProfile): AppConfiguration =
        ProjectConfigurationCodec.decode(DotenvCodec.read(envFile(project)))

    @Synchronized
    fun save(project: ProjectProfile, configuration: AppConfiguration) {
        DotenvCodec.write(envFile(project), ProjectConfigurationCodec.encode(configuration))
    }

    /** Save only while [current] still holds, so a queued save cannot recreate a renamed or deleted project. */
    @Synchronized
    fun saveIf(current: () -> Boolean, project: ProjectProfile, configuration: AppConfiguration) {
        if (current()) save(project, configuration)
    }

    fun select(project: ProjectProfile) {
        preferences.edit().putString(ACTIVE_PROJECT, project.name).remove(LEGACY_ACTIVE_PROJECT).apply()
    }

    @Synchronized
    fun delete(project: ProjectProfile) {
        require(!project.isDefault) { "The default project cannot be deleted" }
        envFile(project).delete()
    }

    private fun available(name: String, ignore: ProjectProfile? = null): String {
        val existing = named().firstOrNull { it.name.equals(name, ignoreCase = true) && it != ignore }
        require(existing == null) { "A project named ${existing?.name} already exists" }
        return name
    }

    private fun envFile(project: ProjectProfile) =
        File(root, if (project.isDefault) ENV_FILE else "${project.name}$ENV_SUFFIX")

    private fun migrateLegacyDirectories(): Map<String, ProjectProfile> {
        val legacy = root.listFiles().orEmpty()
            .filter { it.isDirectory && File(it, ENV_FILE).isFile }
            .sortedBy { it.name }
        val migrated = linkedMapOf<String, ProjectProfile>()
        val preferDefault = legacy.firstOrNull { directory ->
            DotenvCodec.read(File(directory, ENV_FILE))[LEGACY_PROJECT_NAME].orEmpty().trim()
                .equals(ProjectProfile.DEFAULT_NAME, ignoreCase = true)
        }
        for (directory in legacy) {
            val values = DotenvCodec.read(File(directory, ENV_FILE))
            val project = if (directory == preferDefault && !envFile(ProjectProfile.DEFAULT).exists()) {
                ProjectProfile.DEFAULT
            } else {
                ProjectProfile(uniqueMigratedName(values[LEGACY_PROJECT_NAME].orEmpty()))
            }
            DotenvCodec.write(envFile(project), values - LEGACY_PROJECT_NAME)
            File(directory, ENV_FILE).delete()
            directory.listFiles().orEmpty().forEach(File::delete)
            directory.delete()
            migrated[directory.name] = project
        }
        return migrated
    }

    private fun uniqueMigratedName(original: String): String {
        val base = ProjectNames.sanitize(original)
        var candidate = base
        var suffix = 2
        while (runCatching { ProjectNames.validate(candidate); available(candidate) }.isFailure) {
            val tail = " ($suffix)"
            candidate = base.take(ProjectNames.MAX_LENGTH - tail.length).trimEnd() + tail
            suffix += 1
        }
        return candidate
    }

    companion object {
        private const val ACTIVE_PROJECT = "active_project_name"
        private const val LEGACY_ACTIVE_PROJECT = "active_project_id"
        private const val ENV_FILE = ".env"
        private const val ENV_SUFFIX = ".env"
        private const val LEGACY_PROJECT_NAME = "ANDROID_PROJECT_NAME"
    }
}

/** Project-name rules shared with the desktop applications: names must be portable file names. */
object ProjectNames {
    const val MAX_LENGTH = 60
    private val invalidCharacters = Regex("[<>:\"/\\\\|?*\\x00-\\x1f]")
    private val windowsReserved =
        setOf("con", "prn", "aux", "nul") + (1..9).flatMap { listOf("com$it", "lpt$it") }

    fun validate(name: String): String {
        val normalized = name.trim()
        require(normalized.isNotEmpty()) { "Project name is required" }
        require(normalized.length <= MAX_LENGTH) { "Project name must be $MAX_LENGTH characters or fewer" }
        require(!invalidCharacters.containsMatchIn(normalized)) {
            "Project name cannot contain control characters or any of < > : \" / \\ | ? *"
        }
        require(!normalized.startsWith(".") && !normalized.endsWith(".")) {
            "Project name cannot start or end with a period"
        }
        val folded = normalized.lowercase()
        require(folded != ProjectProfile.DEFAULT_NAME && folded != "local") { "\"$normalized\" is reserved" }
        require(folded.substringBefore('.') !in windowsReserved) { "\"$normalized\" is reserved by Windows" }
        return normalized
    }

    /** Convert a legacy free-form name into the closest valid project name. */
    fun sanitize(name: String): String {
        val cleaned = name.replace(invalidCharacters, "_").trim().trim('.').take(MAX_LENGTH).trim()
        return when {
            cleaned.isEmpty() -> "Project"
            runCatching { validate(cleaned) }.isFailure -> "$cleaned project".take(MAX_LENGTH)
            else -> cleaned
        }
    }
}

internal object ProjectConfigurationCodec {
    fun encode(value: AppConfiguration): LinkedHashMap<String, String> = linkedMapOf(
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
        temporary.ownerOnly()
        if (!temporary.renameTo(file)) {
            file.writeText(temporary.readText())
            file.ownerOnly()
            temporary.delete()
        } else {
            file.ownerOnly()
        }
    }

    private fun File.ownerOnly() {
        setReadable(false, false)
        setWritable(false, false)
        setExecutable(false, false)
        setReadable(true, true)
        setWritable(true, true)
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
