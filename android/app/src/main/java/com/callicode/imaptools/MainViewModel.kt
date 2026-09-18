package com.callicode.imaptools

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.callicode.imaptools.auth.SilentTokenProvider
import com.callicode.imaptools.engine.BackupEstimateResult
import com.callicode.imaptools.engine.CancellationSignal
import com.callicode.imaptools.engine.PythonEngine
import com.callicode.imaptools.engine.RequestEncoder
import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AccountSlot
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.BackupEstimateState
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationEvent
import com.callicode.imaptools.model.OperationOptions
import com.callicode.imaptools.model.ProjectProfile
import com.callicode.imaptools.model.TargetType
import com.callicode.imaptools.operation.HistoryEntry
import com.callicode.imaptools.operation.HistoryStore
import com.callicode.imaptools.operation.OperationBus
import com.callicode.imaptools.operation.OperationService
import com.callicode.imaptools.project.ProjectStore
import com.callicode.imaptools.storage.StorageCapacity
import com.callicode.imaptools.storage.WorkspaceArchive
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Collections
import java.util.Locale

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val preferences = application.getSharedPreferences("configuration", 0)
    private val projectStore = ProjectStore(File(application.filesDir, "projects"), preferences)
    private val initialProject = projectStore.initialize(loadLegacy())
    private val projectMemory = mutableMapOf(initialProject.first.id to initialProject.second)
    private val mutableProjects = MutableStateFlow(projectStore.projects())
    val projects = mutableProjects.asStateFlow()
    private val mutableActiveProject = MutableStateFlow(initialProject.first)
    val activeProject = mutableActiveProject.asStateFlow()
    private val mutableConfiguration = MutableStateFlow(initialProject.second)
    val configuration = mutableConfiguration.asStateFlow()
    private val workspaceBaseRoot = File(application.filesDir, "backups").apply { mkdirs() }
    private val pendingSaves = Channel<Pair<ProjectProfile, AppConfiguration>>(Channel.UNLIMITED)
    private val deletedProjects = Collections.synchronizedSet(mutableSetOf<String>())
    private val mutableStorageMessage = MutableStateFlow<String?>(null)
    val storageMessage = mutableStorageMessage.asStateFlow()
    private val mutableAuthenticationBusy = MutableStateFlow(false)
    val authenticationBusy = mutableAuthenticationBusy.asStateFlow()
    private val mutableAuthenticationMessage = MutableStateFlow<String?>(null)
    val authenticationMessage = mutableAuthenticationMessage.asStateFlow()
    private val mutableBackupEstimate = MutableStateFlow<BackupEstimateState>(BackupEstimateState.Idle)
    val backupEstimate = mutableBackupEstimate.asStateFlow()
    private var estimateJob: Job? = null
    private var estimateCancellation: CancellationSignal? = null

    init {
        migrateLegacyWorkspaces(initialProject.first.id)
        viewModelScope.launch(Dispatchers.IO) {
            for ((project, configuration) in pendingSaves) {
                if (project.id in deletedProjects) continue
                runCatching { projectStore.save(project, configuration) }
                    .onFailure { mutableStorageMessage.value = it.message ?: "Unable to save project configuration" }
            }
        }
        viewModelScope.launch {
            OperationBus.state.collect { state ->
                if (state.operation == Operation.BACKUP &&
                    state.status !in setOf(
                        com.callicode.imaptools.model.RunStatus.IDLE,
                        com.callicode.imaptools.model.RunStatus.RUNNING,
                    ) && mutableBackupEstimate.value is BackupEstimateState.Estimating
                ) {
                    cancelBackupEstimate()
                }
            }
        }
    }

    fun update(transform: (AppConfiguration) -> AppConfiguration) {
        if (operationRunning()) return
        mutableConfiguration.value = transform(mutableConfiguration.value)
        projectMemory[mutableActiveProject.value.id] = mutableConfiguration.value
        pendingSaves.trySend(mutableActiveProject.value to mutableConfiguration.value)
    }

    fun createProject(name: String): String? {
        if (operationRunning()) return "Wait for the current operation to finish"
        val normalized = name.trim()
        if (normalized.isEmpty()) return "Project name is required"
        if (normalized.length > 60) return "Project name must be 60 characters or fewer"
        if (normalized.any { it == '\n' || it == '\r' }) return "Project name must be a single line"
        if (mutableProjects.value.any { it.name.equals(normalized, ignoreCase = true) }) {
            return "A project named $normalized already exists"
        }
        val created = projectStore.create(normalized)
        projectMemory[created.first.id] = created.second
        mutableProjects.value = projectStore.projects()
        mutableActiveProject.value = created.first
        mutableConfiguration.value = created.second
        return null
    }

    fun selectProject(project: ProjectProfile) {
        if (operationRunning()) return
        if (project.id == mutableActiveProject.value.id) return
        projectStore.select(project)
        val configuration = projectMemory[project.id] ?: projectStore.load(project)
        projectMemory[project.id] = configuration
        mutableActiveProject.value = project
        mutableConfiguration.value = configuration
    }

    fun deleteActiveProject(): String? {
        if (operationRunning()) return "Wait for the current operation to finish"
        if (mutableProjects.value.size <= 1) return "At least one project is required"
        val deleting = mutableActiveProject.value
        deletedProjects += deleting.id
        projectStore.delete(deleting)
        projectMemory.remove(deleting.id)
        val remaining = projectStore.projects()
        val replacement = remaining.first()
        projectStore.select(replacement)
        val configuration = projectMemory[replacement.id] ?: projectStore.load(replacement)
        projectMemory[replacement.id] = configuration
        mutableProjects.value = remaining
        mutableActiveProject.value = replacement
        mutableConfiguration.value = configuration
        return null
    }

    fun run(estimateInProgress: Boolean = false): String? {
        val configuration = mutableConfiguration.value
        val error = readinessError(configuration)
        if (error != null) return error
        if (configuration.operation == Operation.BACKUP &&
            StorageCapacity.availableBytes(getApplication(), activeWorkspaceRoot()) < StorageCapacity.RESERVED_BYTES
        ) {
            return "At least ${formatBytes(StorageCapacity.RESERVED_BYTES)} of available storage is required to start a backup"
        }
        val started = OperationService.start(
            getApplication(),
            configuration.operation,
            RequestEncoder.encode(configuration, activeWorkspaceRoot()),
            estimateInProgress,
        )
        return if (started) null else "Another operation is already starting"
    }

    fun startBackupEstimate(): String? {
        if (operationRunning()) return "Wait for the current operation to finish"
        val configuration = mutableConfiguration.value
        val readinessError = readinessError(configuration)
        if (readinessError != null) return readinessError
        if (configuration.operation != Operation.BACKUP) return "Storage estimation is only available for backups"

        estimateCancellation?.cancel()
        estimateJob?.cancel()
        val request = RequestEncoder.encode(configuration, activeWorkspaceRoot())
        val available = StorageCapacity.availableBytes(getApplication(), activeWorkspaceRoot())
        val cancellation = CancellationSignal()
        estimateCancellation = cancellation
        mutableBackupEstimate.value = BackupEstimateState.Estimating(available)
        estimateJob = viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                PythonEngine().estimateBackup(
                    request,
                    cancellation,
                    SilentTokenProvider(getApplication(), request),
                )
            }.getOrElse { BackupEstimateResult.Failed(it.message ?: "Storage estimate unavailable") }
            if (estimateCancellation !== cancellation) return@launch
            val currentAvailable = StorageCapacity.availableBytes(getApplication(), activeWorkspaceRoot())
            val state = when (result) {
                is BackupEstimateResult.Ready -> BackupEstimateState.Ready(
                    estimatedBytes = result.estimatedBytes,
                    messageCount = result.messageCount,
                    availableBytes = currentAvailable,
                    requiredBytes = StorageCapacity.requiredBytes(result.estimatedBytes),
                )
                is BackupEstimateResult.Failed -> BackupEstimateState.Unavailable(currentAvailable, result.message)
                BackupEstimateResult.Cancelled -> BackupEstimateState.Idle
            }
            mutableBackupEstimate.value = state
            publishEstimateToRunningBackup(state)
        }
        return null
    }

    fun cancelBackupEstimate() {
        estimateCancellation?.cancel()
        estimateJob?.cancel()
        estimateCancellation = null
        estimateJob = null
        mutableBackupEstimate.value = BackupEstimateState.Idle
    }

    fun setAuthenticationBusy(busy: Boolean) {
        mutableAuthenticationBusy.value = busy
    }

    fun recoverInterruptedAuthentication() {
        if (!mutableAuthenticationBusy.value) return
        mutableAuthenticationBusy.value = false
        mutableAuthenticationMessage.value = "Authentication was interrupted. Please try again."
    }

    fun reportAuthenticationMessage(message: String) {
        mutableAuthenticationBusy.value = false
        mutableAuthenticationMessage.value = message
    }

    fun clearAuthenticationMessage() {
        mutableAuthenticationMessage.value = null
    }

    fun updateOAuthAccount(slot: AccountSlot, email: String, accountId: String, accessToken: String) {
        update { configuration ->
            val current = account(configuration, slot)
            val host = when (current.authentication) {
                Authentication.GOOGLE -> "imap.gmail.com"
                Authentication.MICROSOFT -> "outlook.office365.com"
                Authentication.PASSWORD -> current.host
            }
            configuration.withAccount(
                slot,
                current.copy(
                    host = host,
                    username = email,
                    oauthEmail = email,
                    oauthAccountId = accountId,
                    oauthAccessToken = accessToken,
                ),
            )
        }
    }

    fun updateOAuthToken(slot: AccountSlot, accessToken: String) {
        update { configuration ->
            val current = account(configuration, slot)
            configuration.withAccount(slot, current.copy(oauthAccessToken = accessToken))
        }
    }

    fun clearOAuthAccount(slot: AccountSlot) {
        update { configuration ->
            val current = account(configuration, slot)
            configuration.withAccount(
                slot,
                current.copy(username = "", oauthEmail = "", oauthAccountId = "", oauthAccessToken = ""),
            )
        }
    }

    fun oauthAccountReferenceCount(account: AccountState): Int = mutableProjects.value.sumOf { project ->
        val configuration = projectMemory[project.id] ?: projectStore.load(project)
        listOf(configuration.source, configuration.destination).count {
            it.authentication == account.authentication &&
                it.oauthAccountId.isNotBlank() &&
                it.oauthAccountId == account.oauthAccountId
        }
    }

    fun cancel() = OperationService.cancel(getApplication())

    fun history(): List<HistoryEntry> = HistoryStore(getApplication()).entries()

    fun exportWorkspace(name: String, destination: Uri) = archive("Backup exported") {
        export(RequestEncoder.safeBackupName(name), destination)
    }

    fun importWorkspace(name: String, source: Uri) = archive("Backup imported") {
        import(RequestEncoder.safeBackupName(name), source)
    }

    fun clearStorageMessage() {
        mutableStorageMessage.value = null
    }

    private fun archive(success: String, action: WorkspaceArchive.() -> Unit) {
        viewModelScope.launch {
            mutableStorageMessage.value = withContext(Dispatchers.IO) {
                runCatching {
                    WorkspaceArchive(getApplication<Application>().contentResolver, activeWorkspaceRoot()).action()
                    success
                }.getOrElse { it.message ?: "Storage operation failed" }
            }
        }
    }

    fun readinessError(
        value: AppConfiguration = mutableConfiguration.value,
        requireOAuthToken: Boolean = true,
    ): String? {
        fun accountError(label: String, account: AccountState): String? {
            if (account.host.isBlank()) return "$label IMAP host is required"
            if (account.username.isBlank()) return "$label username is required"
            if (account.authentication == Authentication.PASSWORD && account.password.isBlank()) {
                return "$label password is required"
            }
            if (account.authentication != Authentication.PASSWORD && account.oauthAccountId.isBlank()) {
                return "$label ${account.authentication.title} account is not connected"
            }
            if (requireOAuthToken &&
                account.authentication != Authentication.PASSWORD &&
                account.oauthAccessToken.isBlank()
            ) {
                return "$label ${account.authentication.title} session is not ready"
            }
            return null
        }

        fun targetError(label: String, target: TargetType, localName: String = value.backupName): String? = when (target) {
            TargetType.SOURCE_ACCOUNT -> accountError(label, value.source)
            TargetType.DESTINATION_ACCOUNT -> accountError(label, value.destination)
            TargetType.LOCAL_BACKUP -> if (!File(activeWorkspaceRoot(), RequestEncoder.safeBackupName(localName)).isDirectory) {
                "Local backup does not exist"
            } else null
        }

        return when (value.operation) {
            Operation.COUNT -> targetError("Target", value.countTarget)
            Operation.COMPARE -> targetError("Source", value.compareSource, value.sourceBackupName)
                ?: targetError("Destination", value.compareDestination, value.destinationBackupName)
            Operation.BACKUP -> accountError("Source", value.source)
            Operation.RESTORE -> targetError("Backup", TargetType.LOCAL_BACKUP)
                ?: accountError("Destination", value.destination)
            Operation.MIGRATE -> accountError("Source", value.source) ?: accountError("Destination", value.destination)
        }
    }

    private fun loadLegacy(): AppConfiguration {
        fun account(prefix: String) = AccountState(
            host = preferences.getString("${prefix}_host", "").orEmpty(),
            username = preferences.getString("${prefix}_username", "").orEmpty(),
            authentication = enumValueOrDefault(
                preferences.getString("${prefix}_authentication", null),
                Authentication.PASSWORD,
            ),
            oauthAccountId = preferences.getString("${prefix}_oauth_account_id", "").orEmpty(),
            oauthEmail = preferences.getString("${prefix}_oauth_email", "").orEmpty(),
        )
        val options = OperationOptions(
            folder = preferences.getString("folder", "").orEmpty(),
            workers = preferences.getInt("workers", 4),
            batchSize = preferences.getInt("batch", 10),
            deleteSource = preferences.getBoolean("delete_source", false),
            deleteOrphans = preferences.getBoolean("delete_orphans", false),
            preserveFlags = preferences.getBoolean("preserve_flags", false),
            preserveLabels = preferences.getBoolean("preserve_labels", false),
            gmailMode = preferences.getBoolean("gmail_mode", false),
            manifestOnly = preferences.getBoolean("manifest_only", false),
            applyLabels = preferences.getBoolean("apply_labels", false),
            applyFlags = preferences.getBoolean("apply_flags", false),
            fullRestore = preferences.getBoolean("full_restore", false),
            fullMigrate = preferences.getBoolean("full_migrate", false),
            destinationFolderPrefix = preferences.getString("destination_prefix", "").orEmpty(),
            destinationFolderSeparator = preferences.getString("destination_separator", "").orEmpty(),
        )
        return AppConfiguration(
            operation = enumValueOrDefault(preferences.getString("operation", null), Operation.COUNT),
            source = account("source"),
            destination = account("destination"),
            countTarget = enumValueOrDefault(preferences.getString("count_target", null), TargetType.SOURCE_ACCOUNT),
            compareSource = enumValueOrDefault(
                preferences.getString("compare_source", null),
                TargetType.SOURCE_ACCOUNT,
            ),
            compareDestination = enumValueOrDefault(
                preferences.getString("compare_destination", null),
                TargetType.DESTINATION_ACCOUNT,
            ),
            backupName = preferences.getString("backup_name", "default").orEmpty(),
            sourceBackupName = preferences.getString("source_backup_name", "source").orEmpty(),
            destinationBackupName = preferences.getString("destination_backup_name", "destination").orEmpty(),
            options = options,
        )
    }

    private fun activeWorkspaceRoot(): File =
        File(workspaceBaseRoot, mutableActiveProject.value.id).apply { mkdirs() }

    private fun migrateLegacyWorkspaces(projectId: String) {
        if (preferences.getBoolean(LEGACY_WORKSPACES_MIGRATED, false)) return
        val legacyEntries = workspaceBaseRoot.listFiles().orEmpty()
        val projectRoot = File(workspaceBaseRoot, projectId).apply { mkdirs() }
        legacyEntries.filter { it != projectRoot }.forEach { entry ->
            val destination = File(projectRoot, entry.name)
            if (!destination.exists()) entry.renameTo(destination)
        }
        preferences.edit().putBoolean(LEGACY_WORKSPACES_MIGRATED, true).apply()
    }

    fun operationRunning(): Boolean =
        OperationBus.state.value.status == com.callicode.imaptools.model.RunStatus.RUNNING

    private fun publishEstimateToRunningBackup(state: BackupEstimateState) {
        val message = when (state) {
            is BackupEstimateState.Ready ->
                "Storage estimate: ${formatBytes(state.estimatedBytes)} for ${state.messageCount} messages; " +
                    "${formatBytes(state.availableBytes)} available."
            is BackupEstimateState.Unavailable -> "Storage estimate unavailable: ${state.reason}"
            else -> return
        }
        var backupRunning = false
        OperationBus.update { operationState ->
            if (operationState.status != com.callicode.imaptools.model.RunStatus.RUNNING ||
                operationState.operation != Operation.BACKUP
            ) {
                operationState
            } else {
                backupRunning = true
                operationState.copy(
                    events = operationState.events + OperationEvent(
                        operation = "backup",
                        phase = "storage",
                        message = message,
                        severity = if (state is BackupEstimateState.Ready && !state.hasEnoughSpace) "warning" else "info",
                    ),
                )
            }
        }
        if (backupRunning && state is BackupEstimateState.Ready && !state.hasEnoughSpace) {
            OperationService.stopForInsufficientEstimate(
                getApplication(),
                "Backup stopped because the estimate requires ${formatBytes(state.requiredBytes)}, but only " +
                    "${formatBytes(state.availableBytes)} is available.",
            )
        }
    }

    override fun onCleared() {
        cancelBackupEstimate()
        super.onCleared()
    }

    private inline fun <reified T : Enum<T>> enumValueOrDefault(value: String?, default: T): T =
        runCatching { enumValueOf<T>(value.orEmpty()) }.getOrDefault(default)

    private fun account(configuration: AppConfiguration, slot: AccountSlot): AccountState = when (slot) {
        AccountSlot.SOURCE -> configuration.source
        AccountSlot.DESTINATION -> configuration.destination
    }

    private fun AppConfiguration.withAccount(slot: AccountSlot, account: AccountState): AppConfiguration = when (slot) {
        AccountSlot.SOURCE -> copy(source = account)
        AccountSlot.DESTINATION -> copy(destination = account)
    }

    companion object {
        private const val LEGACY_WORKSPACES_MIGRATED = "legacy_workspaces_migrated"

        fun formatBytes(bytes: Long): String {
            if (bytes < 1024L) return "$bytes B"
            val units = arrayOf("KB", "MB", "GB", "TB")
            var value = bytes.toDouble()
            var unit = -1
            do {
                value /= 1024.0
                unit += 1
            } while (value >= 1024.0 && unit < units.lastIndex)
            return if (value >= 10.0) {
                String.format(Locale.ROOT, "%.0f %s", value, units[unit])
            } else {
                String.format(Locale.ROOT, "%.1f %s", value, units[unit])
            }
        }
    }
}
