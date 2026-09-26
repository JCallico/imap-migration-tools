package com.callicode.imaptools.model

enum class Operation(val title: String) {
    COUNT("Count"),
    COMPARE("Compare"),
    BACKUP("Backup"),
    RESTORE("Restore"),
    MIGRATE("Migrate"),
}

enum class Authentication(val title: String) {
    PASSWORD("Password"),
    GOOGLE("Google"),
    MICROSOFT("Microsoft"),
}

enum class AccountSlot { SOURCE, DESTINATION }

enum class TargetType { SOURCE_ACCOUNT, DESTINATION_ACCOUNT, LOCAL_BACKUP }

data class ProjectProfile(val id: String, val name: String)

data class AccountState(
    val host: String = "",
    val username: String = "",
    val authentication: Authentication = Authentication.PASSWORD,
    val password: String = "",
    val oauthAccountId: String = "",
    val oauthEmail: String = "",
    val oauthAccessToken: String = "",
)

data class OperationOptions(
    val folder: String = "",
    val workers: Int = 4,
    val batchSize: Int = 10,
    val deleteSource: Boolean = false,
    val deleteOrphans: Boolean = false,
    val preserveFlags: Boolean = false,
    val preserveLabels: Boolean = false,
    val gmailMode: Boolean = false,
    val manifestOnly: Boolean = false,
    val applyLabels: Boolean = false,
    val applyFlags: Boolean = false,
    val fullRestore: Boolean = false,
    val fullMigrate: Boolean = false,
    val destinationFolderPrefix: String = "",
    val destinationFolderSeparator: String = "",
)

data class AppConfiguration(
    val operation: Operation = Operation.COUNT,
    val source: AccountState = AccountState(),
    val destination: AccountState = AccountState(),
    val countTarget: TargetType = TargetType.SOURCE_ACCOUNT,
    val compareSource: TargetType = TargetType.SOURCE_ACCOUNT,
    val compareDestination: TargetType = TargetType.DESTINATION_ACCOUNT,
    val backupName: String = "default",
    val sourceBackupName: String = "source",
    val destinationBackupName: String = "destination",
    val options: OperationOptions = OperationOptions(),
)

data class OperationEvent(
    val operation: String,
    val phase: String,
    val message: String,
    val severity: String = "info",
    val folder: String? = null,
    val current: Int? = null,
    val total: Int? = null,
)

enum class RunStatus { IDLE, RUNNING, SUCCEEDED, FAILED, CANCELLED }

data class OperationState(
    val status: RunStatus = RunStatus.IDLE,
    val operation: Operation? = null,
    val events: List<OperationEvent> = emptyList(),
    val result: String? = null,
    val error: String? = null,
)

sealed interface BackupEstimateState {
    data object Idle : BackupEstimateState

    data class Estimating(val availableBytes: Long) : BackupEstimateState

    data class Ready(
        val estimatedBytes: Long,
        val messageCount: Int,
        val availableBytes: Long,
        val requiredBytes: Long,
    ) : BackupEstimateState {
        val hasEnoughSpace: Boolean = requiredBytes <= availableBytes
    }

    data class Unavailable(val availableBytes: Long, val reason: String) : BackupEstimateState
}
