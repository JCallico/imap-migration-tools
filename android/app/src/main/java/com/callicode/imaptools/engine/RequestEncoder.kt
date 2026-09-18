package com.callicode.imaptools.engine

import com.callicode.imaptools.BuildConfig
import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AccountSlot
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.TargetType
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

object RequestEncoder {
    fun encode(configuration: AppConfiguration, workspaceRoot: File): String {
        val backupPath = File(workspaceRoot, safeBackupName(configuration.backupName)).absolutePath
        val sourceBackupPath = File(workspaceRoot, safeBackupName(configuration.sourceBackupName)).absolutePath
        val destinationBackupPath = File(workspaceRoot, safeBackupName(configuration.destinationBackupName)).absolutePath
        val request = JSONObject().put("operation", configuration.operation.name.lowercase())
        val options = configuration.options
        request.put(
            "options",
            JSONObject()
                .putOptional("folder", options.folder)
                .put("workers", options.workers)
                .put("batchSize", options.batchSize)
                .put("deleteSource", options.deleteSource)
                .put("deleteOrphans", options.deleteOrphans)
                .put("preserveFlags", options.preserveFlags)
                .put("preserveLabels", options.preserveLabels)
                .put("gmailMode", options.gmailMode)
                .put("manifestOnly", options.manifestOnly)
                .put("applyLabels", options.applyLabels)
                .put("applyFlags", options.applyFlags)
                .put("fullRestore", options.fullRestore)
                .put("fullMigrate", options.fullMigrate)
                .putOptional("destinationFolderPrefix", options.destinationFolderPrefix)
                .putOptional("destinationFolderSeparator", options.destinationFolderSeparator)
                .put("cachePath", migrationCachePath(workspaceRoot, configuration)),
        )
        when (configuration.operation) {
            Operation.COUNT -> request.put(
                "target",
                target(configuration.countTarget, configuration, backupPath),
            )
            Operation.COMPARE -> {
                request.put("source", target(configuration.compareSource, configuration, sourceBackupPath))
                request.put("destination", target(configuration.compareDestination, configuration, destinationBackupPath))
            }
            Operation.BACKUP -> {
                request.put("source", account(configuration.source, AccountSlot.SOURCE))
                request.put("backupPath", backupPath)
            }
            Operation.RESTORE -> {
                request.put("destination", account(configuration.destination, AccountSlot.DESTINATION))
                request.put("backupPath", backupPath)
            }
            Operation.MIGRATE -> {
                request.put("source", account(configuration.source, AccountSlot.SOURCE))
                request.put("destination", account(configuration.destination, AccountSlot.DESTINATION))
            }
        }
        return request.toString()
    }

    fun safeBackupName(value: String): String {
        val sanitized = value.trim().replace(Regex("[^A-Za-z0-9._-]"), "_").trim('.', '_')
        return sanitized.ifEmpty { "default" }
    }

    private fun target(type: TargetType, configuration: AppConfiguration, backupPath: String): JSONObject =
        when (type) {
            TargetType.LOCAL_BACKUP -> JSONObject().put("kind", "local").put("path", backupPath)
            TargetType.SOURCE_ACCOUNT -> JSONObject().put("kind", "imap")
                .put("account", account(configuration.source, AccountSlot.SOURCE))
            TargetType.DESTINATION_ACCOUNT ->
                JSONObject().put("kind", "imap")
                    .put("account", account(configuration.destination, AccountSlot.DESTINATION))
        }

    private fun account(value: AccountState, slot: AccountSlot): JSONObject =
        JSONObject()
            .put("host", value.host.trim())
            .put("username", value.username.trim())
            .put("tokenSlot", slot.name.lowercase())
            .put("oauthAccountId", value.oauthAccountId)
            .apply {
            when (value.authentication) {
                Authentication.PASSWORD -> put("password", value.password)
                Authentication.GOOGLE, Authentication.MICROSOFT -> put(
                    "oauth2",
                    JSONObject()
                        .put(
                            "clientId",
                            if (value.authentication == Authentication.MICROSOFT) {
                                BuildConfig.MICROSOFT_CLIENT_ID
                            } else {
                                "android-google-identity-services"
                            },
                        )
                        .put("accessToken", value.oauthAccessToken)
                        .put(
                            "provider",
                            if (value.authentication == Authentication.GOOGLE) "google" else "microsoft",
                        )
                        .put("accountType", "auto"),
                )
            }
            }

    private fun migrationCachePath(workspaceRoot: File, configuration: AppConfiguration): String {
        val identity = listOf(
            configuration.source.host,
            configuration.source.username,
            configuration.destination.host,
            configuration.destination.username,
        ).joinToString("\u0000") { it.trim().lowercase() }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(identity.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        return File(workspaceRoot, ".migration-cache/${digest.take(24)}").absolutePath
    }

    private fun JSONObject.putOptional(name: String, value: String): JSONObject = apply {
        if (value.isNotBlank()) put(name, value)
    }
}
