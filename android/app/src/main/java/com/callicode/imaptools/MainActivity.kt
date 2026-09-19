package com.callicode.imaptools

import android.Manifest
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Build
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.callicode.imaptools.auth.OAuthCoordinator
import com.callicode.imaptools.model.AccountState
import com.callicode.imaptools.model.AccountSlot
import com.callicode.imaptools.model.AppConfiguration
import com.callicode.imaptools.model.Authentication
import com.callicode.imaptools.model.BackupEstimateState
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationOptions
import com.callicode.imaptools.model.ProjectProfile
import com.callicode.imaptools.model.RunStatus
import com.callicode.imaptools.model.TargetType
import com.callicode.imaptools.operation.HistoryEntry
import com.callicode.imaptools.operation.OperationBus
import com.callicode.imaptools.storage.RetainedBackupGroup
import com.callicode.imaptools.ui.components.CollapsibleTerminalPanel
import com.callicode.imaptools.ui.about.AboutPrivacyScreen
import com.callicode.imaptools.ui.components.KeyValue
import com.callicode.imaptools.ui.components.StatusIndicator
import com.callicode.imaptools.ui.components.TerminalBrand
import com.callicode.imaptools.ui.components.TerminalPanel
import com.callicode.imaptools.ui.output.ResultFormatter
import com.callicode.imaptools.ui.theme.ImapToolsTheme
import com.callicode.imaptools.ui.theme.LocalTerminalPalette

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private lateinit var oauthCoordinator: OAuthCoordinator
    private val notifications = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }
    private val googleAuthorization = registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) {
        oauthCoordinator.onGoogleAuthorizationResult(it.resultCode, it.data)
    }
    private var archiveWorkspace = "default"
    private var retainedArchiveProjectId: String? = null
    private val exportArchive = registerForActivityResult(ActivityResultContracts.CreateDocument("application/zip")) { uri ->
        uri?.let {
            val projectId = retainedArchiveProjectId
            if (projectId == null) {
                viewModel.exportWorkspace(archiveWorkspace, it)
            } else {
                viewModel.exportRetainedWorkspace(projectId, archiveWorkspace, it)
            }
        }
        retainedArchiveProjectId = null
    }
    private val importArchive = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { viewModel.importWorkspace(archiveWorkspace, it) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) viewModel.recoverInterruptedAuthentication()
        oauthCoordinator = OAuthCoordinator(this, viewModel, googleAuthorization::launch)
        if (Build.VERSION.SDK_INT >= 33) notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
        setContent {
            ImapToolsTheme {
                ImapToolsApp(
                    viewModel,
                    onExport = { name ->
                        retainedArchiveProjectId = null
                        archiveWorkspace = name
                        exportArchive.launch("${name.ifBlank { "backup" }}.zip")
                    },
                    onExportRetained = { projectId, name ->
                        retainedArchiveProjectId = projectId
                        archiveWorkspace = name
                        exportArchive.launch("${name.ifBlank { "backup" }}.zip")
                    },
                    onImport = { name ->
                        archiveWorkspace = name
                        importArchive.launch(arrayOf("application/zip", "application/octet-stream"))
                    },
                    onConnect = oauthCoordinator::connect,
                    onDisconnect = oauthCoordinator::disconnect,
                    onPrepare = oauthCoordinator::prepare,
                )
            }
        }
    }
}

private enum class Screen(val title: String) {
    CONFIGURE("Configure"),
    OUTPUT("Output"),
    HISTORY("History"),
    ABOUT("About"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ImapToolsApp(
    viewModel: MainViewModel,
    onExport: (String) -> Unit,
    onExportRetained: (String, String) -> Unit,
    onImport: (String) -> Unit,
    onConnect: (AccountSlot, Authentication, (String?) -> Unit) -> Unit,
    onDisconnect: (AccountSlot, AccountState, (String?) -> Unit) -> Unit,
    onPrepare: (AppConfiguration, (String?) -> Unit) -> Unit,
) {
    val configuration by viewModel.configuration.collectAsStateWithLifecycle()
    val operationState by OperationBus.state.collectAsStateWithLifecycle()
    val storageMessage by viewModel.storageMessage.collectAsStateWithLifecycle()
    val authenticationBusy by viewModel.authenticationBusy.collectAsStateWithLifecycle()
    val authenticationMessage by viewModel.authenticationMessage.collectAsStateWithLifecycle()
    val backupEstimate by viewModel.backupEstimate.collectAsStateWithLifecycle()
    val projects by viewModel.projects.collectAsStateWithLifecycle()
    val activeProject by viewModel.activeProject.collectAsStateWithLifecycle()
    val retainedBackups by viewModel.retainedBackups.collectAsStateWithLifecycle()
    var screen by remember { mutableStateOf(Screen.CONFIGURE) }
    var confirmation by remember { mutableStateOf(false) }
    var networkConfirmation by remember { mutableStateOf(false) }
    var allowMeteredNetwork by remember { mutableStateOf(false) }
    var backupPreflight by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf<String?>(null) }
    var selectedHistory by remember { mutableStateOf<HistoryEntry?>(null) }
    var showNewProject by remember { mutableStateOf(false) }
    var newProjectName by remember { mutableStateOf("") }
    var confirmProjectDeletion by remember { mutableStateOf(false) }
    var projectBackupsForDeletion by remember { mutableStateOf(emptyList<String>()) }
    var showRetainedBackups by remember { mutableStateOf(false) }
    var retainedBackupToDelete by remember { mutableStateOf<Pair<String, String>?>(null) }
    val snackbar = remember { SnackbarHostState() }
    val context = LocalContext.current
    val uriHandler = LocalUriHandler.current
    val launchOperation: (Boolean) -> Unit = { estimateInProgress ->
        message = viewModel.run(estimateInProgress, allowMeteredNetwork)
        if (message == null) {
            selectedHistory = null
            screen = Screen.OUTPUT
        } else if (estimateInProgress) {
            viewModel.cancelBackupEstimate()
        }
    }
    val prepareOperation: (Boolean) -> Unit = { allowMetered ->
        allowMeteredNetwork = allowMetered
        onPrepare(configuration) { authenticationError ->
            if (authenticationError != null) {
                message = authenticationError
            } else if (configuration.operation == Operation.BACKUP) {
                message = viewModel.startBackupEstimate()
                backupPreflight = message == null
            } else {
                launchOperation(false)
            }
        }
    }
    val continueToNetworkCheck: () -> Unit = {
        val hasUnmeteredWifi = context.hasUnmeteredWifi()
        if (shouldConfirmLargeTransfer(configuration.operation, hasUnmeteredWifi)) {
            networkConfirmation = true
        } else {
            prepareOperation(!hasUnmeteredWifi)
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { TerminalBrand() },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background,
                    scrolledContainerColor = MaterialTheme.colorScheme.surface,
                ),
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                Screen.entries.forEach { item ->
                    val icon = when (item) {
                        Screen.CONFIGURE -> Icons.Default.Build
                        Screen.OUTPUT -> Icons.Default.Terminal
                        Screen.HISTORY -> Icons.Default.History
                        Screen.ABOUT -> Icons.Default.Info
                    }
                    NavigationBarItem(
                        selected = screen == item,
                        onClick = { screen = item },
                        icon = { androidx.compose.material3.Icon(icon, contentDescription = null) },
                        label = { Text(item.title) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.primary,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        when (screen) {
            Screen.CONFIGURE -> ConfigurationScreen(
                configuration,
                operationState.status,
                viewModel.readinessError(configuration, requireOAuthToken = false),
                viewModel::update,
                onRun = {
                    if (configuration.requiresDestructiveConfirmation()) {
                        confirmation = true
                    } else {
                        continueToNetworkCheck()
                    }
                },
                onCancel = viewModel::cancel,
                onExport = onExport,
                onImport = onImport,
                authenticationBusy = authenticationBusy,
                onConnect = { slot, provider -> onConnect(slot, provider) { message = it } },
                onDisconnect = { slot, account -> onDisconnect(slot, account) { message = it } },
                projects = projects,
                activeProject = activeProject,
                onSelectProject = viewModel::selectProject,
                onNewProject = {
                    newProjectName = ""
                    showNewProject = true
                },
                onDeleteProject = {
                    projectBackupsForDeletion = viewModel.activeProjectBackupNames()
                    confirmProjectDeletion = true
                },
                retainedBackups = retainedBackups,
                onManageRetainedBackups = { showRetainedBackups = true },
                modifier = Modifier.padding(padding),
            )
            Screen.OUTPUT -> OutputScreen(
                selectedHistory?.state ?: operationState,
                selectedHistory != null,
                Modifier.padding(padding),
            )
            Screen.HISTORY -> HistoryScreen(
                viewModel,
                onSelect = { entry ->
                    selectedHistory = entry
                    screen = Screen.OUTPUT
                },
                onDelete = { entry ->
                    if (viewModel.deleteHistoryEntry(entry.id) && selectedHistory?.id == entry.id) {
                        selectedHistory = null
                    }
                },
                modifier = Modifier.padding(padding),
            )
            Screen.ABOUT -> AboutPrivacyScreen(
                onOpenLink = uriHandler::openUri,
                modifier = Modifier.padding(padding),
            )
        }
    }
    message?.let { error ->
        AlertDialog(
            onDismissRequest = { message = null },
            confirmButton = { TextButton(onClick = { message = null }) { Text("OK") } },
            title = { Text("Not ready") },
            text = { Text(error) },
        )
    }
    storageMessage?.let { result ->
        AlertDialog(
            onDismissRequest = viewModel::clearStorageMessage,
            confirmButton = { TextButton(onClick = viewModel::clearStorageMessage) { Text("OK") } },
            title = { Text("Storage") },
            text = { Text(result) },
        )
    }
    authenticationMessage?.let { result ->
        AlertDialog(
            onDismissRequest = viewModel::clearAuthenticationMessage,
            confirmButton = { TextButton(onClick = viewModel::clearAuthenticationMessage) { Text("OK") } },
            title = { Text("Authentication") },
            text = { Text(result) },
        )
    }
    if (confirmation) {
        AlertDialog(
            onDismissRequest = { confirmation = false },
            dismissButton = { TextButton(onClick = { confirmation = false }) { Text("Cancel") } },
            confirmButton = {
                Button(onClick = {
                    confirmation = false
                    continueToNetworkCheck()
                }) { Text("Continue") }
            },
            title = { Text("Delete messages?") },
            text = { Text("This operation will delete messages using the selected options. Check the accounts and backup before continuing.") },
        )
    }
    if (networkConfirmation) {
        AlertDialog(
            onDismissRequest = { networkConfirmation = false },
            dismissButton = { TextButton(onClick = { networkConfirmation = false }) { Text("Cancel") } },
            confirmButton = {
                Button(onClick = {
                    networkConfirmation = false
                    prepareOperation(true)
                }) { Text("Continue transfer") }
            },
            title = { Text("Use this network?") },
            text = {
                Text(
                    "This transfer may use a large amount of mobile data and may incur carrier charges.",
                )
            },
        )
    }
    if (backupPreflight) {
        BackupPreflightDialog(
            state = backupEstimate,
            onCancel = {
                backupPreflight = false
                viewModel.cancelBackupEstimate()
            },
            onStart = { estimating ->
                backupPreflight = false
                launchOperation(estimating)
            },
        )
    }
    if (showNewProject) {
        AlertDialog(
            onDismissRequest = { showNewProject = false },
            dismissButton = { TextButton(onClick = { showNewProject = false }) { Text("Cancel") } },
            confirmButton = {
                Button(onClick = {
                    val error = viewModel.createProject(newProjectName)
                    showNewProject = false
                    if (error != null) message = error
                }) { Text("Create") }
            },
            title = { Text("New project") },
            text = {
                OutlinedTextField(
                    value = newProjectName,
                    onValueChange = { newProjectName = it },
                    label = { Text("Project name") },
                    singleLine = true,
                )
            },
        )
    }
    if (confirmProjectDeletion) {
        ProjectDeletionDialog(
            projectName = activeProject.name,
            backupNames = projectBackupsForDeletion,
            onCancel = { confirmProjectDeletion = false },
            onKeepBackups = {
                confirmProjectDeletion = false
                message = viewModel.deleteActiveProject(deleteBackups = false)
            },
            onDeleteBackups = {
                confirmProjectDeletion = false
                message = viewModel.deleteActiveProject(deleteBackups = true)
            },
        )
    }
    if (showRetainedBackups) {
        RetainedBackupsDialog(
            groups = retainedBackups,
            onDismiss = { showRetainedBackups = false },
            onExport = { projectId, workspace ->
                showRetainedBackups = false
                onExportRetained(projectId, workspace)
            },
            onDelete = { projectId, workspace ->
                showRetainedBackups = false
                retainedBackupToDelete = projectId to workspace
            },
        )
    }
    retainedBackupToDelete?.let { (projectId, workspace) ->
        AlertDialog(
            onDismissRequest = {
                retainedBackupToDelete = null
                showRetainedBackups = true
            },
            dismissButton = {
                TextButton(onClick = {
                    retainedBackupToDelete = null
                    showRetainedBackups = true
                }) { Text("Cancel") }
            },
            confirmButton = {
                Button(
                    onClick = {
                        retainedBackupToDelete = null
                        message = viewModel.deleteRetainedWorkspace(projectId, workspace)
                        showRetainedBackups = viewModel.retainedBackups.value.isNotEmpty()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) { Text("Delete backup") }
            },
            title = {
                Text(
                    "DELETE $workspace?",
                    color = MaterialTheme.colorScheme.error,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = { Text("This permanently deletes this backup workspace from the device.") },
            shape = MaterialTheme.shapes.medium,
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.error,
            textContentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 0.dp,
        )
    }
}

@Composable
internal fun ProjectDeletionDialog(
    projectName: String,
    backupNames: List<String>,
    onCancel: () -> Unit,
    onKeepBackups: () -> Unit,
    onDeleteBackups: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        confirmButton = {
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = androidx.compose.ui.Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                if (backupNames.isNotEmpty()) {
                    OutlinedButton(onClick = onKeepBackups, modifier = Modifier.fillMaxWidth()) {
                        Text("DELETE PROJECT ONLY")
                    }
                }
                Button(
                    onClick = onDeleteBackups,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) {
                    Text(if (backupNames.isEmpty()) "DELETE PROJECT" else "DELETE PROJECT + BACKUPS")
                }
                TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("CANCEL") }
            }
        },
        title = {
            Text(
                "DELETE $projectName?",
                color = MaterialTheme.colorScheme.error,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                if (backupNames.isEmpty()) {
                    Text("This permanently deletes the project configuration.")
                } else {
                    Text("Private backup workspaces (${backupNames.size}):")
                    backupNames.forEach { name ->
                        Text("> $name", fontFamily = FontFamily.Monospace)
                    }
                    Text("Choose whether to keep these backups on the device or delete them with the project.")
                }
            }
        },
        shape = MaterialTheme.shapes.medium,
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.error,
        textContentColor = MaterialTheme.colorScheme.onSurface,
        tonalElevation = 0.dp,
    )
}

@Composable
private fun RetainedBackupsDialog(
    groups: List<RetainedBackupGroup>,
    onDismiss: () -> Unit,
    onExport: (String, String) -> Unit,
    onDelete: (String, String) -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
        title = {
            Text(
                "RETAINED BACKUPS",
                color = MaterialTheme.colorScheme.primary,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
        },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Text("Backups retained when their project was deleted. Export or permanently delete each workspace.")
                groups.forEach { group ->
                    TerminalPanel(group.projectName, Modifier.fillMaxWidth()) {
                        group.workspaces.forEach { workspace ->
                            Text(workspace, fontFamily = FontFamily.Monospace)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(
                                    onClick = { onExport(group.projectId, workspace) },
                                    modifier = Modifier.semantics {
                                        contentDescription = "Export retained backup $workspace"
                                    },
                                ) { Text("EXPORT") }
                                TextButton(
                                    onClick = { onDelete(group.projectId, workspace) },
                                    modifier = Modifier.semantics {
                                        contentDescription = "Delete retained backup $workspace"
                                    },
                                ) { Text("DELETE") }
                            }
                        }
                    }
                }
            }
        },
        shape = MaterialTheme.shapes.medium,
        containerColor = MaterialTheme.colorScheme.surface,
        titleContentColor = MaterialTheme.colorScheme.primary,
        textContentColor = MaterialTheme.colorScheme.onSurface,
        tonalElevation = 0.dp,
    )
}

@Composable
internal fun BackupPreflightDialog(
    state: BackupEstimateState,
    onCancel: () -> Unit,
    onStart: (estimateInProgress: Boolean) -> Unit,
) {
    when (state) {
        BackupEstimateState.Idle -> Unit
        is BackupEstimateState.Estimating -> AlertDialog(
            onDismissRequest = onCancel,
            dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
            confirmButton = { Button(onClick = { onStart(true) }) { Text("Start while estimating") } },
            title = { Text("Checking storage") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    CircularProgressIndicator()
                    Text(
                        "This backup saves mail on this device and may use significant storage. " +
                            "We’re estimating the required space now. You can wait for the estimate or start " +
                            "immediately. Available storage will continue to be monitored during the backup.",
                    )
                    Text("Available storage: ${MainViewModel.formatBytes(state.availableBytes)}")
                }
            },
        )
        is BackupEstimateState.Ready -> {
            val expectedRemaining = (state.availableBytes - state.estimatedBytes).coerceAtLeast(0L)
            if (state.hasEnoughSpace) {
                AlertDialog(
                    onDismissRequest = onCancel,
                    dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
                    confirmButton = { Button(onClick = { onStart(false) }) { Text("Start backup") } },
                    title = { Text("Start backup?") },
                    text = {
                        Text(
                            "This backup will save mail on this device.\n\n" +
                                "Estimated backup size: ${MainViewModel.formatBytes(state.estimatedBytes)}\n" +
                                "Messages to download: ${state.messageCount}\n" +
                                "Available storage: ${MainViewModel.formatBytes(state.availableBytes)}\n" +
                                "Expected storage remaining: ${MainViewModel.formatBytes(expectedRemaining)}\n\n" +
                                "The final size may differ from this estimate. Safety headroom is reserved.",
                        )
                    },
                )
            } else {
                AlertDialog(
                    onDismissRequest = onCancel,
                    confirmButton = { TextButton(onClick = onCancel) { Text("Close") } },
                    title = { Text("Not enough storage") },
                    text = {
                        Text(
                            "Estimated backup size: ${MainViewModel.formatBytes(state.estimatedBytes)}\n" +
                                "Available storage: ${MainViewModel.formatBytes(state.availableBytes)}\n" +
                                "Recommended space: ${MainViewModel.formatBytes(state.requiredBytes)}\n\n" +
                                "Free some storage before starting this backup.",
                        )
                    },
                )
            }
        }
        is BackupEstimateState.Unavailable -> AlertDialog(
            onDismissRequest = onCancel,
            dismissButton = { TextButton(onClick = onCancel) { Text("Cancel") } },
            confirmButton = { Button(onClick = { onStart(false) }) { Text("Back up anyway") } },
            title = { Text("Storage estimate unavailable") },
            text = {
                Text(
                        "Continue without a size estimate? Available storage will be monitored while the backup runs.\n\n" +
                        "Available storage: " +
                        MainViewModel.formatBytes(state.availableBytes),
                )
            },
        )
    }
}

@Composable
private fun ConfigurationScreen(
    configuration: AppConfiguration,
    status: RunStatus,
    readinessError: String?,
    update: ((AppConfiguration) -> AppConfiguration) -> Unit,
    onRun: () -> Unit,
    onCancel: () -> Unit,
    onExport: (String) -> Unit,
    onImport: (String) -> Unit,
    authenticationBusy: Boolean,
    onConnect: (AccountSlot, Authentication) -> Unit,
    onDisconnect: (AccountSlot, AccountState) -> Unit,
    projects: List<ProjectProfile>,
    activeProject: ProjectProfile,
    onSelectProject: (ProjectProfile) -> Unit,
    onNewProject: () -> Unit,
    onDeleteProject: () -> Unit,
    retainedBackups: List<RetainedBackupGroup>,
    onManageRetainedBackups: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val controlsLocked = authenticationBusy || status == RunStatus.RUNNING
    Column(modifier.fillMaxSize()) {
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                "SELECT A TASK, CONFIGURE ITS ENDPOINTS, THEN REVIEW BEFORE EXECUTION.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
            )
            ProjectSelector(
                projects,
                activeProject,
                onSelectProject,
                onNewProject,
                onDeleteProject,
                retainedBackups.isNotEmpty(),
                onManageRetainedBackups,
                controlsLocked,
            )
            Section("Operation") {
                Operation.entries.chunked(3).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        row.forEach { operation ->
                            FilterChip(
                                selected = configuration.operation == operation,
                                onClick = { update { it.copy(operation = operation) } },
                                label = { Text(operation.title.uppercase()) },
                            )
                        }
                    }
                }
            }

            if (configuration.operation == Operation.COUNT) {
                TargetSelector("Count target", configuration.countTarget) { target ->
                    update { it.copy(countTarget = target) }
                }
            }
            if (configuration.operation == Operation.COMPARE) {
                TargetSelector("Compare source", configuration.compareSource) { target ->
                    update { it.copy(compareSource = target) }
                }
                TargetSelector("Compare destination", configuration.compareDestination) { target ->
                    update { it.copy(compareDestination = target) }
                }
            }

            if (needsSource(configuration)) {
                AccountEditor(
                    AccountSlot.SOURCE,
                    "Source account",
                    configuration.source,
                    { source -> update { it.copy(source = source) } },
                    onConnect,
                    onDisconnect,
                    controlsLocked,
                )
            }
            if (needsDestination(configuration)) {
                AccountEditor(
                    AccountSlot.DESTINATION,
                    "Destination account",
                    configuration.destination,
                    { destination -> update { it.copy(destination = destination) } },
                    onConnect,
                    onDisconnect,
                    controlsLocked,
                )
            }
            if (configuration.operation in setOf(Operation.BACKUP, Operation.RESTORE) ||
                (configuration.operation == Operation.COUNT && configuration.countTarget == TargetType.LOCAL_BACKUP)
            ) {
                Section("Local backup") {
                    OutlinedTextField(
                        value = configuration.backupName,
                        onValueChange = { name -> update { it.copy(backupName = name) } },
                        modifier = Modifier.fillMaxWidth(),
                        label = { Text("Workspace name") },
                        supportingText = {
                            Text("Stored in private app storage; secrets are never written to configuration.")
                        },
                        singleLine = true,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { onImport(configuration.backupName) }) { Text("Import ZIP") }
                        OutlinedButton(onClick = { onExport(configuration.backupName) }) { Text("Export ZIP") }
                    }
                }
            }
            if (configuration.operation == Operation.COMPARE && configuration.compareSource == TargetType.LOCAL_BACKUP) {
                BackupNameEditor(
                    "Source backup workspace",
                    configuration.sourceBackupName,
                    { name -> update { it.copy(sourceBackupName = name) } },
                    onImport,
                    onExport,
                )
            }
            if (configuration.operation == Operation.COMPARE &&
                configuration.compareDestination == TargetType.LOCAL_BACKUP
            ) {
                BackupNameEditor(
                    "Destination backup workspace",
                    configuration.destinationBackupName,
                    { name -> update { it.copy(destinationBackupName = name) } },
                    onImport,
                    onExport,
                )
            }
            OptionsEditor(configuration.operation, configuration.options) { options ->
                update { it.copy(options = options) }
            }
            Spacer(Modifier.height(8.dp))
        }
        Surface(
            color = MaterialTheme.colorScheme.surface,
            shadowElevation = 8.dp,
        ) {
            Column(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                StatusIndicator(
                    status = when {
                        status == RunStatus.RUNNING || authenticationBusy -> RunStatus.RUNNING
                        readinessError == null -> RunStatus.SUCCEEDED
                        else -> RunStatus.IDLE
                    },
                    label = when {
                        status == RunStatus.RUNNING -> "Operation running"
                        authenticationBusy -> "Authentication in progress"
                        readinessError == null -> "Ready to run"
                        else -> readinessError
                    },
                )
                if (status == RunStatus.RUNNING) {
                    OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) { Text("CANCEL OPERATION") }
                } else {
                    Button(
                        onClick = onRun,
                        enabled = readinessError == null && !authenticationBusy,
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.small,
                    ) {
                        Text("RUN ${configuration.operation.title.uppercase()}")
                    }
                }
            }
        }
    }
}

@Composable
private fun ProjectSelector(
    projects: List<ProjectProfile>,
    activeProject: ProjectProfile,
    onSelect: (ProjectProfile) -> Unit,
    onNew: () -> Unit,
    onDelete: () -> Unit,
    hasRetainedBackups: Boolean,
    onManageRetainedBackups: () -> Unit,
    authenticationBusy: Boolean,
) {
    Section("Project") {
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            projects.forEach { project ->
                FilterChip(
                    selected = project.id == activeProject.id,
                    onClick = { onSelect(project) },
                    enabled = !authenticationBusy,
                    label = { Text(project.name) },
                )
            }
        }
        Text(
            "Each project autosaves to its own private .env file.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = onNew, enabled = !authenticationBusy) { Text("NEW PROJECT") }
            TextButton(
                onClick = onDelete,
                enabled = projects.size > 1 && !authenticationBusy,
            ) { Text("DELETE") }
        }
        if (hasRetainedBackups) {
            OutlinedButton(onClick = onManageRetainedBackups, enabled = !authenticationBusy) {
                Text("MANAGE RETAINED BACKUPS")
            }
        }
    }
}

@Composable
private fun AccountEditor(
    slot: AccountSlot,
    title: String,
    account: AccountState,
    onChange: (AccountState) -> Unit,
    onConnect: (AccountSlot, Authentication) -> Unit,
    onDisconnect: (AccountSlot, AccountState) -> Unit,
    authenticationBusy: Boolean,
) {
    Section(title) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Authentication.entries.forEach { auth ->
                FilterChip(
                    selected = account.authentication == auth,
                    onClick = {
                        onChange(
                            account.copy(
                                authentication = auth,
                                host = when (auth) {
                                    Authentication.GOOGLE -> "imap.gmail.com"
                                    Authentication.MICROSOFT -> "outlook.office365.com"
                                    Authentication.PASSWORD -> account.host
                                },
                                username = if (auth == account.authentication) account.username else "",
                                oauthAccountId = "",
                                oauthEmail = "",
                                oauthAccessToken = "",
                            ),
                        )
                    },
                    enabled = !authenticationBusy,
                    label = { Text(auth.title) },
                )
            }
        }
        if (account.authentication == Authentication.PASSWORD) {
            OutlinedTextField(
                account.host,
                { onChange(account.copy(host = it)) },
                Modifier.fillMaxWidth(),
                label = { Text("IMAP host") },
                singleLine = true,
            )
            OutlinedTextField(
                account.username,
                { onChange(account.copy(username = it)) },
                Modifier.fillMaxWidth(),
                label = { Text("Username") },
                singleLine = true,
            )
            OutlinedTextField(
                account.password,
                { onChange(account.copy(password = it)) },
                Modifier.fillMaxWidth(),
                label = { Text("Password or app password") },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
        } else {
            val connected = account.oauthAccountId.isNotBlank()
            StatusIndicator(
                status = if (connected) RunStatus.SUCCEEDED else RunStatus.IDLE,
                label = if (connected) "Connected as ${account.oauthEmail}" else "No account connected",
            )
            Text(
                if (account.authentication == Authentication.GOOGLE) {
                    "Google handles account selection and consent. Gmail IMAP is configured automatically."
                } else {
                    "Microsoft handles account selection and consent. Outlook IMAP is configured automatically."
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
            if (connected) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        onClick = { onConnect(slot, account.authentication) },
                        enabled = !authenticationBusy,
                    ) { Text("CHANGE ACCOUNT") }
                    TextButton(
                        onClick = { onDisconnect(slot, account) },
                        enabled = !authenticationBusy,
                    ) { Text("DISCONNECT") }
                }
            } else {
                Button(
                    onClick = { onConnect(slot, account.authentication) },
                    enabled = !authenticationBusy,
                    modifier = Modifier.fillMaxWidth(),
                    shape = MaterialTheme.shapes.small,
                ) { Text("CONNECT ${account.authentication.title.uppercase()}") }
            }
        }
    }
}

@Composable
private fun TargetSelector(title: String, selected: TargetType, onSelected: (TargetType) -> Unit) {
    Section(title) {
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            TargetType.entries.forEach { target ->
                FilterChip(
                    selected = selected == target,
                    onClick = { onSelected(target) },
                    label = { Text(target.name.lowercase().replace('_', ' ').replaceFirstChar(Char::uppercase)) },
                )
            }
        }
    }
}

@Composable
private fun BackupNameEditor(
    title: String,
    value: String,
    onChange: (String) -> Unit,
    onImport: (String) -> Unit,
    onExport: (String) -> Unit,
) {
    Section(title) {
        OutlinedTextField(
            value,
            onChange,
            Modifier.fillMaxWidth(),
            label = { Text("Workspace name") },
            singleLine = true,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { onImport(value) }) { Text("Import ZIP") }
            OutlinedButton(onClick = { onExport(value) }) { Text("Export ZIP") }
        }
    }
}

@Composable
private fun OptionsEditor(operation: Operation, options: OperationOptions, onChange: (OperationOptions) -> Unit) {
    if (operation == Operation.COUNT) return
    if (operation == Operation.COMPARE) {
        Section("Destination mapping") {
            OutlinedTextField(
                options.destinationFolderPrefix,
                { onChange(options.copy(destinationFolderPrefix = it)) },
                Modifier.fillMaxWidth(),
                label = { Text("Destination folder prefix") },
                singleLine = true,
            )
            OutlinedTextField(
                options.destinationFolderSeparator,
                { onChange(options.copy(destinationFolderSeparator = it)) },
                Modifier.fillMaxWidth(),
                label = { Text("Destination folder separator") },
                singleLine = true,
            )
        }
        return
    }
    Section("Options") {
        OutlinedTextField(
            options.folder,
            { onChange(options.copy(folder = it)) },
            Modifier.fillMaxWidth(),
            label = { Text("Only this folder (optional)") },
            singleLine = true,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            NumberField("Workers", options.workers) { onChange(options.copy(workers = it)) }
            NumberField("Batch size", options.batchSize) { onChange(options.copy(batchSize = it)) }
        }
        if (operation in setOf(Operation.BACKUP, Operation.MIGRATE)) {
            Toggle("Preserve flags", options.preserveFlags) { onChange(options.copy(preserveFlags = it)) }
            Toggle("Preserve Gmail labels", options.preserveLabels) { onChange(options.copy(preserveLabels = it)) }
        }
        if (operation in setOf(Operation.BACKUP, Operation.RESTORE, Operation.MIGRATE)) {
            Toggle(
                if (operation == Operation.BACKUP) "Delete local backup orphans" else "Delete destination orphans",
                options.deleteOrphans,
            ) { onChange(options.copy(deleteOrphans = it)) }
        }
        Toggle("Gmail mode", options.gmailMode) { onChange(options.copy(gmailMode = it)) }
        when (operation) {
            Operation.BACKUP -> Toggle("Manifest only", options.manifestOnly) { onChange(options.copy(manifestOnly = it)) }
            Operation.RESTORE -> {
                Toggle("Apply labels", options.applyLabels) { onChange(options.copy(applyLabels = it)) }
                Toggle("Apply flags", options.applyFlags) { onChange(options.copy(applyFlags = it)) }
                Toggle("Full restore", options.fullRestore) { onChange(options.copy(fullRestore = it)) }
            }
            Operation.MIGRATE -> {
                Toggle("Delete from source", options.deleteSource) { onChange(options.copy(deleteSource = it)) }
                Toggle("Full migrate", options.fullMigrate) { onChange(options.copy(fullMigrate = it)) }
                OutlinedTextField(
                    options.destinationFolderPrefix,
                    { onChange(options.copy(destinationFolderPrefix = it)) },
                    Modifier.fillMaxWidth(),
                    label = { Text("Destination folder prefix") },
                    singleLine = true,
                )
                OutlinedTextField(
                    options.destinationFolderSeparator,
                    { onChange(options.copy(destinationFolderSeparator = it)) },
                    Modifier.fillMaxWidth(),
                    label = { Text("Destination folder separator") },
                    singleLine = true,
                )
            }
            else -> Unit
        }
    }
}

@Composable
private fun RowScope.NumberField(label: String, value: Int, onChange: (Int) -> Unit) {
    OutlinedTextField(
        value.toString(),
        { text -> text.toIntOrNull()?.takeIf { it > 0 }?.let(onChange) },
        Modifier.weight(1f),
        label = { Text(label) },
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        singleLine = true,
    )
}

@Composable
private fun Toggle(label: String, checked: Boolean, onChecked: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, modifier = Modifier.padding(top = 12.dp))
        Switch(checked, onChecked)
    }
}

@Composable
private fun Section(title: String, content: @Composable ColumnScope.() -> Unit) {
    TerminalPanel(title = title, modifier = Modifier.fillMaxWidth(), content = content)
}

@Composable
private fun OutputScreen(
    state: com.callicode.imaptools.model.OperationState,
    historical: Boolean,
    modifier: Modifier = Modifier,
) {
    val terminal = LocalTerminalPalette.current
    var monitorExpanded by rememberSaveable { mutableStateOf(true) }
    var outputExpanded by rememberSaveable { mutableStateOf(true) }
    var resultExpanded by rememberSaveable { mutableStateOf(true) }
    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        CollapsibleTerminalPanel(
            title = "Operation monitor",
            expanded = monitorExpanded,
            onExpandedChange = { monitorExpanded = it },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(
                state.operation?.title?.uppercase() ?: "NO OPERATION SELECTED",
                style = MaterialTheme.typography.headlineSmall,
            )
            StatusIndicator(state.status)
            if (state.status == RunStatus.RUNNING) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            }
            state.events.lastOrNull()?.let { event ->
                event.folder?.let { KeyValue("Folder", it) }
                if (event.current != null && event.total != null) {
                    KeyValue("Progress", "${event.current} / ${event.total}")
                }
            }
        }
        CollapsibleTerminalPanel(
            title = if (historical) "Saved output" else "Live output",
            expanded = outputExpanded,
            onExpandedChange = { outputExpanded = it },
            modifier = Modifier.fillMaxWidth(),
        ) {
            if (state.events.isEmpty()) {
                Text(
                    "$ waiting for an operation…",
                    color = terminal.muted,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            state.events.forEach { event ->
                val eventColor = when (event.severity.lowercase()) {
                    "error" -> MaterialTheme.colorScheme.error
                    "warning" -> terminal.warning
                    "success" -> terminal.success
                    else -> MaterialTheme.colorScheme.onSurface
                }
                Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        eventMarker(event.severity),
                        color = eventColor,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Bold,
                    )
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(
                            event.phase.uppercase(),
                            color = eventColor,
                            style = MaterialTheme.typography.labelSmall,
                        )
                        Text(
                            event.message,
                            color = MaterialTheme.colorScheme.onSurface,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodySmall,
                        )
                        if (event.current != null) {
                            Text(
                                if (event.total != null) "${event.current} / ${event.total}" else event.current.toString(),
                                color = terminal.muted,
                                style = MaterialTheme.typography.labelSmall,
                            )
                        }
                    }
                }
            }
            state.error?.let {
                HorizontalDivider()
                Text("✕ ERROR  $it", color = MaterialTheme.colorScheme.error, fontFamily = FontFamily.Monospace)
            }
        }
        state.result?.let {
            ResultSummary(
                operation = state.operation,
                rawResult = it,
                expanded = resultExpanded,
                onExpandedChange = { resultExpanded = it },
            )
        }
    }
}

@Composable
private fun ResultSummary(
    operation: Operation?,
    rawResult: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
) {
    val terminal = LocalTerminalPalette.current
    val result = remember(operation, rawResult) { ResultFormatter.format(operation, rawResult) }
    CollapsibleTerminalPanel(
        title = "Result summary",
        expanded = expanded,
        onExpandedChange = onExpandedChange,
        modifier = Modifier.fillMaxWidth(),
        accent = terminal.success,
    ) {
        Text(result.heading, color = terminal.success, style = MaterialTheme.typography.titleMedium)
        result.metrics.forEach { metric ->
            KeyValue(
                metric.label,
                metric.value,
                valueColor = if (metric.isError) MaterialTheme.colorScheme.error else null,
            )
        }
        if (result.details.isNotEmpty()) {
            HorizontalDivider(Modifier.padding(vertical = 2.dp))
            Text("DETAILS", color = terminal.muted, style = MaterialTheme.typography.labelSmall)
            result.details.forEach { detail ->
                KeyValue(
                    detail.label,
                    detail.value,
                    valueColor = if (detail.isError) MaterialTheme.colorScheme.error else null,
                )
            }
        }
        result.fallback?.let {
            Text(
                it,
                color = MaterialTheme.colorScheme.onSurface,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun HistoryScreen(
    viewModel: MainViewModel,
    onSelect: (HistoryEntry) -> Unit,
    onDelete: (HistoryEntry) -> Unit,
    modifier: Modifier = Modifier,
) {
    var entryToDelete by remember { mutableStateOf<HistoryEntry?>(null) }
    val history = viewModel.history()
    val terminal = LocalTerminalPalette.current
    Column(
        modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("RUN HISTORY", style = MaterialTheme.typography.headlineSmall)
        Text(
            "LOCAL RECORD OF COMPLETED OPERATIONS",
            color = terminal.muted,
            style = MaterialTheme.typography.labelSmall,
        )
        if (history.isEmpty()) {
            TerminalPanel("No runs recorded") {
                Text(
                    "$ completed operations will appear here",
                    color = terminal.muted,
                    fontFamily = FontFamily.Monospace,
                )
            }
        }
        history.forEach { item ->
            val itemStatus = runCatching { RunStatus.valueOf(item.status.uppercase()) }.getOrDefault(RunStatus.IDLE)
            TerminalPanel(
                item.operation,
                modifier = Modifier.fillMaxWidth().clickable { onSelect(item) },
                accent = statusColor(itemStatus),
            ) {
                StatusIndicator(itemStatus)
                KeyValue("Time", item.timestamp)
                KeyValue("Summary", item.summary.historyPreview())
                Text(
                    "VIEW OUTPUT →",
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.labelMedium,
                )
                TextButton(
                    onClick = { entryToDelete = item },
                    modifier = Modifier.semantics {
                        contentDescription = "Delete ${item.operation} history entry from ${item.timestamp}"
                    },
                ) {
                    Text("DELETE SAVED OUTPUT", color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
    entryToDelete?.let { item ->
        AlertDialog(
            onDismissRequest = { entryToDelete = null },
            confirmButton = {
                Button(
                    onClick = {
                        onDelete(item)
                        entryToDelete = null
                    },
                    modifier = Modifier.semantics { contentDescription = "Confirm delete saved output" },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) { Text("DELETE SAVED OUTPUT") }
            },
            dismissButton = { TextButton(onClick = { entryToDelete = null }) { Text("CANCEL") } },
            title = {
                Text(
                    "DELETE HISTORY ENTRY?",
                    color = MaterialTheme.colorScheme.error,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                )
            },
            text = {
                Text("This permanently deletes the saved output for this run.")
            },
            shape = MaterialTheme.shapes.medium,
            containerColor = MaterialTheme.colorScheme.surface,
            titleContentColor = MaterialTheme.colorScheme.error,
            textContentColor = MaterialTheme.colorScheme.onSurface,
            tonalElevation = 0.dp,
        )
    }
}

private fun String.historyPreview(): String {
    val singleLine = replace(Regex("\\s+"), " ").trim()
    return if (singleLine.length <= 160) singleLine else "${singleLine.take(159)}…"
}

private fun eventMarker(severity: String): String = when (severity.lowercase()) {
    "error" -> "✕"
    "warning" -> "⚠"
    "success" -> "✓"
    else -> "›"
}

@Composable
private fun statusColor(status: RunStatus) = when (status) {
    RunStatus.FAILED -> MaterialTheme.colorScheme.error
    RunStatus.SUCCEEDED -> MaterialTheme.colorScheme.primary
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

private fun needsSource(value: AppConfiguration): Boolean = when (value.operation) {
    Operation.BACKUP, Operation.MIGRATE -> true
    Operation.COUNT -> value.countTarget == TargetType.SOURCE_ACCOUNT
    Operation.COMPARE -> value.compareSource == TargetType.SOURCE_ACCOUNT ||
        value.compareDestination == TargetType.SOURCE_ACCOUNT
    else -> false
}

private fun needsDestination(value: AppConfiguration): Boolean = when (value.operation) {
    Operation.RESTORE, Operation.MIGRATE -> true
    Operation.COUNT -> value.countTarget == TargetType.DESTINATION_ACCOUNT
    Operation.COMPARE -> value.compareSource == TargetType.DESTINATION_ACCOUNT ||
        value.compareDestination == TargetType.DESTINATION_ACCOUNT
    else -> false
}

internal fun shouldConfirmLargeTransfer(operation: Operation, hasUnmeteredWifi: Boolean): Boolean =
    !hasUnmeteredWifi && operation in setOf(Operation.BACKUP, Operation.RESTORE, Operation.MIGRATE)

private fun AppConfiguration.requiresDestructiveConfirmation(): Boolean = when (operation) {
    Operation.BACKUP, Operation.RESTORE -> options.deleteOrphans
    Operation.MIGRATE -> options.deleteSource || options.deleteOrphans
    else -> false
}

private fun Context.hasUnmeteredWifi(): Boolean {
    val connectivity = getSystemService(ConnectivityManager::class.java)
    val network = connectivity.activeNetwork ?: return false
    val capabilities = connectivity.getNetworkCapabilities(network) ?: return false
    return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
}
