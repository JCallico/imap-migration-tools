package com.callicode.imaptools

import android.Manifest
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.callicode.imaptools.model.BackupEstimateState
import com.callicode.imaptools.model.Operation
import com.callicode.imaptools.model.OperationState
import com.callicode.imaptools.model.RunStatus
import com.callicode.imaptools.operation.HistoryStore
import com.callicode.imaptools.ui.about.AboutPrivacyScreen
import com.callicode.imaptools.ui.about.OPEN_SOURCE_NOTICES_URL
import com.callicode.imaptools.ui.about.PRIVACY_POLICY_URL
import com.callicode.imaptools.ui.about.SUPPORT_URL
import com.callicode.imaptools.ui.components.CollapsibleTerminalPanel
import com.callicode.imaptools.ui.theme.ImapToolsTheme
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProjectFlowTest {
    @get:Rule(order = 0)
    val notificationPermission: GrantPermissionRule = GrantPermissionRule.grant(Manifest.permission.POST_NOTIFICATIONS)

    @get:Rule(order = 1)
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun projectCanBeCreatedSelectedAndDeleted() {
        val projectName = "UI Test Project"

        compose.onNodeWithText("NEW PROJECT").performClick()
        compose.onNodeWithText("Project name").performTextInput(projectName)
        compose.onNodeWithText("Create").performClick()

        compose.onNodeWithText(projectName).assertIsDisplayed()
        compose.onNodeWithText("DELETE").performClick()
        compose.onNodeWithText("DELETE $projectName?").assertIsDisplayed()
        compose.onNodeWithText("This permanently deletes the project configuration.").assertIsDisplayed()
        compose.onNodeWithText("DELETE PROJECT").performClick()

        compose.onNodeWithText(projectName).assertDoesNotExist()

        var startedWhileEstimating = false
        compose.activity.setContent {
            ImapToolsTheme {
                BackupPreflightDialog(
                    state = BackupEstimateState.Estimating(8L * 1024L * 1024L * 1024L),
                    onCancel = {},
                    onStart = { startedWhileEstimating = it },
                )
            }
        }
        compose.onNodeWithText("Checking storage").assertIsDisplayed()
        compose.onNodeWithText("Start while estimating").performClick()
        assertTrue(startedWhileEstimating)
    }

    @Test
    fun projectBackupsCanBeRetainedAndDeletedLater() {
        val projectName = "Retained UI Project"
        val workspaceName = "mail-archive"

        compose.onNodeWithText("NEW PROJECT").performClick()
        compose.onNodeWithText("Project name").performTextInput(projectName)
        compose.onNodeWithText("Create").performClick()

        val projectDirectory = File(compose.activity.filesDir, "projects").listFiles().orEmpty().first { directory ->
            File(directory, ".env").readText().contains(projectName)
        }
        val workspace = File(compose.activity.filesDir, "backups/${projectDirectory.name}/$workspaceName")
        assertTrue(workspace.mkdirs())
        File(workspace, "message.eml").writeText("message")

        compose.onNodeWithText("DELETE").performClick()
        compose.onNodeWithText("DELETE PROJECT ONLY").performClick()

        compose.onNodeWithText(projectName).assertDoesNotExist()
        compose.onNodeWithText("MANAGE RETAINED BACKUPS").performClick()
        compose.onNodeWithText("RETAINED BACKUPS").assertIsDisplayed()
        compose.onNodeWithText(workspaceName).assertIsDisplayed()
        compose.onNodeWithContentDescription("Delete retained backup $workspaceName").performClick()
        compose.onNodeWithText("DELETE $workspaceName?").assertIsDisplayed()
        compose.onNodeWithText("Delete backup").performClick()

        compose.onNodeWithText(workspaceName).assertDoesNotExist()
        assertFalse(workspace.exists())
    }

    @Test
    fun savedHistoryOutputRequiresConfirmationAndCanBeDeleted() {
        HistoryStore(compose.activity).append(
            OperationState(status = RunStatus.SUCCEEDED, operation = Operation.COUNT, result = "{\"total\":12}"),
        )

        compose.onNodeWithText("History").performClick()
        compose.onNodeWithText("─ COUNT ").assertIsDisplayed()
        compose.onNodeWithText("DELETE SAVED OUTPUT").performClick()
        compose.onNodeWithText("DELETE HISTORY ENTRY?").assertIsDisplayed()
        compose.onNodeWithText("This permanently deletes the saved output for this run.").assertIsDisplayed()
        compose.onNodeWithContentDescription("Confirm delete saved output").performClick()

        compose.onNodeWithText("─ NO RUNS RECORDED ").assertIsDisplayed()
        assertTrue(HistoryStore(compose.activity).entries().isEmpty())
    }

    @Test
    fun terminalPanelCanBeCollapsedAndExpanded() {
        compose.activity.setContent {
            ImapToolsTheme {
                var expanded by remember { mutableStateOf(true) }
                CollapsibleTerminalPanel(
                    title = "Live output",
                    expanded = expanded,
                    onExpandedChange = { expanded = it },
                ) {
                    Text("Transfer details")
                }
            }
        }

        compose.onNodeWithText("Transfer details").assertIsDisplayed()
        compose.onNodeWithText("─ LIVE OUTPUT ").performClick()
        compose.onNodeWithText("Transfer details").assertDoesNotExist()
        compose.onNodeWithText("─ LIVE OUTPUT ").performClick()
        compose.onNodeWithText("Transfer details").assertIsDisplayed()
    }

    @Test
    fun aboutAndPrivacyAreAvailableWithoutAuthentication() {
        compose.onNodeWithText("About").performClick()

        compose.onNodeWithText("ABOUT / PRIVACY").assertIsDisplayed()
        compose.onNodeWithText("VERSION").assertIsDisplayed()
        compose.onNodeWithText("READ PRIVACY POLICY").assertIsDisplayed()
        compose.onNodeWithText("CONTACT SUPPORT").assertIsDisplayed()
    }

    @Test
    fun aboutLinksOpenDocumentedDestinations() {
        var openedUrl: String? = null
        compose.activity.setContent {
            ImapToolsTheme {
                AboutPrivacyScreen(onOpenLink = { openedUrl = it })
            }
        }

        compose.onNodeWithText("READ PRIVACY POLICY").performClick()
        assertEquals(PRIVACY_POLICY_URL, openedUrl)

        compose.onNodeWithText("CONTACT SUPPORT").performClick()
        assertEquals(SUPPORT_URL, openedUrl)

        compose.onNodeWithText("VIEW OPEN-SOURCE NOTICES").performScrollTo().performClick()
        assertEquals(OPEN_SOURCE_NOTICES_URL, openedUrl)
    }
}
