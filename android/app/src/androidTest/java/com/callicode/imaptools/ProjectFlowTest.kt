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
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.rule.GrantPermissionRule
import com.callicode.imaptools.model.BackupEstimateState
import com.callicode.imaptools.ui.components.CollapsibleTerminalPanel
import com.callicode.imaptools.ui.theme.ImapToolsTheme
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
        compose.onNodeWithText("Delete $projectName?").assertIsDisplayed()
        compose.onNodeWithText("Delete project").performClick()

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
}
