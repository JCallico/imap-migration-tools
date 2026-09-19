package com.callicode.imaptools.ui.about

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.callicode.imaptools.BuildConfig
import com.callicode.imaptools.ui.components.KeyValue
import com.callicode.imaptools.ui.components.TerminalPanel

internal const val PRIVACY_POLICY_URL =
    "https://github.com/JCallico/imap-migration-tools/blob/main/docs/privacy.md"
internal const val SUPPORT_URL =
    "https://github.com/JCallico/imap-migration-tools/issues"
internal const val OPEN_SOURCE_NOTICES_URL =
    "https://github.com/JCallico/imap-migration-tools/blob/main/docs/open-source-notices.md"

@Composable
internal fun AboutPrivacyScreen(
    onOpenLink: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            "ABOUT / PRIVACY",
            color = MaterialTheme.colorScheme.primary,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Black,
            style = MaterialTheme.typography.headlineSmall,
        )
        Text(
            "A local-first toolbox for counting, comparing, backing up, restoring, and migrating IMAP mailboxes.",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
        )

        TerminalPanel("Build", Modifier.fillMaxWidth()) {
            KeyValue("Version", BuildConfig.VERSION_NAME)
            KeyValue("Build", BuildConfig.VERSION_CODE.toString())
            KeyValue("Package", BuildConfig.APPLICATION_ID)
        }

        TerminalPanel("Support & privacy", Modifier.fillMaxWidth()) {
            Text(
                "You can read the privacy policy or contact support without connecting an email account. " +
                    "The issue tracker is public—never include passwords, tokens, private email, or mailbox content.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(
                onClick = { onOpenLink(PRIVACY_POLICY_URL) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("READ PRIVACY POLICY")
            }
            OutlinedButton(
                onClick = { onOpenLink(SUPPORT_URL) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("CONTACT SUPPORT")
            }
        }

        TerminalPanel("Local backup storage", Modifier.fillMaxWidth()) {
            DisclosureLine(
                "Backups are stored in this app’s private storage on this device. They are not uploaded to an " +
                    "IMAP Migration Tools server.",
            )
            DisclosureLine(
                "When deleting a project, you choose whether its private backups are also deleted. Backups you " +
                    "retain remain available to export or delete from the project screen.",
            )
            DisclosureLine(
                "Uninstalling the app or clearing its storage removes app-private projects, history, and backups. " +
                    "Exported archives remain wherever you saved them and must be deleted separately.",
            )
        }

        TerminalPanel("Open source", Modifier.fillMaxWidth()) {
            Text(
                "IMAP Migration Tools is distributed under the MIT License and includes open-source components " +
                    "under their own licenses, including AndroidX, Kotlin, Chaquopy, CPython, and MSAL.",
                style = MaterialTheme.typography.bodyMedium,
            )
            OutlinedButton(
                onClick = { onOpenLink(OPEN_SOURCE_NOTICES_URL) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("VIEW OPEN-SOURCE NOTICES")
            }
        }
    }
}

@Composable
private fun DisclosureLine(text: String) {
    Text(
        text = "> $text",
        color = MaterialTheme.colorScheme.onSurface,
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.bodySmall,
    )
}
