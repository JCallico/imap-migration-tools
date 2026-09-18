package com.callicode.imaptools.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.callicode.imaptools.model.RunStatus
import com.callicode.imaptools.ui.theme.LocalTerminalPalette

@Composable
fun TerminalBrand(modifier: Modifier = Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Text(
            ">_",
            color = MaterialTheme.colorScheme.primary,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Black,
        )
        Spacer(Modifier.width(10.dp))
        Column {
            Text("IMAP MIGRATION", style = MaterialTheme.typography.titleMedium)
            Text(
                "TOOLS / ANDROID",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.labelSmall,
            )
        }
    }
}

@Composable
fun TerminalPanel(
    title: String,
    modifier: Modifier = Modifier,
    accent: Color = MaterialTheme.colorScheme.primary,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        tonalElevation = 0.dp,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                text = "─ ${title.uppercase()} ",
                modifier = Modifier.padding(start = 14.dp, top = 12.dp, end = 14.dp),
                color = accent,
                style = MaterialTheme.typography.titleMedium,
            )
            Column(
                modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 14.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                content = content,
            )
        }
    }
}

@Composable
fun CollapsibleTerminalPanel(
    title: String,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = MaterialTheme.colorScheme.primary,
    content: @Composable ColumnScope.() -> Unit,
) {
    val action = if (expanded) "Collapse $title" else "Expand $title"
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        tonalElevation = 0.dp,
    ) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .clickable(onClickLabel = action, role = Role.Button) {
                        onExpandedChange(!expanded)
                    }
                    .semantics {
                        stateDescription = if (expanded) "Expanded" else "Collapsed"
                    }
                    .padding(horizontal = 14.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "─ ${title.uppercase()} ",
                    color = accent,
                    style = MaterialTheme.typography.titleMedium,
                )
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = accent,
                )
            }
            if (expanded) {
                Column(
                    modifier = Modifier.padding(start = 14.dp, end = 14.dp, bottom = 14.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    content = content,
                )
            }
        }
    }
}

@Composable
fun StatusIndicator(status: RunStatus, modifier: Modifier = Modifier, label: String? = null) {
    val terminal = LocalTerminalPalette.current
    val (marker, color) = when (status) {
        RunStatus.SUCCEEDED -> "✓" to terminal.success
        RunStatus.FAILED -> "✕" to MaterialTheme.colorScheme.error
        RunStatus.CANCELLED -> "○" to terminal.warning
        RunStatus.RUNNING -> "●" to terminal.success
        RunStatus.IDLE -> "•" to terminal.muted
    }
    val text = label ?: status.name.lowercase().replaceFirstChar(Char::uppercase)
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        Text(
            marker,
            modifier = Modifier.width(22.dp),
            color = color,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.width(8.dp))
        Text(text.uppercase(), color = color, style = MaterialTheme.typography.labelLarge)
    }
}

@Composable
fun KeyValue(label: String, value: String, modifier: Modifier = Modifier, valueColor: Color? = null) {
    Row(modifier, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(
            label.uppercase(),
            modifier = Modifier.weight(0.35f),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.labelSmall,
        )
        Text(
            value,
            modifier = Modifier.weight(0.65f),
            color = valueColor ?: MaterialTheme.colorScheme.onSurface,
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}
