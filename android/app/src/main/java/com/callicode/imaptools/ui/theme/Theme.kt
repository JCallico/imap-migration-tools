package com.callicode.imaptools.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.PlatformTextStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Typography

@Immutable
data class TerminalPalette(
    val success: Color,
    val warning: Color,
    val muted: Color,
    val line: Color,
    val raisedSurface: Color,
)

private val DarkColors = darkColorScheme(
    primary = TerminalGreen,
    onPrimary = TerminalBlack,
    primaryContainer = Color(0xFF17351B),
    onPrimaryContainer = Color(0xFFA9F5B0),
    secondary = TerminalGreen,
    onSecondary = TerminalBlack,
    secondaryContainer = Color(0xFF203D24),
    onSecondaryContainer = Color(0xFFBDF5C2),
    tertiary = TerminalYellow,
    onTertiary = TerminalBlack,
    tertiaryContainer = Color(0xFF3A3713),
    onTertiaryContainer = Color(0xFFFFF49A),
    background = TerminalBlack,
    onBackground = TerminalText,
    surface = TerminalPanel,
    onSurface = TerminalText,
    surfaceVariant = TerminalPanelRaised,
    onSurfaceVariant = TerminalMuted,
    outline = TerminalLine,
    error = TerminalRed,
)

private val LightColors = lightColorScheme(
    primary = PaperGreen,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD0F2D3),
    onPrimaryContainer = Color(0xFF06210A),
    secondary = PaperGreen,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDCEBDD),
    onSecondaryContainer = Color(0xFF162B18),
    tertiary = PaperYellow,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFFF3B5),
    onTertiaryContainer = Color(0xFF251F00),
    background = PaperBackground,
    onBackground = PaperText,
    surface = PaperPanel,
    onSurface = PaperText,
    surfaceVariant = PaperPanelRaised,
    onSurfaceVariant = PaperMuted,
    outline = PaperLine,
    error = PaperRed,
)

private val DarkTerminalPalette = TerminalPalette(
    success = TerminalGreen,
    warning = TerminalYellow,
    muted = TerminalMuted,
    line = TerminalLine,
    raisedSurface = TerminalPanelRaised,
)

private val LightTerminalPalette = TerminalPalette(
    success = PaperGreen,
    warning = PaperYellow,
    muted = PaperMuted,
    line = PaperLine,
    raisedSurface = PaperPanelRaised,
)

val LocalTerminalPalette = staticCompositionLocalOf { DarkTerminalPalette }

private val AppTypography = Typography(
    headlineSmall = TextStyle(
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        letterSpacing = 0.2.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold,
        fontSize = 15.sp,
        letterSpacing = 0.8.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    titleSmall = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    bodyMedium = TextStyle(
        fontSize = 14.sp,
        lineHeight = 20.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    bodySmall = TextStyle(
        fontSize = 12.sp,
        lineHeight = 17.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 13.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontSize = 11.sp,
        letterSpacing = 0.3.sp,
        platformStyle = PlatformTextStyle(includeFontPadding = false),
    ),
)

private val AppShapes = Shapes(
    extraSmall = RoundedCornerShape(2.dp),
    small = RoundedCornerShape(3.dp),
    medium = RoundedCornerShape(5.dp),
    large = RoundedCornerShape(7.dp),
    extraLarge = RoundedCornerShape(9.dp),
)

@Composable
fun ImapToolsTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    androidx.compose.runtime.CompositionLocalProvider(
        LocalTerminalPalette provides if (darkTheme) DarkTerminalPalette else LightTerminalPalette,
    ) {
        MaterialTheme(
            colorScheme = if (darkTheme) DarkColors else LightColors,
            typography = AppTypography,
            shapes = AppShapes,
            content = content,
        )
    }
}
