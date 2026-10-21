package me.usersu.manager.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// UserSU's accent is the amber of a shell prompt's warning line: it reads as
// "something changed here" without the alarm of red.
private val Amber = Color(0xFFD9A114)
private val AmberDark = Color(0xFF8F6A0A)
private val Slate = Color(0xFF1B1D21)
private val SlateLight = Color(0xFF2A2D33)
private val Paper = Color(0xFFF6F4EF)

private val LightColors = lightColorScheme(
    primary = AmberDark,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFFE08A),
    onPrimaryContainer = Color(0xFF2A1F00),
    secondary = SlateLight,
    background = Paper,
    surface = Paper,
)

private val DarkColors = darkColorScheme(
    primary = Amber,
    onPrimary = Color(0xFF2A1F00),
    primaryContainer = AmberDark,
    onPrimaryContainer = Color(0xFFFFE08A),
    secondary = Color(0xFFB9BDC4),
    background = Slate,
    surface = SlateLight,
)

@Composable
fun UserSUTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
