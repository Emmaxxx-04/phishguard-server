package com.fishguard.mobile.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/** Mode d'affichage choisi par l'utilisateur (persisté via DataStore). */
enum class AppThemeMode { SYSTEM, LIGHT, DARK }

/** Couleurs additionnelles non couvertes par le ColorScheme Material3 standard. */
data class ExtendedColors(
    val surface: Color,
    val surfaceAlt: Color,
    val line: Color,
    val textMuted: Color
)

private val DarkExtended = ExtendedColors(
    surface = SurfaceDark,
    surfaceAlt = SurfaceDarkAlt,
    line = LineDark,
    textMuted = TextMutedDark
)

private val LightExtended = ExtendedColors(
    surface = SurfaceLight,
    surfaceAlt = SurfaceLightAlt,
    line = LineLight,
    textMuted = TextMutedLight
)

val LocalExtendedColors = staticCompositionLocalOf { DarkExtended }

private val FishGuardDarkScheme = darkColorScheme(
    primary = BrandCyan,
    secondary = BrandBlue,
    error = RiskCritical,
    background = BgDark,
    surface = SurfaceDark,
    onBackground = TextPrimaryDark,
    onSurface = TextPrimaryDark,
    outline = LineDark
)

private val FishGuardLightScheme = lightColorScheme(
    primary = BrandBlue,
    secondary = BrandNavy,
    error = RiskCritical,
    background = BgLight,
    surface = SurfaceLight,
    onBackground = TextPrimaryLight,
    onSurface = TextPrimaryLight,
    outline = LineLight
)

/** Petit accesseur pratique : `FishGuardTheme.colors.surface` depuis n'importe quel composable. */
object FishGuardTheme {
    val colors: ExtendedColors
        @Composable get() = LocalExtendedColors.current
}

@Composable
fun FishGuardTheme(darkTheme: Boolean, content: @Composable () -> Unit) {
    val colorScheme = if (darkTheme) FishGuardDarkScheme else FishGuardLightScheme
    val extended = if (darkTheme) DarkExtended else LightExtended

    CompositionLocalProvider(LocalExtendedColors provides extended) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = FishGuardTypography,
            content = content
        )
    }
}
