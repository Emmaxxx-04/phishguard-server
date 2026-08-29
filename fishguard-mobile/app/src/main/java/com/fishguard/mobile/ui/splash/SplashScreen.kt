package com.fishguard.mobile.ui.splash

import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.EaseOutBack
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.R
import com.fishguard.mobile.ui.theme.BrandBlue
import com.fishguard.mobile.ui.theme.BrandCyan
import com.fishguard.mobile.ui.theme.BrandNavyDeep
import kotlinx.coroutines.delay

/**
 * Écran de lancement animé : logo qui apparaît en douceur avec un halo pulsé,
 * affiché brièvement avant d'atterrir sur l'onboarding ou le dashboard.
 */
@Composable
fun SplashScreen(onFinished: () -> Unit) {
    val logoScale = remember { Animatable(0.6f) }
    val logoAlpha = remember { Animatable(0f) }
    val textAlpha = remember { Animatable(0f) }

    val pulseTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by pulseTransition.animateFloat(
        initialValue = 1f,
        targetValue = 1.35f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulseScale"
    )
    val pulseAlpha by pulseTransition.animateFloat(
        initialValue = 0.5f,
        targetValue = 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(1400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "pulseAlpha"
    )

    LaunchedEffect(Unit) {
        logoAlpha.animateTo(1f, tween(400))
        logoScale.animateTo(1f, tween(550, easing = EaseOutBack))
        textAlpha.animateTo(1f, tween(400))
        delay(900)
        onFinished()
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(
                Brush.radialGradient(
                    colors = listOf(BrandBlue, BrandNavyDeep),
                    center = Offset.Unspecified,
                    radius = 1200f
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Box(contentAlignment = Alignment.Center) {
                // Halo pulsé derrière le logo
                Box(
                    Modifier
                        .size(140.dp)
                        .scale(pulseScale)
                        .alpha(pulseAlpha)
                        .clip(CircleShape)
                        .background(BrandCyan)
                )
                Box(
                    Modifier
                        .size(110.dp)
                        .scale(logoScale.value)
                        .alpha(logoAlpha.value)
                        .clip(CircleShape)
                        .background(Color.White.copy(alpha = 0.14f)),
                    contentAlignment = Alignment.Center
                ) {
                    Image(
                        painter = painterResource(R.drawable.fishguard_mark),
                        contentDescription = null,
                        modifier = Modifier.size(70.dp)
                    )
                }
            }
            Spacer(Modifier.height(20.dp))
            Text(
                "FishGuard",
                style = MaterialTheme.typography.headlineMedium,
                color = Color.White,
                modifier = Modifier.alpha(textAlpha.value)
            )
            Text(
                "On ne mord plus à l'hameçon",
                color = Color.White.copy(alpha = 0.75f),
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.alpha(textAlpha.value).padding(top = 4.dp)
            )
        }
    }
}
