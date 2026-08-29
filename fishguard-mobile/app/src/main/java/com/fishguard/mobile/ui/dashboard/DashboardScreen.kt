package com.fishguard.mobile.ui.dashboard

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.R
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.ui.RiskBadge
import com.fishguard.mobile.ui.theme.BrandBlue
import com.fishguard.mobile.ui.theme.BrandCyan
import com.fishguard.mobile.ui.theme.BrandNavy
import com.fishguard.mobile.ui.theme.ExtendedColors
import com.fishguard.mobile.ui.theme.FishGuardTheme
import com.fishguard.mobile.ui.theme.RiskCritical
import com.fishguard.mobile.ui.theme.RiskSafe

@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel,
    notificationAccessGranted: Boolean,
    onOpenThreat: (Long) -> Unit,
    onOpenNotificationSettings: () -> Unit,
    onOpenManualTest: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    val colors = FishGuardTheme.colors

    Scaffold(
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onOpenManualTest,
                icon = { Icon(Icons.Filled.Edit, contentDescription = null) },
                text = { Text("Tester un message") },
                containerColor = BrandBlue
            )
        }
    ) { fabPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = fabPadding.calculateBottomPadding())
        ) {
            HeroHeader()

            Column(Modifier.padding(horizontal = 20.dp)) {
                Spacer(Modifier.height(18.dp))

                if (!notificationAccessGranted) {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        border = BorderStroke(1.dp, colors.line),
                        shape = RoundedCornerShape(14.dp),
                        modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
                    ) {
                        Column(Modifier.padding(16.dp)) {
                            Text("Accès aux notifications requis", fontWeight = FontWeight.Medium)
                            Text(
                                "Pour analyser WhatsApp et les SMS reçus en notification, active l'accès dans les réglages Android.",
                                color = colors.textMuted,
                                modifier = Modifier.padding(top = 4.dp, bottom = 10.dp)
                            )
                            Button(onClick = onOpenNotificationSettings) { Text("Activer maintenant") }
                        }
                    }
                }

                // --- Bandeau de synthèse : menaces vs messages sûrs, séparés visuellement ---
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    RiskSummaryCard(
                        label = "Menaces détectées",
                        value = state.riskyCount,
                        accent = RiskCritical,
                        modifier = Modifier.weight(1f)
                    )
                    RiskSummaryCard(
                        label = "Messages sûrs",
                        value = state.safeCount,
                        accent = RiskSafe,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(12.dp))

                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(colors.surfaceAlt, RoundedCornerShape(12.dp))
                        .padding(14.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column {
                        Text("Total analysé", color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                        Text("${state.totalAnalyzed}", fontWeight = FontWeight.Medium)
                    }
                    Column(horizontalAlignment = Alignment.End) {
                        Text("Dont critiques", color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                        Text(
                            "${state.criticalCount}",
                            fontWeight = FontWeight.Medium,
                            color = if (state.criticalCount > 0) RiskCritical else MaterialTheme.colorScheme.onSurface
                        )
                    }
                }

                Spacer(Modifier.height(28.dp))
                Text("Détections récentes", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(bottom = 10.dp))

                if (state.recentThreats.isEmpty()) {
                    EmptyState()
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        state.recentThreats.forEach { threat ->
                            ThreatRow(threat, colors, onClick = { onOpenThreat(threat.id) })
                        }
                    }
                }

                Spacer(Modifier.height(90.dp)) // laisse de la place pour le FAB
            }
        }
    }
}

@Composable
private fun HeroHeader() {
    Box(
        Modifier
            .fillMaxWidth()
            .background(
                Brush.linearGradient(
                    colors = listOf(BrandNavy, BrandBlue, BrandCyan),
                    start = Offset(0f, 0f),
                    end = Offset(900f, 500f)
                )
            )
            .padding(horizontal = 20.dp, vertical = 26.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(52.dp)
                    .clip(CircleShape)
                    .background(Color.White.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Image(
                    painter = painterResource(R.drawable.fishguard_mark),
                    contentDescription = null,
                    modifier = Modifier.size(34.dp)
                )
            }
            Spacer(Modifier.width(14.dp))
            Column {
                Text("FishGuard", style = MaterialTheme.typography.headlineMedium, color = Color.White)
                Text(
                    "Protection en temps réel — SMS & WhatsApp",
                    color = Color.White.copy(alpha = 0.85f),
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }
}

@Composable
private fun RiskSummaryCard(label: String, value: Int, accent: Color, modifier: Modifier = Modifier) {
    val colors = FishGuardTheme.colors
    Column(
        modifier = modifier
            .background(colors.surface, RoundedCornerShape(14.dp))
            .border(BorderStroke(1.dp, colors.line), RoundedCornerShape(14.dp))
            .padding(16.dp)
    ) {
        Box(
            Modifier
                .size(10.dp)
                .clip(CircleShape)
                .background(accent)
        )
        Spacer(Modifier.height(10.dp))
        Text(value.toString(), style = MaterialTheme.typography.headlineMedium)
        Text(label, color = colors.textMuted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 2.dp))
    }
}

@Composable
private fun ThreatRow(threat: ThreatEntity, colors: ExtendedColors, onClick: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = colors.surface),
        border = BorderStroke(1.dp, colors.line),
        shape = RoundedCornerShape(10.dp),
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick)
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                Column {
                    Text(threat.sourceApp, fontWeight = FontWeight.Medium)
                    if (threat.sender.isNotBlank()) {
                        Text(threat.sender, color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                    }
                }
                RiskBadge(threat.riskLevel, threat.score)
            }
            Text(threat.messagePreview, color = colors.textMuted, maxLines = 2, modifier = Modifier.padding(top = 6.dp))
        }
    }
}

@Composable
private fun EmptyState() {
    val colors = FishGuardTheme.colors
    Column(
        Modifier
            .fillMaxWidth()
            .background(colors.surfaceAlt, RoundedCornerShape(12.dp))
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text("Aucune détection pour l'instant", fontWeight = FontWeight.Medium)
        Text(
            "Dès qu'un SMS ou une notification WhatsApp arrive, l'analyse apparaîtra ici.",
            color = colors.textMuted,
            modifier = Modifier.padding(top = 4.dp)
        )
    }
}
