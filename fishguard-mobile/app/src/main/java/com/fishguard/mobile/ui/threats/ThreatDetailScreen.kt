package com.fishguard.mobile.ui.threats

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.detection.ThreatSignal
import com.fishguard.mobile.ui.FishGuardTopBar
import com.fishguard.mobile.ui.RiskBadge
import com.fishguard.mobile.ui.riskColor
import com.fishguard.mobile.ui.theme.FishGuardTheme

@Composable
fun ThreatDetailScreen(app: FishGuardApp, threatId: Long, onBack: () -> Unit) {
    var threat by remember { mutableStateOf<ThreatEntity?>(null) }
    val colors = FishGuardTheme.colors

    LaunchedEffect(threatId) {
        threat = app.database.threatDao().getById(threatId)
    }

    val current = threat ?: run {
        Column(Modifier.fillMaxSize()) {
            FishGuardTopBar(title = "Détail", onBack = onBack)
            Text("Chargement...", color = colors.textMuted, modifier = Modifier.padding(20.dp))
        }
        return
    }

    val signals: List<ThreatSignal> = remember(current.signalsJson) {
        try {
            val type = object : TypeToken<List<ThreatSignal>>() {}.type
            Gson().fromJson(current.signalsJson, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }

    Column(Modifier.fillMaxSize()) {
        FishGuardTopBar(title = current.sourceApp, onBack = onBack)

        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
        ) {
        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
            Column {
                if (current.sender.isNotBlank()) {
                    Text(current.sender, color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                }
            }
            RiskBadge(current.riskLevel, current.score)
        }
        Text(
            "Analysé par le moteur ${if (current.engine == "backend") "backend FishGuard" else "local (hors ligne)"}",
            color = colors.textMuted,
            modifier = Modifier.padding(top = 8.dp, bottom = 20.dp)
        )

        SectionLabel("Message")
        Text(
            current.fullMessage,
            modifier = Modifier
                .fillMaxWidth()
                .background(colors.surface, RoundedCornerShape(10.dp))
                .padding(14.dp)
        )

        Spacer(Modifier.height(20.dp))
        SectionLabel("Pourquoi ce score ?")

        if (signals.isEmpty()) {
            Text("Aucun signal spécifique détecté.", color = colors.textMuted, modifier = Modifier.padding(top = 4.dp))
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
                signals.forEach { signal ->
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .background(colors.surface, RoundedCornerShape(10.dp))
                            .padding(12.dp)
                    ) {
                        Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                            Text(signal.category, fontWeight = FontWeight.Medium)
                            if (signal.weight > 0) {
                                Text("+${signal.weight} pts", color = riskColor(current.riskLevel))
                            }
                        }
                        Text(signal.explanation, color = colors.textMuted, modifier = Modifier.padding(top = 4.dp))
                    }
                }
            }
        }
        Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, style = MaterialTheme.typography.titleMedium)
}
