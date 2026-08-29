package com.fishguard.mobile.ui.manualtest

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.ui.FishGuardTopBar
import com.fishguard.mobile.ui.RiskBadge
import com.fishguard.mobile.ui.riskColor
import com.fishguard.mobile.ui.theme.FishGuardTheme

private val SOURCE_OPTIONS = listOf("WhatsApp", "SMS", "Appel", "Autre")

@Composable
fun ManualTestScreen(viewModel: ManualTestViewModel, onBack: () -> Unit) {
    val colors = FishGuardTheme.colors
    val state by viewModel.uiState

    var text by remember { mutableStateOf("") }
    var sender by remember { mutableStateOf("") }
    var source by remember { mutableStateOf(SOURCE_OPTIONS[0]) }

    Column(Modifier.fillMaxSize()) {
        FishGuardTopBar(title = "Tester un message", onBack = onBack)

        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(20.dp)
        ) {
            Text(
                "Colle un SMS ou un message WhatsApp suspect pour voir instantanément comment FishGuard l'évaluerait — sans attendre de le recevoir réellement.",
                color = colors.textMuted,
                modifier = Modifier.padding(bottom = 18.dp)
            )

            Text("Source", style = MaterialTheme.typography.labelSmall, color = colors.textMuted, modifier = Modifier.padding(bottom = 6.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(colors.surfaceAlt, RoundedCornerShape(10.dp))
                    .padding(4.dp),
                horizontalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                SOURCE_OPTIONS.forEach { option ->
                    val selected = option == source
                    Box(
                        Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(8.dp))
                            .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.18f) else androidx.compose.ui.graphics.Color.Transparent)
                            .clickable { source = option }
                            .padding(vertical = 10.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            option,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
                            color = if (selected) MaterialTheme.colorScheme.primary else colors.textMuted
                        )
                    }
                }
            }

            Spacer(Modifier.height(16.dp))

            OutlinedTextField(
                value = sender,
                onValueChange = { sender = it },
                label = { Text("Expéditeur (optionnel — numéro ou nom)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(12.dp))

            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                label = { Text("Contenu du message") },
                minLines = 4,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(16.dp))

            Button(
                onClick = { viewModel.analyze(source, sender, text) },
                enabled = text.isNotBlank() && !state.isAnalyzing,
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                if (state.isAnalyzing) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text("Analyser")
                }
            }

            state.result?.let { result ->
                Spacer(Modifier.height(24.dp))
                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                    Text("Résultat", style = MaterialTheme.typography.titleMedium)
                    RiskBadge(result.riskLevel.name, result.score)
                }

                if (result.signals.isEmpty()) {
                    Text(
                        "Aucun signal de risque détecté dans ce message.",
                        color = colors.textMuted,
                        modifier = Modifier.padding(top = 10.dp)
                    )
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 12.dp)) {
                        result.signals.forEach { signal ->
                            Column(
                                Modifier
                                    .fillMaxWidth()
                                    .background(colors.surface, RoundedCornerShape(10.dp))
                                    .padding(12.dp)
                            ) {
                                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                    Text(signal.category, fontWeight = FontWeight.Medium)
                                    if (signal.weight > 0) {
                                        Text("+${signal.weight} pts", color = riskColor(result.riskLevel.name))
                                    }
                                }
                                Text(signal.explanation, color = colors.textMuted, modifier = Modifier.padding(top = 4.dp))
                            }
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))

                if (state.saved) {
                    Text("Enregistré dans l'historique ✓", color = riskColor("SAFE"))
                } else {
                    OutlinedButton(
                        onClick = { viewModel.saveToHistory(source, sender, text) },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Enregistrer dans l'historique")
                    }
                }
            }

            Spacer(Modifier.height(24.dp))
        }
    }
}
