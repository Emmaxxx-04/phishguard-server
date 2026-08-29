package com.fishguard.mobile.ui.calls

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.VolumeUp
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.calls.CallProtectionState
import com.fishguard.mobile.ui.RiskBadge
import com.fishguard.mobile.ui.riskColor
import com.fishguard.mobile.ui.theme.FishGuardTheme
import com.fishguard.mobile.ui.theme.RiskCritical

@Composable
fun CallConsentScreen(
    callerNumber: String,
    isUnknownNumber: Boolean = true,
    onConfirm: () -> Unit,
    onCancel: () -> Unit
) {
    val colors = FishGuardTheme.colors

    Column(Modifier.fillMaxSize().padding(24.dp)) {
        if (isUnknownNumber) {
            Row(
                Modifier
                    .background(RiskCritical.copy(alpha = 0.12f), RoundedCornerShape(10.dp))
                    .padding(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Icon(Icons.Filled.Warning, contentDescription = null, tint = RiskCritical, modifier = Modifier.size(18.dp))
                Text(
                    "Numéro inconnu — absent de tes contacts",
                    color = RiskCritical,
                    fontWeight = FontWeight.Medium,
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
            Spacer(Modifier.height(16.dp))
        }

        Icon(Icons.Filled.VolumeUp, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(40.dp))
        Spacer(Modifier.height(16.dp))
        Text(
            if (isUnknownNumber) "Analyser cet appel ?" else "Protéger cet appel ?",
            style = MaterialTheme.typography.headlineMedium
        )
        if (callerNumber.isNotBlank()) {
            Text(callerNumber, color = colors.textMuted, modifier = Modifier.padding(top = 4.dp))
        }

        Spacer(Modifier.height(20.dp))

        InfoRow("1. Mets l'appel en haut-parleur", "FishGuard écoute via le micro du téléphone, pas le flux de l'appel — le haut-parleur est indispensable.")
        InfoRow("2. Tout reste sur ton téléphone", "La transcription se fait hors ligne, localement. Rien n'est envoyé à un serveur, même avec le mode backend activé.")
        InfoRow("3. Informe ton interlocuteur", "Par respect et pour rester dans les clous légalement, dis à la personne que l'appel est analysé pour ta sécurité — comme le font les services clients.")
        InfoRow("4. Rien n'est parfait", "La reconnaissance vocale peut se tromper, surtout avec du bruit ambiant. Ne te fie jamais uniquement au score : reste vigilant·e.")

        Spacer(Modifier.weight(1f, fill = false))
        Spacer(Modifier.height(24.dp))

        Button(onClick = onConfirm, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text("J'ai mis le haut-parleur, démarrer")
        }
        Spacer(Modifier.height(10.dp))
        OutlinedButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text("Annuler")
        }
    }
}

@Composable
private fun InfoRow(title: String, description: String) {
    val colors = FishGuardTheme.colors
    Row(Modifier.fillMaxWidth().padding(bottom = 14.dp)) {
        Icon(Icons.Filled.Info, contentDescription = null, tint = colors.textMuted, modifier = Modifier.size(18.dp).padding(top = 2.dp))
        Column(Modifier.padding(start = 10.dp)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(description, color = colors.textMuted, modifier = Modifier.padding(top = 2.dp))
        }
    }
}

@Composable
fun CallSummaryScreen(
    callerNumber: String,
    finalScore: Int,
    finalRiskLevel: String,
    signalCategories: List<String>,
    onReportConfirmed: (note: String) -> Unit,
    onDismiss: () -> Unit
) {
    val colors = FishGuardTheme.colors
    var showReportForm by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    var noteDraft by androidx.compose.runtime.remember {
        androidx.compose.runtime.mutableStateOf("Analysé pendant l'appel — score $finalScore/100.")
    }
    var confirmed by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(false) }
    var error by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf<String?>(null) }

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(20.dp))
        Text("Appel terminé", style = MaterialTheme.typography.headlineMedium)
        if (callerNumber.isNotBlank()) {
            Text(callerNumber, color = colors.textMuted, modifier = Modifier.padding(top = 4.dp))
        }

        Spacer(Modifier.height(20.dp))
        Box(
            Modifier.size(120.dp).clip(CircleShape).background(riskColor(finalRiskLevel).copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("$finalScore", style = MaterialTheme.typography.headlineMedium, color = riskColor(finalRiskLevel))
                Text("/ 100", color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
            }
        }
        Spacer(Modifier.height(12.dp))
        RiskBadge(finalRiskLevel, finalScore)

        if (signalCategories.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Column {
                signalCategories.forEach { category ->
                    Text("• $category", color = colors.textMuted, modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }

        Spacer(Modifier.height(24.dp))
        Text(
            "Ce score est une aide, pas un verdict. C'est à toi de décider : cet appel était-il vraiment une tentative de phishing ?",
            color = colors.textMuted,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        if (!showReportForm) {
            Button(
                onClick = { showReportForm = true },
                colors = ButtonDefaults.buttonColors(containerColor = riskColor("CRITICAL")),
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                Text("Oui, c'était une tentative de phishing")
            }
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = onDismiss, modifier = Modifier.fillMaxWidth()) {
                Text("Non, c'était légitime")
            }
        } else {
            OutlinedTextField(
                value = noteDraft,
                onValueChange = { noteDraft = it; error = null },
                label = { Text("Décris ce qui s'est passé") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = confirmed, onCheckedChange = { confirmed = it; error = null })
                Text(
                    "Je confirme que ce numéro m'a réellement contacté pour me demander de l'argent, un code, ou s'est fait passer pour quelqu'un d'autre.",
                    style = MaterialTheme.typography.labelSmall,
                    color = colors.textMuted
                )
            }
            error?.let {
                Text(it, color = riskColor("CRITICAL"), style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 6.dp))
            }
            Spacer(Modifier.height(10.dp))
            Button(
                onClick = {
                    if (noteDraft.trim().length < MIN_REPORT_NOTE_LENGTH) {
                        error = "Décris ce qui s'est passé avec au moins $MIN_REPORT_NOTE_LENGTH caractères."
                    } else if (!confirmed) {
                        error = "Coche la case de confirmation pour signaler ce numéro."
                    } else {
                        onReportConfirmed(noteDraft)
                    }
                },
                modifier = Modifier.fillMaxWidth().height(50.dp)
            ) {
                Text("Confirmer le signalement")
            }
        }
    }
}

@Composable
fun CallProtectionLiveScreen(state: CallProtectionState, onStop: () -> Unit) {
    val colors = FishGuardTheme.colors

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(20.dp))
        Text("Protection active", style = MaterialTheme.typography.titleMedium, color = colors.textMuted)

        Spacer(Modifier.height(24.dp))
        Box(
            Modifier.size(160.dp).clip(CircleShape).background(riskColor(state.riskLevel).copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("${state.score}", style = MaterialTheme.typography.headlineMedium, color = riskColor(state.riskLevel))
                Text("/ 100", color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
            }
        }

        Spacer(Modifier.height(16.dp))
        RiskBadge(state.riskLevel, state.score)

        if (state.partialText.isNotBlank()) {
            Spacer(Modifier.height(20.dp))
            Text(
                "\"${state.partialText}\"",
                color = colors.textMuted,
                modifier = Modifier
                    .background(colors.surface, RoundedCornerShape(10.dp))
                    .padding(12.dp)
            )
        }

        if (state.signalCategories.isNotEmpty()) {
            Spacer(Modifier.height(20.dp))
            Text("Signaux détectés", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            Column {
                state.signalCategories.forEach { category ->
                    Text("• $category", color = colors.textMuted, modifier = Modifier.padding(vertical = 2.dp))
                }
            }
        }

        if (state.score >= 55) {
            Spacer(Modifier.height(20.dp))
            Text(
                "Ne communique aucun code, mot de passe ou montant d'argent.",
                color = riskColor("CRITICAL"),
                fontWeight = FontWeight.Medium
            )
        }

        Spacer(Modifier.weight(1f))
        Button(
            onClick = onStop,
            colors = ButtonDefaults.buttonColors(containerColor = riskColor("CRITICAL")),
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text("Arrêter la protection")
        }
    }
}
