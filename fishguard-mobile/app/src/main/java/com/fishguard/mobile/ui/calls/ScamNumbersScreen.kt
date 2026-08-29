package com.fishguard.mobile.ui.calls

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.ui.FishGuardTopBar
import com.fishguard.mobile.ui.theme.FishGuardTheme
import com.fishguard.mobile.ui.theme.RiskCritical
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ScamNumbersScreen(viewModel: ScamNumbersViewModel, onBack: () -> Unit) {
    val colors = FishGuardTheme.colors
    val numbers by viewModel.numbers.collectAsState()
    val dateFormat = remember { SimpleDateFormat("dd/MM/yyyy", Locale.FRENCH) }

    var numberDraft by remember { mutableStateOf("") }
    var noteDraft by remember { mutableStateOf("") }
    var confirmed by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize()) {
        FishGuardTopBar(title = "Numéros signalés", onBack = onBack)

        Column(Modifier.padding(20.dp)) {
            Text(
                "Un numéro n'est ajouté à la liste rouge qu'après confirmation explicite : " +
                    "décris précisément ce qui s'est passé, puis coche la case ci-dessous. " +
                    "Ce n'est pas un simple bouton \"signaler\" — c'est une déclaration que tu assumes.",
                color = colors.textMuted,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            OutlinedTextField(
                value = numberDraft,
                onValueChange = { numberDraft = it; errorMessage = null },
                label = { Text("Numéro de téléphone") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = noteDraft,
                onValueChange = { noteDraft = it; errorMessage = null },
                label = { Text("Que s'est-il passé exactement ? (au moins $MIN_REPORT_NOTE_LENGTH caractères)") },
                minLines = 2,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(Modifier.height(10.dp))
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                Checkbox(checked = confirmed, onCheckedChange = { confirmed = it; errorMessage = null })
                Text(
                    "Je confirme que ce numéro m'a réellement contacté pour me demander de l'argent, " +
                        "un code, ou s'est fait passer pour quelqu'un d'autre.",
                    style = MaterialTheme.typography.labelSmall,
                    color = colors.textMuted,
                    modifier = Modifier.padding(start = 4.dp)
                )
            }

            errorMessage?.let {
                Text(it, color = RiskCritical, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(top = 6.dp))
            }

            Spacer(Modifier.height(10.dp))
            Button(
                onClick = {
                    when (viewModel.report(numberDraft, noteDraft, confirmed)) {
                        ReportResult.Success -> {
                            numberDraft = ""
                            noteDraft = ""
                            confirmed = false
                            errorMessage = null
                        }
                        ReportResult.NumberBlank -> errorMessage = "Indique un numéro de téléphone."
                        ReportResult.NoteTooShort -> errorMessage =
                            "Décris ce qui s'est passé avec au moins $MIN_REPORT_NOTE_LENGTH caractères — pas juste \"arnaque\"."
                        ReportResult.NotConfirmed -> errorMessage = "Coche la case de confirmation pour signaler ce numéro."
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Signaler ce numéro")
            }
        }

        if (numbers.isEmpty()) {
            Column(Modifier.padding(20.dp)) {
                Text("Aucun numéro signalé pour l'instant.", color = colors.textMuted)
            }
        } else {
            LazyColumn(
                Modifier.fillMaxSize().padding(horizontal = 20.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(numbers, key = { it.id }) { entry ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = colors.surface),
                        border = BorderStroke(1.dp, colors.line),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Row(
                            Modifier.padding(12.dp).fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(entry.number, fontWeight = FontWeight.Medium)
                                if (entry.note.isNotBlank()) {
                                    Text(entry.note, color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                                }
                                if (entry.source == "CALL_ANALYSIS" && entry.linkedScore != null) {
                                    Text(
                                        "Confirmé après analyse d'appel — score ${entry.linkedScore}/100",
                                        color = colors.textMuted,
                                        style = MaterialTheme.typography.labelSmall
                                    )
                                }
                                Text(
                                    "Signalé le ${dateFormat.format(Date(entry.reportedAt))}",
                                    color = colors.textMuted,
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                            IconButton(onClick = { viewModel.remove(entry.id) }) {
                                Icon(Icons.Filled.Delete, contentDescription = "Retirer", tint = RiskCritical)
                            }
                        }
                    }
                }
                item { Spacer(Modifier.height(20.dp)) }
            }
        }
    }
}
