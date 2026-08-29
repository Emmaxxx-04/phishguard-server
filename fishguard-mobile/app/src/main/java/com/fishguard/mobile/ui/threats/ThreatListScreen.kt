package com.fishguard.mobile.ui.threats

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.ui.RiskBadge
import com.fishguard.mobile.ui.theme.FishGuardTheme
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ThreatListScreen(viewModel: ThreatListViewModel, onOpenThreat: (Long) -> Unit) {
    val state by viewModel.uiState.collectAsState()
    val colors = FishGuardTheme.colors
    val dateFormat = remember { SimpleDateFormat("dd/MM HH:mm", Locale.FRENCH) }
    var filter by rememberSaveable { mutableStateOf(ThreatFilter.ALL) }

    val displayed = when (filter) {
        ThreatFilter.ALL -> state.all
        ThreatFilter.RISKY -> state.risky
        ThreatFilter.SAFE -> state.safe
    }
    var showClearConfirm by remember { mutableStateOf(false) }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text("Effacer tout l'historique ?") },
            text = { Text("Cette action supprime définitivement les ${state.all.size} messages analysés enregistrés sur cet appareil.") },
            confirmButton = {
                TextButton(onClick = {
                    viewModel.clearHistory()
                    showClearConfirm = false
                }) { Text("Effacer", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) { Text("Annuler") }
            }
        )
    }

    Column(Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            horizontalArrangement = Arrangement.SpaceBetween,
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp)
        ) {
            Text("Historique", style = MaterialTheme.typography.headlineMedium)
            TextButton(onClick = { showClearConfirm = true }, enabled = state.all.isNotEmpty()) { Text("Effacer") }
        }

        // --- Séparation claire messages à risque / messages sûrs ---
        FilterTabs(
            filter = filter,
            counts = Triple(state.all.size, state.risky.size, state.safe.size),
            onSelect = { filter = it }
        )

        Spacer(Modifier.height(12.dp))

        if (displayed.isEmpty()) {
            Text(
                when (filter) {
                    ThreatFilter.RISKY -> "Aucun message à risque pour l'instant."
                    ThreatFilter.SAFE -> "Aucun message sûr enregistré pour l'instant."
                    ThreatFilter.ALL -> "Aucun message analysé pour l'instant."
                },
                color = colors.textMuted
            )
            return@Column
        }

        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(displayed, key = { it.id }) { threat ->
                ThreatItemCard(threat, colors, dateFormat, onClick = { onOpenThreat(threat.id) })
            }
        }
    }
}

@Composable
private fun FilterTabs(filter: ThreatFilter, counts: Triple<Int, Int, Int>, onSelect: (ThreatFilter) -> Unit) {
    val colors = FishGuardTheme.colors
    val (all, risky, safe) = counts
    Row(
        Modifier
            .fillMaxWidth()
            .background(colors.surfaceAlt, RoundedCornerShape(10.dp))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        FilterChipItem("Tous ($all)", filter == ThreatFilter.ALL, Modifier.weight(1f)) { onSelect(ThreatFilter.ALL) }
        FilterChipItem("À risque ($risky)", filter == ThreatFilter.RISKY, Modifier.weight(1f)) { onSelect(ThreatFilter.RISKY) }
        FilterChipItem("Sûrs ($safe)", filter == ThreatFilter.SAFE, Modifier.weight(1f)) { onSelect(ThreatFilter.SAFE) }
    }
}

@Composable
private fun FilterChipItem(label: String, selected: Boolean, modifier: Modifier = Modifier, onClick: () -> Unit) {
    val colors = FishGuardTheme.colors
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.18f) else androidx.compose.ui.graphics.Color.Transparent)
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        contentAlignment = androidx.compose.ui.Alignment.Center
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal,
            color = if (selected) MaterialTheme.colorScheme.primary else colors.textMuted
        )
    }
}

@Composable
private fun ThreatItemCard(
    threat: ThreatEntity,
    colors: com.fishguard.mobile.ui.theme.ExtendedColors,
    dateFormat: SimpleDateFormat,
    onClick: () -> Unit
) {
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
                    val subtitle = listOfNotNull(
                        threat.sender.takeIf { it.isNotBlank() },
                        dateFormat.format(Date(threat.timestamp))
                    ).joinToString(" · ")
                    Text(subtitle, color = colors.textMuted, style = MaterialTheme.typography.labelSmall)
                }
                RiskBadge(threat.riskLevel, threat.score)
            }
            Text(threat.messagePreview, color = colors.textMuted, maxLines = 2, modifier = Modifier.padding(top = 6.dp))
        }
    }
}
