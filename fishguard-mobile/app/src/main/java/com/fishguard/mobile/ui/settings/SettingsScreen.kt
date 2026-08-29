package com.fishguard.mobile.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.ui.theme.FishGuardTheme
import com.fishguard.mobile.ui.theme.RiskCritical
import com.fishguard.mobile.ui.theme.RiskSafe

@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    notificationAccessGranted: Boolean,
    onOpenNotificationSettings: () -> Unit,
    onRequestCallScreeningRole: () -> Unit,
    onOpenFullScreenIntentSettings: () -> Unit,
    onOpenScamNumbers: () -> Unit
) {
    val state by viewModel.uiState.collectAsState()
    val testState by viewModel.connectionTestState
    val colors = FishGuardTheme.colors

    var urlDraft by remember(state.backendUrl) { mutableStateOf(state.backendUrl) }
    var pathDraft by remember(state.backendPath) { mutableStateOf(state.backendPath) }
    var apiKeyDraft by remember(state.backendApiKey) { mutableStateOf(state.backendApiKey) }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp)
    ) {
        Text("Réglages", style = MaterialTheme.typography.headlineMedium, modifier = Modifier.padding(bottom = 20.dp))

        SettingsSection("Apparence") {
            Text("Thème", color = colors.textMuted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(bottom = 6.dp))
            SegmentedRow(
                options = listOf("SYSTEM" to "Système", "LIGHT" to "Clair", "DARK" to "Sombre"),
                selected = state.themeMode,
                onSelect = viewModel::setThemeMode
            )
        }

        SettingsSection("Accès système") {
            Row(
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(Modifier.weight(1f)) {
                    Text("Accès aux notifications (WhatsApp)")
                    Text(
                        if (notificationAccessGranted) "Activé" else "Désactivé — requis pour WhatsApp",
                        color = colors.textMuted,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
                TextButton(onClick = onOpenNotificationSettings) { Text(if (notificationAccessGranted) "Gérer" else "Activer") }
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = { viewModel.pushTestNotification() }, modifier = Modifier.fillMaxWidth()) {
                Text("Tester la notification")
            }
            Text(
                "Envoie une notification factice pour vérifier que les alertes s'affichent bien sur cet appareil.",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(top = 4.dp)
            )
        }

        SettingsSection("Protection des appels") {
            Text(
                "Avant de décrocher : FishGuard vérifie le numéro appelant contre une liste de numéros " +
                    "déjà signalés (rôle système \"Filtrage des appels\", à accorder une fois).",
                color = colors.textMuted,
                modifier = Modifier.padding(bottom = 10.dp)
            )
            OutlinedButton(onClick = onRequestCallScreeningRole, modifier = Modifier.fillMaxWidth()) {
                Text("Activer la vérification des numéros")
            }
            Spacer(Modifier.height(8.dp))
            OutlinedButton(onClick = onOpenScamNumbers, modifier = Modifier.fillMaxWidth()) {
                Text("Gérer les numéros signalés")
            }

            Spacer(Modifier.height(16.dp))
            Text(
                "À la prise d'appel : si le numéro est déjà dans tes contacts, une simple notification " +
                    "propose d'analyser. Si le numéro est inconnu, un pop-up s'affiche directement à " +
                    "l'écran pour te prévenir tout de suite. Dans les deux cas, l'analyse elle-même reste " +
                    "manuelle : haut-parleur à activer, transcription hors ligne, score affiché en continu.",
                color = colors.textMuted
            )
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = onOpenFullScreenIntentSettings, modifier = Modifier.fillMaxWidth()) {
                Text("Autoriser le pop-up plein écran")
            }
            Text(
                "Sur Android 14 et plus, ce réglage doit être accordé explicitement — sinon le numéro " +
                    "inconnu ne reçoit qu'une notification classique, comme un numéro connu.",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(top = 4.dp)
            )
            Spacer(Modifier.height(10.dp))
            SettingsSwitchRow(
                "Proposer la protection à chaque appel",
                state.callAssistantEnabled,
                viewModel::setCallAssistantEnabled
            )
        }

        SettingsSection("Sources surveillées") {
            SettingsSwitchRow("WhatsApp", state.monitorWhatsapp, viewModel::setMonitorWhatsapp)
            SettingsSwitchRow("SMS", state.monitorSms, viewModel::setMonitorSms)
            SettingsSwitchRow("Autres notifications (Messenger, Telegram...)", state.monitorOtherNotifs, viewModel::setMonitorOtherNotifs)

            Spacer(Modifier.height(16.dp))
            Text(
                "Ce qui est analysé parmi ces sources",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(bottom = 4.dp)
            )
            SettingsSwitchRow(
                "Ignorer les stickers, photos et messages vocaux sans texte",
                state.ignoreMediaNotifications,
                viewModel::setIgnoreMediaNotifications
            )
            SettingsSwitchRow(
                "Ignorer les résumés de groupe (évite les doublons)",
                state.ignoreGroupSummaries,
                viewModel::setIgnoreGroupSummaries
            )
            Text(
                "Utile si tu approches une limite de messages analysés : ces notifications ne " +
                    "contiennent jamais de texte à risque, inutile de les faire compter.",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(top = 6.dp)
            )
        }

        SettingsSection("Moteur de détection") {
            Text("Sensibilité", color = colors.textMuted, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(bottom = 6.dp))
            SegmentedRow(
                options = listOf("LOW" to "Basse", "NORMAL" to "Normale", "HIGH" to "Élevée"),
                selected = state.sensitivity,
                onSelect = viewModel::setSensitivity
            )
            Text(
                "Basse = moins de fausses alertes. Élevée = plus prudent, quitte à signaler des messages inoffensifs.",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(top = 6.dp, bottom = 16.dp)
            )
        }

        SettingsSection("Backend (API de l'app web)") {
            SettingsSwitchRow(
                "Utiliser le backend quand disponible",
                state.backendPreferred,
                viewModel::setBackendPreferred
            )
            Text(
                "L'analyse locale reste toujours active en secours, y compris hors ligne ou si le backend ne répond pas.",
                color = colors.textMuted,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(top = 4.dp, bottom = 14.dp)
            )
            OutlinedTextField(
                value = urlDraft,
                onValueChange = { urlDraft = it },
                label = { Text("URL du serveur (ex: https://fishguard.tondomaine.com)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = pathDraft,
                onValueChange = { pathDraft = it },
                label = { Text("Chemin de l'endpoint") },
                singleLine = true,
                placeholder = { Text("/api/analyze") },
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(10.dp))
            OutlinedTextField(
                value = apiKeyDraft,
                onValueChange = { apiKeyDraft = it },
                label = { Text("Clé API (optionnelle)") },
                singleLine = true,
                visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(
                    onClick = {
                        viewModel.setBackendUrl(urlDraft)
                        viewModel.setBackendPath(pathDraft)
                        viewModel.setBackendApiKey(apiKeyDraft)
                    },
                    modifier = Modifier.weight(1f)
                ) { Text("Enregistrer") }

                OutlinedButton(
                    onClick = { viewModel.testConnection(urlDraft, pathDraft, apiKeyDraft) },
                    enabled = urlDraft.isNotBlank() && testState != ConnectionTestState.TESTING,
                    modifier = Modifier.weight(1f)
                ) {
                    if (testState == ConnectionTestState.TESTING) {
                        CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text("Tester")
                    }
                }
            }

            when (testState) {
                ConnectionTestState.SUCCESS -> Text(
                    "Connexion réussie ✓",
                    color = RiskSafe,
                    modifier = Modifier.padding(top = 8.dp)
                )
                ConnectionTestState.FAILURE -> Text(
                    "Connexion impossible — vérifie l'URL, le chemin, et que le serveur est accessible depuis ce réseau.",
                    color = RiskCritical,
                    modifier = Modifier.padding(top = 8.dp)
                )
                else -> Unit
            }
        }

        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(Modifier.padding(bottom = 24.dp)) {
        Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(bottom = 10.dp))
        content()
    }
}

@Composable
private fun SettingsSwitchRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp)
    ) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
private fun SegmentedRow(options: List<Pair<String, String>>, selected: String, onSelect: (String) -> Unit) {
    val colors = FishGuardTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .background(colors.surfaceAlt, RoundedCornerShape(10.dp))
            .padding(4.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        options.forEach { (value, label) ->
            val isSelected = value == selected
            Box(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.18f) else androidx.compose.ui.graphics.Color.Transparent)
                    .clickable { onSelect(value) }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = if (isSelected) FontWeight.Medium else FontWeight.Normal,
                    color = if (isSelected) MaterialTheme.colorScheme.primary else colors.textMuted
                )
            }
        }
    }
}
