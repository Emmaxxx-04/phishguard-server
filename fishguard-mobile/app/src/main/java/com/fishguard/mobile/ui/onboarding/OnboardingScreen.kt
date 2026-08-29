package com.fishguard.mobile.ui.onboarding

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Sms
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.fishguard.mobile.ui.theme.BrandCyan
import com.fishguard.mobile.ui.theme.FishGuardTheme

/**
 * Écran affiché uniquement au tout premier lancement, avant toute demande de
 * permission système. Explique CE QUE l'app va lire et POURQUOI, dans son
 * propre langage — un utilisateur qui comprend pourquoi accepte davantage
 * qu'un utilisateur qui voit une pop-up système sans contexte.
 */
@Composable
fun OnboardingScreen(onContinue: () -> Unit) {
    val colors = FishGuardTheme.colors

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp)
    ) {
        Spacer(Modifier.height(24.dp))
        Text("Bienvenue sur FishGuard", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Avant d'activer la protection, voici précisément ce que l'app va faire.",
            color = colors.textMuted,
            modifier = Modifier.padding(top = 8.dp, bottom = 28.dp)
        )

        OnboardingItem(
            icon = Icons.Filled.Sms,
            title = "Lire les SMS reçus",
            description = "Chaque SMS entrant est analysé sur l'appareil pour repérer les tentatives d'arnaque, avant que tu ne le lises."
        )
        OnboardingItem(
            icon = Icons.Filled.Notifications,
            title = "Lire le contenu des notifications WhatsApp",
            description = "FishGuard ne se connecte jamais à ton compte WhatsApp : il lit uniquement le texte déjà affiché dans la notification, comme le ferait un bloqueur de spam."
        )
        OnboardingItem(
            icon = Icons.Filled.Lock,
            title = "Tout reste sur ton téléphone",
            description = "L'analyse est locale par défaut. Rien n'est envoyé à un serveur, sauf si tu actives toi-même le mode backend dans les réglages."
        )
        OnboardingItem(
            icon = Icons.Filled.CheckCircle,
            title = "Tu gardes le contrôle",
            description = "Chaque source (SMS, WhatsApp, autres notifications) peut être désactivée à tout moment dans les réglages."
        )
        OnboardingItem(
            icon = Icons.Filled.Phone,
            title = "Protection des appels (optionnelle)",
            description = "FishGuard vérifie si un numéro appelant est déjà dans tes contacts — un numéro connu ne déclenche rien. Pour un numéro inconnu, il te propose d'analyser l'appel, et c'est toujours toi qui décides à la fin s'il faut le signaler."
        )

        Spacer(Modifier.height(24.dp))

        Button(
            onClick = onContinue,
            modifier = Modifier.fillMaxWidth().height(52.dp)
        ) {
            Text("Continuer")
        }
        Text(
            "Android te demandera ensuite de confirmer chaque permission séparément.",
            color = colors.textMuted,
            style = MaterialTheme.typography.labelSmall,
            modifier = Modifier.padding(top = 10.dp)
        )
    }
}

@Composable
private fun OnboardingItem(icon: ImageVector, title: String, description: String) {
    val colors = FishGuardTheme.colors
    Row(
        Modifier
            .fillMaxWidth()
            .padding(bottom = 14.dp)
            .background(colors.surface, RoundedCornerShape(12.dp))
            .padding(14.dp)
    ) {
        Icon(icon, contentDescription = null, tint = BrandCyan, modifier = Modifier.padding(top = 2.dp))
        Column(Modifier.padding(start = 14.dp)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(description, color = colors.textMuted, modifier = Modifier.padding(top = 2.dp))
        }
    }
}
