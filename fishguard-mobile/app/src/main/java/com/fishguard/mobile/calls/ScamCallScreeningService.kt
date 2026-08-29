package com.fishguard.mobile.calls

import android.telecom.Call
import android.telecom.CallScreeningService
import android.telecom.CallScreeningService.CallResponse
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.google.gson.Gson
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.R
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.data.normalizePhoneNumber
import com.fishguard.mobile.detection.ThreatSignal
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Rôle système officiel pour "filtrer les appels" (le même utilisé par
 * Truecaller, Google Téléphone, etc.). Ne donne PAS accès au contenu de la
 * conversation — seulement au numéro appelant, avant que le téléphone sonne.
 * L'utilisateur doit accorder ce rôle une fois (voir Réglages > Protection
 * des appels), Android ne l'accorde jamais automatiquement.
 */
class ScamCallScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        val rawNumber = callDetails.handle?.schemeSpecificPart ?: run {
            respondNeutral(callDetails)
            return
        }
        val normalized = normalizePhoneNumber(rawNumber)
        val app = applicationContext as FishGuardApp

        CoroutineScope(Dispatchers.IO).launch {
            val match = app.database.scamNumberDao().findByNormalizedNumber(normalized)
            if (match != null) {
                notifyFlaggedCall(rawNumber, match.note)
                logCall(app, rawNumber, matched = true, note = match.note)
            }
        }

        // On ne bloque jamais automatiquement l'appel (trop risqué en cas de faux
        // positif) : on laisse toujours sonner, et on prévient en parallèle.
        respondNeutral(callDetails)
    }

    private fun respondNeutral(callDetails: Call.Details) {
        val response = CallResponse.Builder()
            .setDisallowCall(false)
            .setRejectCall(false)
            .setSkipCallLog(false)
            .setSkipNotification(false)
            .build()
        respondToCall(callDetails, response)
    }

    private fun notifyFlaggedCall(number: String, note: String) {
        val body = if (note.isNotBlank()) {
            "$number a été signalé : $note"
        } else {
            "$number a déjà été signalé comme suspect par toi ou un membre de l'équipe."
        }
        val notification = NotificationCompat.Builder(this, FishGuardApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("⚠ Appel d'un numéro signalé")
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setAutoCancel(true)
            .build()
        try {
            NotificationManagerCompat.from(this).notify(number.hashCode(), notification)
        } catch (e: SecurityException) {
            // Permission de notification non accordée : rien de plus à faire.
        }
    }

    private suspend fun logCall(app: FishGuardApp, number: String, matched: Boolean, note: String) {
        val signals = listOf(
            ThreatSignal(
                "Numéro signalé",
                note.ifBlank { "Ce numéro a déjà été signalé comme suspect." },
                40
            )
        )
        app.database.threatDao().insert(
            ThreatEntity(
                timestamp = System.currentTimeMillis(),
                sourceApp = "Appel",
                sender = number,
                messagePreview = "Appel d'un numéro déjà signalé",
                fullMessage = "Appel entrant depuis un numéro déjà signalé : $number\nNote : $note",
                score = 60,
                riskLevel = "HIGH",
                engine = "local",
                signalsJson = Gson().toJson(signals)
            )
        )
    }
}
