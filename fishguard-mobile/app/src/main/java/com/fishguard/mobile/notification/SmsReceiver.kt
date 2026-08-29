package com.fishguard.mobile.notification

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.fishguard.mobile.FishGuardApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Complète le NotificationListenerService : capte le SMS dès son arrivée via
 * l'API Telephony officielle, sans dépendre de l'affichage d'une notification
 * (utile si FishGuard est réglé comme appli SMS par défaut, ou simplement pour
 * ne rien manquer si une autre notif écrase la précédente avant lecture).
 */
class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val app = context.applicationContext as FishGuardApp
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        val fullBody = messages.joinToString("") { it.messageBody ?: "" }
        val sender = messages.firstOrNull()?.originatingAddress ?: ""
        if (fullBody.isBlank()) return

        CoroutineScope(Dispatchers.IO).launch {
            if (!app.settingsRepository.monitorSms.first()) return@launch
            ThreatAlerter.analyzeAndAlert(context.applicationContext, "SMS", sender, fullBody)
        }
    }
}
