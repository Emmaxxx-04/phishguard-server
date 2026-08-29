package com.fishguard.mobile.calls

import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.telephony.TelephonyManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Écoute uniquement l'ÉTAT de l'appel (sonne / décroché / raccroché) — jamais
 * le contenu audio, ce qui rend cette détection légale sans consentement
 * particulier à ce stade.
 *
 * Deux comportements distincts selon que le numéro est déjà enregistré comme
 * contact (voir `ContactsLookup`) :
 *  - Numéro connu : une simple notification propose l'analyse — discrète, à
 *    ouvrir quand on veut.
 *  - Numéro inconnu : un pop-up s'affiche directement à l'écran (comme un
 *    appel entrant), pour prévenir immédiatement et demander si on veut
 *    analyser — plus visible car plus à risque statistiquement.
 *
 * Dans les deux cas, l'analyse elle-même reste toujours déclenchée par un
 * geste explicite de l'utilisateur, jamais automatiquement.
 */
class CallStateReceiver : BroadcastReceiver() {

    companion object {
        const val PROMPT_NOTIFICATION_ID = 424_242
        // Le numéro n'est fiable qu'à l'état RINGING sur les versions récentes
        // d'Android ; on le mémorise pour le réutiliser à l'état OFFHOOK.
        private var lastRingingNumber: String = ""
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != "android.intent.action.PHONE_STATE") return
        val app = context.applicationContext as FishGuardApp
        val state = intent.getStringExtra(TelephonyManager.EXTRA_STATE)
        val incomingNumber = intent.getStringExtra(TelephonyManager.EXTRA_INCOMING_NUMBER)

        if (state == TelephonyManager.EXTRA_STATE_RINGING && !incomingNumber.isNullOrBlank()) {
            lastRingingNumber = incomingNumber
        }

        CoroutineScope(Dispatchers.IO).launch {
            when (state) {
                TelephonyManager.EXTRA_STATE_OFFHOOK -> {
                    val number = incomingNumber?.ifBlank { null } ?: lastRingingNumber
                    if (app.settingsRepository.callAssistantEnabled.first()) {
                        val isKnown = ContactsLookup.isKnownContact(context, number)
                        if (isKnown) {
                            showKnownNumberNotification(context, number)
                        } else {
                            showUnknownNumberPopup(context, number)
                        }
                    }
                }
                TelephonyManager.EXTRA_STATE_IDLE -> {
                    NotificationManagerCompat.from(context).cancel(PROMPT_NOTIFICATION_ID)
                    lastRingingNumber = ""
                    val stopIntent = Intent(context, CallProtectionService::class.java).apply {
                        action = CallProtectionService.ACTION_STOP
                    }
                    context.startService(stopIntent)
                }
            }
        }
    }

    /** Numéro déjà dans les contacts : simple notification, non intrusive. */
    private fun showKnownNumberNotification(context: Context, number: String) {
        val pendingIntent = buildConsentPendingIntent(context, number, isUnknown = false)

        val notification = NotificationCompat.Builder(context, FishGuardApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Appel en cours")
            .setContentText("Numéro enregistré dans tes contacts. Analyser quand même ?")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        try {
            NotificationManagerCompat.from(context).notify(PROMPT_NOTIFICATION_ID, notification)
        } catch (e: SecurityException) {
            // Permission de notification non accordée : rien de plus à faire.
        }
    }

    /**
     * Numéro absent des contacts : tente d'afficher directement un pop-up
     * plein écran (`fullScreenIntent`, le mécanisme standard pour un appel
     * entrant ou une alarme). Si l'appareil n'autorise pas cet affichage
     * (réglage refusé sur Android 14+, ou notification masquée), la
     * notification à haute priorité reste affichée en repli — jamais muette.
     */
    private fun showUnknownNumberPopup(context: Context, number: String) {
        val pendingIntent = buildConsentPendingIntent(context, number, isUnknown = true)

        val canUseFullScreen = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            context.getSystemService(NotificationManager::class.java)?.canUseFullScreenIntent() ?: false
        } else {
            true
        }

        val builder = NotificationCompat.Builder(context, FishGuardApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Numéro inconnu")
            .setContentText("Ce numéro n'est pas dans tes contacts. Analyser cet appel ?")
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)

        if (canUseFullScreen) {
            builder.setFullScreenIntent(pendingIntent, true)
        }

        try {
            NotificationManagerCompat.from(context).notify(PROMPT_NOTIFICATION_ID, builder.build())
        } catch (e: SecurityException) {
            // Permission de notification non accordée : rien de plus à faire.
        }
    }

    private fun buildConsentPendingIntent(context: Context, number: String, isUnknown: Boolean): PendingIntent {
        val openIntent = Intent(context, CallProtectionActivity::class.java).apply {
            putExtra("caller_number", number)
            putExtra("is_unknown_number", isUnknown)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        return PendingIntent.getActivity(
            context, PROMPT_NOTIFICATION_ID, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}
