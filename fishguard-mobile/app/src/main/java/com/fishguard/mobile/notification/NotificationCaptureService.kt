package com.fishguard.mobile.notification

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import com.fishguard.mobile.FishGuardApp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Écoute TOUTES les notifications système une fois que l'utilisateur a accordé
 * l'accès dans Réglages > Applications > Accès spécial > Accès aux notifications.
 * Android ne permet aucune autre façon de lire le contenu des notifications
 * WhatsApp — il n'existe pas d'API publique WhatsApp pour ça (chiffrement de bout
 * en bout), donc c'est la seule voie légitime, et elle nécessite un geste explicite
 * de l'utilisateur.
 *
 * Toutes les notifications ne sont pas analysées : `NotificationFilter` écarte
 * en amont les stickers, photos sans légende, réactions et résumés de groupe —
 * réglable dans Réglages > Sources surveillées.
 */
class NotificationCaptureService : NotificationListenerService() {

    companion object {
        // Ajuste selon les apps que tu veux surveiller.
        private val WHATSAPP_PACKAGES = setOf("com.whatsapp", "com.whatsapp.w4b")
        private val SMS_PACKAGES = setOf(
            "com.google.android.apps.messaging", // Google Messages
            "com.android.mms",
            "com.samsung.android.messaging"
        )
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        val extras = sbn.notification?.extras ?: return

        val text = (extras.getCharSequence("android.text")
            ?: extras.getCharSequence("android.bigText"))?.toString()
            ?: return

        if (text.isBlank()) return

        val sender = extras.getCharSequence("android.title")?.toString() ?: ""

        val app = applicationContext as FishGuardApp

        CoroutineScope(Dispatchers.IO).launch {
            val sourceLabel = when (pkg) {
                in WHATSAPP_PACKAGES -> {
                    if (!app.settingsRepository.monitorWhatsapp.first()) return@launch
                    "WhatsApp"
                }
                in SMS_PACKAGES -> {
                    if (!app.settingsRepository.monitorSms.first()) return@launch
                    "SMS"
                }
                else -> {
                    if (!app.settingsRepository.monitorOtherNotifs.first()) return@launch
                    sender.ifBlank { pkg }
                }
            }

            val filterSettings = NotificationFilter.FilterSettings(
                ignoreMedia = app.settingsRepository.ignoreMediaNotifications.first(),
                ignoreGroupSummaries = app.settingsRepository.ignoreGroupSummaries.first()
            )
            if (!NotificationFilter.shouldAnalyze(sbn, text, filterSettings)) return@launch

            ThreatAlerter.analyzeAndAlert(applicationContext, sourceLabel, sender, text)
        }
    }

    override fun onNotificationRemoved(sbn: StatusBarNotification) {
        // Rien à faire : on ne conserve que les résultats d'analyse, pas les notifs brutes.
    }
}
