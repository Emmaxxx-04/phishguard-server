package com.fishguard.mobile.notification

import android.app.Notification
import android.service.notification.StatusBarNotification

/**
 * Décide si une notification mérite d'être envoyée au moteur de détection.
 * But : ne pas gaspiller d'analyses (et de place dans l'historique) sur des
 * stickers, photos sans légende, accusés de lecture ou résumés de groupe —
 * qui ne contiennent jamais de texte à analyser de toute façon.
 */
object NotificationFilter {

    /**
     * Textes que WhatsApp/Messages posent tels quels en notification quand il
     * n'y a pas de texte réel (média sans légende, sticker...). Comparaison
     * insensible à la casse sur le texte entier (après retrait d'un éventuel
     * préfixe "Nom de l'expéditeur : " dans les groupes).
     */
    private val MEDIA_PLACEHOLDER_EXACT = setOf(
        // Français
        "photo", "vidéo", "video", "autocollant", "sticker", "gif",
        "message vocal", "document", "contact", "position", "localisation",
        "audio", "image", "carte de visite", "fiche contact",
        // Anglais (au cas où le téléphone est en anglais)
        "voice message", "location", "contact card", "video note",
        "missed voice call", "missed video call",
        // Appels manqués (variantes FR)
        "appel vocal manqué", "appel vidéo manqué"
    )

    /** Motifs de réactions ("a réagi 👍", "Reacted 👍 to...") — jamais un vrai message. */
    private val REACTION_REGEX = Regex(
        """^(.*\s)?(a réagi|reacted|liked|a aimé)\b""",
        RegexOption.IGNORE_CASE
    )

    /** Longueur minimale pour qu'un texte vaille la peine d'être analysé. */
    private const val MIN_MEANINGFUL_LENGTH = 2

    data class FilterSettings(
        val ignoreMedia: Boolean,
        val ignoreGroupSummaries: Boolean
    )

    fun shouldAnalyze(sbn: StatusBarNotification, text: String, settings: FilterSettings): Boolean {
        val trimmed = text.trim()

        if (trimmed.length < MIN_MEANINGFUL_LENGTH) return false

        if (settings.ignoreGroupSummaries && isGroupSummary(sbn)) return false

        if (settings.ignoreMedia) {
            if (REACTION_REGEX.containsMatchIn(trimmed)) return false
            if (isMediaPlaceholder(trimmed)) return false
        }

        return true
    }

    private fun isGroupSummary(sbn: StatusBarNotification): Boolean {
        val flags = sbn.notification?.flags ?: 0
        return (flags and Notification.FLAG_GROUP_SUMMARY) != 0
    }

    private fun isMediaPlaceholder(text: String): Boolean {
        // Dans un groupe, WhatsApp préfixe par "Nom : ", on l'enlève avant de comparer.
        val withoutSenderPrefix = text.substringAfter(": ", text)
        val candidate = withoutSenderPrefix.trim().lowercase()
        return candidate in MEDIA_PLACEHOLDER_EXACT || text.trim().lowercase() in MEDIA_PLACEHOLDER_EXACT
    }
}
