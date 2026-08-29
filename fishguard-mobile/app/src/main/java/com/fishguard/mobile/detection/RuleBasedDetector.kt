package com.fishguard.mobile.detection

import kotlin.math.min

/** Sensibilité du moteur : décale le score final avant classification. */
enum class Sensitivity(val bias: Int) {
    LOW(-12),    // moins de faux positifs, quitte à rater des cas limites
    NORMAL(0),
    HIGH(12)     // plus prudent, davantage d'alertes potentiellement bénignes
}

/** Un numéro brut (non enregistré comme contact) ressemble typiquement à ceci. */
private val RAW_PHONE_PATTERN = Regex("""^\+?\d[\d\s.-]{6,}$""")

/**
 * Moteur de détection 100% local (aucune donnée envoyée hors de l'appareil).
 * Fonctionne toujours, y compris hors ligne — c'est le mode par défaut.
 */
class RuleBasedDetector {

    fun analyze(
        sourceApp: String,
        text: String,
        sender: String = "",
        sensitivity: Sensitivity = Sensitivity.NORMAL
    ): DetectionResult {
        val matched = mutableListOf<ThreatSignal>()
        var rawScore = 0

        for (pattern in ScamPatterns.all) {
            if (pattern.regex.containsMatchIn(text)) {
                matched += ThreatSignal(pattern.category, pattern.explanation, pattern.weight)
                rawScore += pattern.weight
            }
        }

        val hasImpersonation = matched.any { it.category == "Usurpation d'identité" || it.category == "Changement de numéro suspect" }
        val hasMoneyAsk = matched.any {
            it.category == "Promesse de remboursement multiplié" || it.category == "Demande de transfert d'argent"
        }
        val hasUrgency = matched.any { it.category == "Urgence temporelle" || it.category == "Situation de détresse fabriquée" }
        val hasCredentialTheft = matched.any {
            it.category == "Demande de code de vérification" || it.category == "Demande de coordonnées bancaires"
        }

        // --- Bonus de combinaison : plus révélateurs que la somme de leurs parties ---
        if (hasImpersonation && hasMoneyAsk) {
            rawScore += 15
            matched += ThreatSignal(
                "Schéma combiné",
                "Combinaison usurpation + demande d'argent : signature typique d'une arnaque ciblée (« hameçonnage social »).",
                15
            )
        }
        if (hasMoneyAsk && hasUrgency) {
            rawScore += 10
            matched += ThreatSignal(
                "Pression + demande",
                "La demande d'argent est associée à une pression d'urgence, ce qui réduit le temps de réflexion de la victime.",
                10
            )
        }
        if (hasCredentialTheft && hasUrgency) {
            rawScore += 12
            matched += ThreatSignal(
                "Vol d'identifiants sous pression",
                "La demande de code ou d'informations bancaires est associée à une urgence artificielle : schéma classique de prise de contrôle de compte.",
                12
            )
        }

        // --- Incohérence expéditeur : numéro non enregistré qui prétend être un proche ---
        if (hasImpersonation && sender.isNotBlank() && RAW_PHONE_PATTERN.matches(sender.trim())) {
            rawScore += 20
            matched += ThreatSignal(
                "Numéro inconnu + usurpation",
                "Le message prétend être quelqu'un de connu, mais il provient d'un numéro qui n'est pas enregistré comme contact.",
                20
            )
        }

        // --- Style d'écriture : majuscules excessives (indicateur faible, non cumulé si texte très court) ---
        val letters = text.count { it.isLetter() }
        if (letters >= 20) {
            val capsRatio = text.count { it.isUpperCase() }.toDouble() / letters
            if (capsRatio > 0.6) {
                rawScore += 8
                matched += ThreatSignal(
                    "Majuscules excessives",
                    "Message rédigé presque entièrement en majuscules, technique fréquente pour attirer l'attention et créer un sentiment d'urgence.",
                    8
                )
            }
        }

        val biased = rawScore + sensitivity.bias
        val score = biased.coerceIn(0, 100)

        return DetectionResult(
            sourceApp = sourceApp,
            originalText = text,
            score = score,
            riskLevel = DetectionResult.scoreToLevel(score),
            signals = matched,
            engine = "local"
        )
    }
}
