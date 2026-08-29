package com.fishguard.mobile.detection

/** Niveau de risque calculé pour un message analysé. */
enum class RiskLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL }

/**
 * Une catégorie de menace détectée, avec le texte qui a déclenché le signal.
 * Sert à construire l'explication affichée à l'utilisateur (transparence du score).
 */
data class ThreatSignal(
    val category: String,
    val explanation: String,
    val weight: Int
)

data class DetectionResult(
    val sourceApp: String,
    val originalText: String,
    val score: Int,
    val riskLevel: RiskLevel,
    val signals: List<ThreatSignal>,
    val engine: String
) {
    companion object {
        fun scoreToLevel(score: Int): RiskLevel = when {
            score >= 80 -> RiskLevel.CRITICAL
            score >= 55 -> RiskLevel.HIGH
            score >= 30 -> RiskLevel.MEDIUM
            score >= 12 -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
    }
}
