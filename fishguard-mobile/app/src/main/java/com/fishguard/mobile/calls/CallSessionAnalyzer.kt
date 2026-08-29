package com.fishguard.mobile.calls

import com.fishguard.mobile.detection.DetectionResult
import com.fishguard.mobile.detection.RuleBasedDetector
import com.fishguard.mobile.detection.Sensitivity

/**
 * Accumule au fil de l'appel le texte transcrit localement et réévalue le score
 * à chaque nouveau fragment. Réutilise tel quel `RuleBasedDetector` (déjà rodé
 * sur les SMS/WhatsApp) — comme il rescanne tout le texte à chaque appel, un
 * signal détecté tôt dans la conversation (ex: "je suis du service client")
 * reste comptabilisé même si le sujet a changé depuis, exactement le
 * comportement voulu pour une accumulation progressive.
 */
class CallSessionAnalyzer(
    private val sender: String,
    private val sensitivity: Sensitivity = Sensitivity.NORMAL,
    private val detector: RuleBasedDetector = RuleBasedDetector()
) {
    private val transcriptBuilder = StringBuilder()

    val fullTranscript: String get() = transcriptBuilder.toString()

    /** Ajoute un fragment fraîchement transcrit et retourne le score à jour. */
    fun ingest(fragment: String): DetectionResult {
        if (fragment.isNotBlank()) {
            if (transcriptBuilder.isNotEmpty()) transcriptBuilder.append(" ")
            transcriptBuilder.append(fragment.trim())
        }
        return detector.analyze(
            sourceApp = "Appel",
            text = transcriptBuilder.toString().ifBlank { " " },
            sender = sender,
            sensitivity = sensitivity
        )
    }

    /** Résultat courant sans ajouter de nouveau texte (pour le résumé final par ex.). */
    fun currentResult(): DetectionResult = detector.analyze(
        sourceApp = "Appel",
        text = transcriptBuilder.toString().ifBlank { " " },
        sender = sender,
        sensitivity = sensitivity
    )
}
