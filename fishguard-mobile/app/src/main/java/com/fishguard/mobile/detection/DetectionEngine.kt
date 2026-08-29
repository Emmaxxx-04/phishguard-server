package com.fishguard.mobile.detection

enum class DetectionMode { LOCAL_ONLY, BACKEND_PREFERRED }

/**
 * Point d'entrée unique utilisé par le service de capture des notifications et
 * le receiver SMS. Applique toujours l'analyse locale (rapide, offline, gratuite),
 * et si le mode BACKEND_PREFERRED est actif et qu'une URL est configurée,
 * tente en plus le backend Flask — avec repli silencieux sur le résultat local
 * en cas d'échec réseau (pas de crash, pas de blocage de l'UX).
 */
class DetectionEngine(
    private val localDetector: RuleBasedDetector = RuleBasedDetector()
) {

    suspend fun analyze(
        sourceApp: String,
        text: String,
        sender: String = "",
        sensitivity: Sensitivity = Sensitivity.NORMAL,
        mode: DetectionMode,
        backendUrl: String?,
        backendPath: String = "/api/analyze",
        backendApiKey: String = ""
    ): DetectionResult {
        val localResult = localDetector.analyze(sourceApp, text, sender, sensitivity)

        if (mode == DetectionMode.LOCAL_ONLY || backendUrl.isNullOrBlank()) {
            return localResult
        }

        return try {
            val remote = RemoteApiClient(backendUrl, backendPath, backendApiKey).analyze(sourceApp, text)
            // On garde le score le plus élevé des deux moteurs : mieux vaut une
            // fausse alerte de plus qu'une arnaque manquée.
            if (remote.score >= localResult.score) remote else localResult
        } catch (e: Exception) {
            localResult
        }
    }
}
