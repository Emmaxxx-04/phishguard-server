package com.fishguard.mobile.notification

import android.Manifest
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import com.fishguard.mobile.MainActivity
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.R
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.detection.DetectionMode
import com.fishguard.mobile.detection.DetectionResult
import com.fishguard.mobile.detection.RiskLevel
import com.fishguard.mobile.detection.Sensitivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Point d'entrée partagé par le NotificationListenerService, le SmsReceiver et
 * l'écran de test manuel : lance l'analyse, enregistre le résultat en base, et
 * pousse une alerte système si le score dépasse le seuil "à risque".
 *
 * Tout est enveloppé dans un try/catch : une analyse qui échoue (réseau,
 * permission manquante...) ne doit jamais faire planter le service en
 * arrière-plan, seulement passer en mode dégradé silencieusement.
 */
object ThreatAlerter {

    private const val TAG = "FishGuard/ThreatAlerter"

    fun analyzeAndAlert(context: Context, sourceApp: String, sender: String, text: String) {
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val app = context.applicationContext as FishGuardApp
                val result = runDetection(app, sourceApp, sender, text)
                persistAndMaybeAlert(context, app, sourceApp, sender, text, result)
            } catch (e: Exception) {
                Log.e(TAG, "Échec de l'analyse en arrière-plan", e)
            }
        }
    }

    /** Utilisé par l'écran "Tester un message" : analyse sans rien enregistrer. */
    suspend fun analyzeOnly(context: Context, sourceApp: String, sender: String, text: String): DetectionResult {
        val app = context.applicationContext as FishGuardApp
        return runDetection(app, sourceApp, sender, text)
    }

    /** Enregistre un résultat (venant par ex. de l'écran de test manuel) et alerte si nécessaire. */
    suspend fun persistResult(context: Context, sourceApp: String, sender: String, text: String, result: DetectionResult) {
        val app = context.applicationContext as FishGuardApp
        persistAndMaybeAlert(context, app, sourceApp, sender, text, result)
    }

    private suspend fun runDetection(app: FishGuardApp, sourceApp: String, sender: String, text: String): DetectionResult {
        val backendUrl = app.settingsRepository.backendUrl.first()
        val backendPath = app.settingsRepository.backendPath.first()
        val backendApiKey = app.settingsRepository.backendApiKey.first()
        val modeStr = app.settingsRepository.detectionMode.first()
        val mode = if (modeStr == "BACKEND_PREFERRED") DetectionMode.BACKEND_PREFERRED else DetectionMode.LOCAL_ONLY
        val sensitivityStr = app.settingsRepository.sensitivity.first()
        val sensitivity = when (sensitivityStr) {
            "LOW" -> Sensitivity.LOW
            "HIGH" -> Sensitivity.HIGH
            else -> Sensitivity.NORMAL
        }

        return app.detectionEngine.analyze(
            sourceApp = sourceApp,
            text = text,
            sender = sender,
            sensitivity = sensitivity,
            mode = mode,
            backendUrl = backendUrl,
            backendPath = backendPath,
            backendApiKey = backendApiKey
        )
    }

    private suspend fun persistAndMaybeAlert(
        context: Context,
        app: FishGuardApp,
        sourceApp: String,
        sender: String,
        text: String,
        result: DetectionResult
    ) {
        val entity = ThreatEntity(
            timestamp = System.currentTimeMillis(),
            sourceApp = sourceApp,
            sender = sender,
            messagePreview = text.take(120),
            fullMessage = text,
            score = result.score,
            riskLevel = result.riskLevel.name,
            engine = result.engine,
            signalsJson = Gson().toJson(result.signals)
        )
        val id = app.database.threatDao().insert(entity)

        if (result.riskLevel == RiskLevel.HIGH || result.riskLevel == RiskLevel.CRITICAL) {
            pushSystemAlert(context, id, sourceApp, result)
        }
    }

    private fun hasNotificationPermission(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun pushSystemAlert(context: Context, threatId: Long, sourceApp: String, result: DetectionResult) {
        if (!hasNotificationPermission(context)) {
            // La menace reste visible dans l'historique de l'app même sans permission système.
            Log.w(TAG, "Permission POST_NOTIFICATIONS manquante : alerte non affichée (voir Historique dans l'app)")
            return
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            putExtra("threat_id", threatId)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context, threatId.toInt(), openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val title = if (result.riskLevel == RiskLevel.CRITICAL) {
            "⚠ Arnaque probable détectée ($sourceApp)"
        } else {
            "Message suspect détecté ($sourceApp)"
        }

        val notification = NotificationCompat.Builder(context, FishGuardApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText("Score de risque : ${result.score}/100 — touchez pour voir le détail")
            .setStyle(NotificationCompat.BigTextStyle().bigText(result.originalText.take(200)))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        try {
            androidx.core.app.NotificationManagerCompat.from(context).notify(threatId.toInt(), notification)
        } catch (e: SecurityException) {
            Log.w(TAG, "Notification refusée par le système", e)
        }
    }

    /** Notification factice utilisée par le bouton "Tester la notification" des réglages. */
    fun pushTestNotification(context: Context) {
        if (!hasNotificationPermission(context)) return
        val notification = NotificationCompat.Builder(context, FishGuardApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Test FishGuard")
            .setContentText("Si tu vois cette notification, les alertes fonctionnent correctement.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        try {
            androidx.core.app.NotificationManagerCompat.from(context).notify(999_999, notification)
        } catch (e: SecurityException) {
            Log.w(TAG, "Notification de test refusée par le système", e)
        }
    }
}
