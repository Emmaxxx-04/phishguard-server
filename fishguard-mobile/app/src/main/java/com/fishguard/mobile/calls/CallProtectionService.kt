package com.fishguard.mobile.calls

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.gson.Gson
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.R
import com.fishguard.mobile.data.ThreatEntity
import com.fishguard.mobile.detection.RiskLevel
import com.fishguard.mobile.detection.Sensitivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

data class CallProtectionState(
    val running: Boolean = false,
    val score: Int = 0,
    val riskLevel: String = "SAFE",
    val partialText: String = "",
    val signalCategories: List<String> = emptyList()
)

/**
 * Capte le micro (l'utilisateur doit avoir mis l'appel en haut-parleur) et
 * transcrit en direct via Vosk, hors ligne. Ne démarre jamais tout seul :
 * uniquement après confirmation explicite sur l'écran de consentement
 * (`CallProtectionActivity`). S'arrête automatiquement quand l'appel se
 * termine (voir `CallStateReceiver`) ou quand l'utilisateur appuie sur Arrêter.
 */
class CallProtectionService : Service() {

    companion object {
        const val NOTIF_CHANNEL_ID = "fishguard_call_protection"
        const val NOTIF_ID = 555_555
        const val ACTION_STOP = "com.fishguard.mobile.calls.STOP"

        private val _state = MutableStateFlow(CallProtectionState())
        val state: StateFlow<CallProtectionState> = _state.asStateFlow()
    }

    private var recordJob: Job? = null
    private var audioRecord: AudioRecord? = null
    private lateinit var speechEngine: VoskSpeechEngine
    private lateinit var sessionAnalyzer: CallSessionAnalyzer
    private var callerNumber: String = ""

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        speechEngine = VoskSpeechEngine(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopProtection()
            return START_NOT_STICKY
        }

        callerNumber = intent?.getStringExtra("caller_number") ?: ""
        val app = applicationContext as FishGuardApp

        startForeground(NOTIF_ID, buildNotification("Initialisation..."))

        CoroutineScope(Dispatchers.IO).launch {
            val sensitivityStr = app.settingsRepository.sensitivity.first()
            val sensitivity = when (sensitivityStr) {
                "LOW" -> Sensitivity.LOW
                "HIGH" -> Sensitivity.HIGH
                else -> Sensitivity.NORMAL
            }
            sessionAnalyzer = CallSessionAnalyzer(sender = callerNumber, sensitivity = sensitivity)

            speechEngine.prepareModel { modelState ->
                if (modelState is VoskSpeechEngine.ModelState.Ready) {
                    speechEngine.startRecognizer()
                    startRecording()
                    _state.value = CallProtectionState(running = true)
                }
                if (modelState is VoskSpeechEngine.ModelState.Error) {
                    stopSelf()
                }
            }
        }

        return START_NOT_STICKY
    }

    private fun startRecording() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO)
            != PackageManager.PERMISSION_GRANTED
        ) {
            stopSelf()
            return
        }

        val sampleRate = VoskSpeechEngine.SAMPLE_RATE.toInt()
        val minBuffer = AudioRecord.getMinBufferSize(
            sampleRate, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT
        )
        val bufferSize = maxOf(minBuffer, 4096)

        val record = AudioRecord(
            MediaRecorder.AudioSource.MIC,
            sampleRate,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT,
            bufferSize
        )
        audioRecord = record
        record.startRecording()

        recordJob = CoroutineScope(Dispatchers.Default).launch {
            val buffer = ShortArray(bufferSize / 2)
            while (isActive) {
                val read = record.read(buffer, 0, buffer.size)
                if (read > 0) {
                    val finalText = speechEngine.acceptAudio(buffer, read)
                    if (!finalText.isNullOrBlank()) {
                        onNewTranscript(finalText)
                    } else {
                        val partial = speechEngine.partialText()
                        _state.value = _state.value.copy(partialText = partial)
                    }
                }
            }
        }
    }

    private fun onNewTranscript(fragment: String) {
        val result = sessionAnalyzer.ingest(fragment)
        _state.value = _state.value.copy(
            running = true,
            score = result.score,
            riskLevel = result.riskLevel.name,
            partialText = "",
            signalCategories = result.signals.map { it.category }.distinct()
        )
        updateNotification(result.score)

        if (result.riskLevel == RiskLevel.HIGH || result.riskLevel == RiskLevel.CRITICAL) {
            pushLiveAlert(result.score)
        }
    }

    private fun pushLiveAlert(score: Int) {
        try {
            val manager = getSystemService(NotificationManager::class.java)
            val notification = NotificationCompat.Builder(this, FishGuardApp.CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle("⚠ Signes d'arnaque détectés dans l'appel")
                .setContentText("Score : $score/100 — ne communique aucun code ni montant.")
                .setPriority(NotificationCompat.PRIORITY_MAX)
                .setAutoCancel(true)
                .build()
            manager.notify(NOTIF_ID + 1, notification)
        } catch (e: SecurityException) {
            // Permission de notification non accordée.
        }
    }

    private fun stopProtection() {
        recordJob?.cancel()
        audioRecord?.stop()
        audioRecord?.release()
        audioRecord = null
        speechEngine.release()

        if (::sessionAnalyzer.isInitialized) {
            saveSummaryToHistory()
        }

        _state.value = CallProtectionState(running = false)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun saveSummaryToHistory() {
        val app = applicationContext as FishGuardApp
        val result = sessionAnalyzer.currentResult()
        if (result.originalText.isBlank()) return

        CoroutineScope(Dispatchers.IO).launch {
            app.database.threatDao().insert(
                ThreatEntity(
                    timestamp = System.currentTimeMillis(),
                    sourceApp = "Appel",
                    sender = callerNumber,
                    messagePreview = "Résumé de l'appel protégé — score ${result.score}/100",
                    fullMessage = "Transcription locale de l'appel :\n\n${sessionAnalyzer.fullTranscript}",
                    score = result.score,
                    riskLevel = result.riskLevel.name,
                    engine = "local",
                    signalsJson = Gson().toJson(result.signals)
                )
            )
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        recordJob?.cancel()
        audioRecord?.release()
        if (::speechEngine.isInitialized) speechEngine.release()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID, "Protection d'appel active", NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = Intent(this, CallProtectionService::class.java).apply { action = ACTION_STOP }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIF_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("Protection d'appel active")
            .setContentText(text)
            .setOngoing(true)
            .addAction(0, "Arrêter", stopPendingIntent)
            .build()
    }

    private fun updateNotification(score: Int) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIF_ID, buildNotification("Score actuel : $score/100"))
    }
}
