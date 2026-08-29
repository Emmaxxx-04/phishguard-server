package com.fishguard.mobile

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import com.fishguard.mobile.data.AppDatabase
import com.fishguard.mobile.data.SettingsRepository
import com.fishguard.mobile.detection.DetectionEngine

class FishGuardApp : Application() {

    val database by lazy { AppDatabase.getInstance(this) }
    val settingsRepository by lazy { SettingsRepository(this) }
    val detectionEngine by lazy { DetectionEngine() }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Alertes FishGuard",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerte immédiate lorsqu'un message suspect est détecté"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "fishguard_alerts"
    }
}
