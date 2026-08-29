package com.fishguard.mobile.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "fishguard_settings")

class SettingsRepository(private val context: Context) {

    companion object {
        val KEY_BACKEND_URL = stringPreferencesKey("backend_url")
        val KEY_MODE = stringPreferencesKey("detection_mode") // "LOCAL_ONLY" | "BACKEND_PREFERRED"
        val KEY_MONITOR_WHATSAPP = booleanPreferencesKey("monitor_whatsapp")
        val KEY_MONITOR_SMS = booleanPreferencesKey("monitor_sms")
        val KEY_MONITOR_OTHER_NOTIFS = booleanPreferencesKey("monitor_other_notifs")
        val KEY_ONBOARDING_DONE = booleanPreferencesKey("onboarding_done")
        val KEY_THEME_MODE = stringPreferencesKey("theme_mode") // "SYSTEM" | "LIGHT" | "DARK"
        val KEY_SENSITIVITY = stringPreferencesKey("sensitivity") // "LOW" | "NORMAL" | "HIGH"
        val KEY_BACKEND_PATH = stringPreferencesKey("backend_path")
        val KEY_BACKEND_API_KEY = stringPreferencesKey("backend_api_key")
        val KEY_CALL_ASSISTANT_ENABLED = booleanPreferencesKey("call_assistant_enabled")
        val KEY_IGNORE_MEDIA_NOTIFS = booleanPreferencesKey("ignore_media_notifs")
        val KEY_IGNORE_GROUP_SUMMARIES = booleanPreferencesKey("ignore_group_summaries")
    }

    val ignoreMediaNotifications = context.dataStore.data.map { it[KEY_IGNORE_MEDIA_NOTIFS] ?: true }
    suspend fun setIgnoreMediaNotifications(enabled: Boolean) {
        context.dataStore.edit { it[KEY_IGNORE_MEDIA_NOTIFS] = enabled }
    }

    val ignoreGroupSummaries = context.dataStore.data.map { it[KEY_IGNORE_GROUP_SUMMARIES] ?: true }
    suspend fun setIgnoreGroupSummaries(enabled: Boolean) {
        context.dataStore.edit { it[KEY_IGNORE_GROUP_SUMMARIES] = enabled }
    }

    val callAssistantEnabled = context.dataStore.data.map { it[KEY_CALL_ASSISTANT_ENABLED] ?: true }
    suspend fun setCallAssistantEnabled(enabled: Boolean) {
        context.dataStore.edit { it[KEY_CALL_ASSISTANT_ENABLED] = enabled }
    }

    val backendPath = context.dataStore.data.map { it[KEY_BACKEND_PATH] ?: "/api/analyze" }
    suspend fun setBackendPath(path: String) {
        context.dataStore.edit { it[KEY_BACKEND_PATH] = path }
    }

    val backendApiKey = context.dataStore.data.map { it[KEY_BACKEND_API_KEY] ?: "" }
    suspend fun setBackendApiKey(key: String) {
        context.dataStore.edit { it[KEY_BACKEND_API_KEY] = key }
    }

    val themeMode = context.dataStore.data.map { it[KEY_THEME_MODE] ?: "SYSTEM" }
    suspend fun setThemeMode(mode: String) {
        context.dataStore.edit { it[KEY_THEME_MODE] = mode }
    }

    val sensitivity = context.dataStore.data.map { it[KEY_SENSITIVITY] ?: "NORMAL" }
    suspend fun setSensitivity(level: String) {
        context.dataStore.edit { it[KEY_SENSITIVITY] = level }
    }

    val onboardingDone = context.dataStore.data.map { it[KEY_ONBOARDING_DONE] ?: false }

    suspend fun setOnboardingDone(done: Boolean) {
        context.dataStore.edit { it[KEY_ONBOARDING_DONE] = done }
    }

    val backendUrl = context.dataStore.data.map { it[KEY_BACKEND_URL] ?: "" }
    val detectionMode = context.dataStore.data.map { it[KEY_MODE] ?: "LOCAL_ONLY" }
    val monitorWhatsapp = context.dataStore.data.map { it[KEY_MONITOR_WHATSAPP] ?: true }
    val monitorSms = context.dataStore.data.map { it[KEY_MONITOR_SMS] ?: true }
    val monitorOtherNotifs = context.dataStore.data.map { it[KEY_MONITOR_OTHER_NOTIFS] ?: false }

    suspend fun setBackendUrl(url: String) {
        context.dataStore.edit { it[KEY_BACKEND_URL] = url }
    }

    suspend fun setDetectionMode(mode: String) {
        context.dataStore.edit { it[KEY_MODE] = mode }
    }

    suspend fun setMonitorWhatsapp(enabled: Boolean) {
        context.dataStore.edit { it[KEY_MONITOR_WHATSAPP] = enabled }
    }

    suspend fun setMonitorSms(enabled: Boolean) {
        context.dataStore.edit { it[KEY_MONITOR_SMS] = enabled }
    }

    suspend fun setMonitorOtherNotifs(enabled: Boolean) {
        context.dataStore.edit { it[KEY_MONITOR_OTHER_NOTIFS] = enabled }
    }
}
