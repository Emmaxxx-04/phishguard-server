package com.fishguard.mobile.ui.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.detection.RemoteApiClient
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

data class SettingsUiState(
    val backendUrl: String = "",
    val backendPath: String = "/api/analyze",
    val backendApiKey: String = "",
    val backendPreferred: Boolean = false,
    val monitorWhatsapp: Boolean = true,
    val monitorSms: Boolean = true,
    val monitorOtherNotifs: Boolean = false,
    val themeMode: String = "SYSTEM",
    val sensitivity: String = "NORMAL",
    val callAssistantEnabled: Boolean = true,
    val ignoreMediaNotifications: Boolean = true,
    val ignoreGroupSummaries: Boolean = true
)

enum class ConnectionTestState { IDLE, TESTING, SUCCESS, FAILURE }

class SettingsViewModel(private val app: FishGuardApp) : ViewModel() {

    private val repo = app.settingsRepository

    val uiState = combine(
        listOf(
            repo.backendUrl, repo.backendPath, repo.backendApiKey, repo.detectionMode,
            repo.monitorWhatsapp, repo.monitorSms, repo.monitorOtherNotifs, repo.themeMode,
            repo.sensitivity, repo.callAssistantEnabled, repo.ignoreMediaNotifications,
            repo.ignoreGroupSummaries
        )
    ) { values ->
        SettingsUiState(
            backendUrl = values[0] as String,
            backendPath = values[1] as String,
            backendApiKey = values[2] as String,
            backendPreferred = (values[3] as String) == "BACKEND_PREFERRED",
            monitorWhatsapp = values[4] as Boolean,
            monitorSms = values[5] as Boolean,
            monitorOtherNotifs = values[6] as Boolean,
            themeMode = values[7] as String,
            sensitivity = values[8] as String,
            callAssistantEnabled = values[9] as Boolean,
            ignoreMediaNotifications = values[10] as Boolean,
            ignoreGroupSummaries = values[11] as Boolean
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SettingsUiState())

    var connectionTestState = androidx.compose.runtime.mutableStateOf(ConnectionTestState.IDLE)
        private set

    fun setBackendUrl(url: String) = viewModelScope.launch { repo.setBackendUrl(url) }
    fun setBackendPath(path: String) = viewModelScope.launch { repo.setBackendPath(path) }
    fun setBackendApiKey(key: String) = viewModelScope.launch { repo.setBackendApiKey(key) }

    fun setBackendPreferred(preferred: Boolean) = viewModelScope.launch {
        repo.setDetectionMode(if (preferred) "BACKEND_PREFERRED" else "LOCAL_ONLY")
    }

    fun setMonitorWhatsapp(enabled: Boolean) = viewModelScope.launch { repo.setMonitorWhatsapp(enabled) }
    fun setMonitorSms(enabled: Boolean) = viewModelScope.launch { repo.setMonitorSms(enabled) }
    fun setMonitorOtherNotifs(enabled: Boolean) = viewModelScope.launch { repo.setMonitorOtherNotifs(enabled) }
    fun setThemeMode(mode: String) = viewModelScope.launch { repo.setThemeMode(mode) }
    fun setSensitivity(level: String) = viewModelScope.launch { repo.setSensitivity(level) }
    fun setCallAssistantEnabled(enabled: Boolean) = viewModelScope.launch { repo.setCallAssistantEnabled(enabled) }
    fun setIgnoreMediaNotifications(enabled: Boolean) = viewModelScope.launch { repo.setIgnoreMediaNotifications(enabled) }
    fun setIgnoreGroupSummaries(enabled: Boolean) = viewModelScope.launch { repo.setIgnoreGroupSummaries(enabled) }

    fun testConnection(url: String, path: String, apiKey: String) {
        if (url.isBlank()) return
        connectionTestState.value = ConnectionTestState.TESTING
        viewModelScope.launch {
            val result = RemoteApiClient(url, path, apiKey).testConnection()
            connectionTestState.value = if (result.isSuccess) ConnectionTestState.SUCCESS else ConnectionTestState.FAILURE
        }
    }

    fun pushTestNotification() {
        com.fishguard.mobile.notification.ThreatAlerter.pushTestNotification(app)
    }
}
