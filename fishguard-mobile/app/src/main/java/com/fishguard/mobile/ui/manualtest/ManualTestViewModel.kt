package com.fishguard.mobile.ui.manualtest

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.detection.DetectionResult
import com.fishguard.mobile.notification.ThreatAlerter
import kotlinx.coroutines.launch

data class ManualTestUiState(
    val isAnalyzing: Boolean = false,
    val result: DetectionResult? = null,
    val saved: Boolean = false
)

class ManualTestViewModel(private val app: FishGuardApp) : ViewModel() {

    var uiState = androidx.compose.runtime.mutableStateOf(ManualTestUiState())
        private set

    fun analyze(sourceApp: String, sender: String, text: String) {
        if (text.isBlank()) return
        uiState.value = uiState.value.copy(isAnalyzing = true, result = null, saved = false)
        viewModelScope.launch {
            val result = ThreatAlerter.analyzeOnly(app, sourceApp, sender, text)
            uiState.value = uiState.value.copy(isAnalyzing = false, result = result)
        }
    }

    fun saveToHistory(sourceApp: String, sender: String, text: String) {
        val result = uiState.value.result ?: return
        viewModelScope.launch {
            ThreatAlerter.persistResult(app, sourceApp, sender, text, result)
            uiState.value = uiState.value.copy(saved = true)
        }
    }

    fun reset() {
        uiState.value = ManualTestUiState()
    }
}
