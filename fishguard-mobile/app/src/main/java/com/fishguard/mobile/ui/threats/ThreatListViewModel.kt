package com.fishguard.mobile.ui.threats

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.data.ThreatEntity
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

enum class ThreatFilter { ALL, RISKY, SAFE }

data class ThreatListUiState(
    val all: List<ThreatEntity> = emptyList(),
    val risky: List<ThreatEntity> = emptyList(),
    val safe: List<ThreatEntity> = emptyList()
)

class ThreatListViewModel(private val app: FishGuardApp) : ViewModel() {

    val uiState: StateFlow<ThreatListUiState> = combine(
        app.database.threatDao().observeAll(),
        app.database.threatDao().observeRisky(),
        app.database.threatDao().observeSafe()
    ) { all, risky, safe -> ThreatListUiState(all, risky, safe) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), ThreatListUiState())

    fun clearHistory() {
        viewModelScope.launch { app.database.threatDao().clearAll() }
    }
}
