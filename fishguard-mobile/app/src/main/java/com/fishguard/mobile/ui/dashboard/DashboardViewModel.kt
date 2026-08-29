package com.fishguard.mobile.ui.dashboard

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.data.ThreatEntity
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn

data class DashboardUiState(
    val totalAnalyzed: Int = 0,
    val riskyCount: Int = 0,
    val safeCount: Int = 0,
    val criticalCount: Int = 0,
    val recentThreats: List<ThreatEntity> = emptyList()
)

class DashboardViewModel(app: FishGuardApp) : ViewModel() {

    val uiState: StateFlow<DashboardUiState> = combine(
        app.database.threatDao().observeAll(),
        app.database.threatDao().observeRisky()
    ) { all, risky ->
        DashboardUiState(
            totalAnalyzed = all.size,
            riskyCount = risky.size,
            safeCount = all.size - risky.size,
            criticalCount = all.count { it.riskLevel == "CRITICAL" },
            recentThreats = all.take(5)
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), DashboardUiState())
}
