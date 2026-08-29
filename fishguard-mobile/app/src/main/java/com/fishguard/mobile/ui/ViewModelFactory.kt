package com.fishguard.mobile.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.ui.calls.ScamNumbersViewModel
import com.fishguard.mobile.ui.dashboard.DashboardViewModel
import com.fishguard.mobile.ui.manualtest.ManualTestViewModel
import com.fishguard.mobile.ui.settings.SettingsViewModel
import com.fishguard.mobile.ui.threats.ThreatListViewModel

class FishGuardViewModelFactory(private val app: FishGuardApp) : ViewModelProvider.Factory {
    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return when {
            modelClass.isAssignableFrom(DashboardViewModel::class.java) -> DashboardViewModel(app) as T
            modelClass.isAssignableFrom(ThreatListViewModel::class.java) -> ThreatListViewModel(app) as T
            modelClass.isAssignableFrom(SettingsViewModel::class.java) -> SettingsViewModel(app) as T
            modelClass.isAssignableFrom(ManualTestViewModel::class.java) -> ManualTestViewModel(app) as T
            modelClass.isAssignableFrom(ScamNumbersViewModel::class.java) -> ScamNumbersViewModel(app) as T
            else -> throw IllegalArgumentException("ViewModel inconnu : ${modelClass.name}")
        }
    }
}
