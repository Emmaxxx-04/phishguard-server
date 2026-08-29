package com.fishguard.mobile.ui.calls

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.fishguard.mobile.FishGuardApp
import com.fishguard.mobile.data.ScamNumberEntity
import com.fishguard.mobile.data.normalizePhoneNumber
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** Règle stricte : un signalement doit avoir un motif d'au moins cette longueur. */
const val MIN_REPORT_NOTE_LENGTH = 10

sealed class ReportResult {
    data object Success : ReportResult()
    data object NumberBlank : ReportResult()
    data object NoteTooShort : ReportResult()
    data object NotConfirmed : ReportResult()
}

class ScamNumbersViewModel(private val app: FishGuardApp) : ViewModel() {

    val numbers: StateFlow<List<ScamNumberEntity>> = app.database.scamNumberDao().observeAll()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    /**
     * Un numéro n'entre dans la liste rouge qu'à trois conditions strictes :
     * un motif suffisamment détaillé (pas juste "arnaque"), une confirmation
     * explicite de l'utilisateur (case à cocher côté écran), et — quand elle
     * existe — la trace du score d'analyse d'appel qui a motivé le signalement.
     */
    fun report(
        number: String,
        note: String,
        confirmed: Boolean,
        source: String = "MANUAL",
        linkedScore: Int? = null
    ): ReportResult {
        if (number.isBlank()) return ReportResult.NumberBlank
        if (note.trim().length < MIN_REPORT_NOTE_LENGTH) return ReportResult.NoteTooShort
        if (!confirmed) return ReportResult.NotConfirmed

        viewModelScope.launch {
            app.database.scamNumberDao().insert(
                ScamNumberEntity(
                    number = number.trim(),
                    normalizedNumber = normalizePhoneNumber(number),
                    note = note.trim(),
                    reportedAt = System.currentTimeMillis(),
                    source = source,
                    linkedScore = linkedScore
                )
            )
        }
        return ReportResult.Success
    }

    fun remove(id: Long) {
        viewModelScope.launch { app.database.scamNumberDao().delete(id) }
    }
}
