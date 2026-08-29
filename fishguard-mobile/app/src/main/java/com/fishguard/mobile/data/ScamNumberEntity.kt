package com.fishguard.mobile.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "scam_numbers")
data class ScamNumberEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val number: String,
    val normalizedNumber: String,
    val note: String,
    val reportedAt: Long,
    /** "CALL_ANALYSIS" (appuyé sur un score d'appel réel) ou "MANUAL" (signalement direct). */
    val source: String = "MANUAL",
    /** Score de l'analyse d'appel qui a motivé le signalement, s'il y en a une. */
    val linkedScore: Int? = null
)

/** Ne garde que les chiffres (et le + initial) pour comparer des numéros écrits différemment. */
fun normalizePhoneNumber(raw: String): String {
    val trimmed = raw.trim()
    val plus = if (trimmed.startsWith("+")) "+" else ""
    return plus + trimmed.filter { it.isDigit() }
}
