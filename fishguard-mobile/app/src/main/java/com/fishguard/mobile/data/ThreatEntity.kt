package com.fishguard.mobile.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "threats")
data class ThreatEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val sourceApp: String,
    val sender: String,
    val messagePreview: String,
    val fullMessage: String,
    val score: Int,
    val riskLevel: String,
    val engine: String,
    val signalsJson: String
)
