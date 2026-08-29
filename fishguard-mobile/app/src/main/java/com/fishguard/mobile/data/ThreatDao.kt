package com.fishguard.mobile.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ThreatDao {
    @Insert
    suspend fun insert(threat: ThreatEntity): Long

    @Query("SELECT * FROM threats ORDER BY timestamp DESC")
    fun observeAll(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE riskLevel IN ('MEDIUM','HIGH','CRITICAL') ORDER BY timestamp DESC")
    fun observeRisky(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE riskLevel IN ('SAFE','LOW') ORDER BY timestamp DESC")
    fun observeSafe(): Flow<List<ThreatEntity>>

    @Query("SELECT * FROM threats WHERE id = :id")
    suspend fun getById(id: Long): ThreatEntity?

    @Query("SELECT COUNT(*) FROM threats WHERE riskLevel IN ('HIGH', 'CRITICAL')")
    fun observeHighRiskCount(): Flow<Int>

    @Query("DELETE FROM threats")
    suspend fun clearAll()
}
