package com.fishguard.mobile.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface ScamNumberDao {
    @Insert
    suspend fun insert(entry: ScamNumberEntity): Long

    @Query("SELECT * FROM scam_numbers ORDER BY reportedAt DESC")
    fun observeAll(): Flow<List<ScamNumberEntity>>

    @Query("SELECT * FROM scam_numbers WHERE normalizedNumber = :normalized LIMIT 1")
    suspend fun findByNormalizedNumber(normalized: String): ScamNumberEntity?

    @Query("DELETE FROM scam_numbers WHERE id = :id")
    suspend fun delete(id: Long)
}
