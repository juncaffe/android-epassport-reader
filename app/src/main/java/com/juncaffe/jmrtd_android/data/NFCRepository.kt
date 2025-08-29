package com.juncaffe.jmrtd_android.data

import android.nfc.Tag
import kotlinx.coroutines.flow.Flow

interface NFCRepository {
    suspend fun enableReaderMode()
    suspend fun disableReaderMode()
    fun observedNFCData(): Flow<Tag>
    fun isReaderModeEnabled(): Boolean
}