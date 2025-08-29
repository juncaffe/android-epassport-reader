package com.juncaffe.jmrtd_android.domain

import android.nfc.Tag
import com.juncaffe.jmrtd_android.data.NFCRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class NFCUseCase @Inject constructor(
    private val nfcRepository: NFCRepository
) {
    suspend fun startNFCReader() {
        nfcRepository.enableReaderMode()
    }

    suspend fun stopNFCReader() {
        nfcRepository.disableReaderMode()
    }

    fun observeNFCData(): Flow<Tag> {
        return nfcRepository.observedNFCData()
    }
}