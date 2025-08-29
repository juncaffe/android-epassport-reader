package com.juncaffe.jmrtd_android.data

import android.nfc.Tag
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject

class NFCRepositoryImpl @Inject constructor(
    private val nfcManager: NFCManager
): NFCRepository {

    private val _nfcDataFlow = MutableSharedFlow<Tag>(replay = 1)
    private var isEnabled = false

    override suspend fun enableReaderMode() {
        if(!isEnabled) {
            nfcManager.enableReaderMode { tag ->
                _nfcDataFlow.tryEmit(tag)
            }
            isEnabled = true
        }
    }

    override suspend fun disableReaderMode() {
        nfcManager.disableReaderMode()
        isEnabled = false
    }

    override fun observedNFCData(): Flow<Tag> = _nfcDataFlow.asSharedFlow()

    override fun isReaderModeEnabled(): Boolean = isEnabled
}