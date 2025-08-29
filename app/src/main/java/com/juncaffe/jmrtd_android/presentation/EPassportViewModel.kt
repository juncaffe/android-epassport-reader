package com.juncaffe.jmrtd_android.presentation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.juncaffe.epassport.EPassportReader
import com.juncaffe.epassport.api.EPassportCallback
import com.juncaffe.epassport.model.State
import com.juncaffe.epassport.mrtd.BACKey
import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.jmrtd_android.domain.NFCUseCase
import com.juncaffe.jmrtd_android.model.ScanStatus
import com.juncaffe.jmrtd_android.model.ScanUiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.inject.Inject

@HiltViewModel
class EPassportViewModel @Inject constructor(
    private val nfcUseCase: NFCUseCase
): ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState = _uiState.asStateFlow()

    private var bacKey: BACKey? = null

    init {
        observeData()
    }

    fun setBacKey(bacKey: BACKey?) {
        this.bacKey = bacKey
        _uiState.update {
            it.copy(status = ScanStatus.Idle)
        }
    }

    fun onAuthentication(message: String) {
        _uiState.update {
            it.copy(status = ScanStatus.Authentication,
                message = message
            )
        }
    }

    fun onProgress(overall: Int, stage: String, progress: Int) {
        val newStages = LinkedHashMap(_uiState.value.stageProgress).apply {
            this[stage] = progress.coerceIn(0, 100)
        }
        _uiState.update {
            it.copy(status = ScanStatus.Scanning,
            overallProgress = overall.coerceIn(0, 100),
                stageProgress = newStages
            )
        }
    }

    fun onComplete(dg2Image: ByteArray?) {
        _uiState.update {
            it.copy(status = ScanStatus.Done,
                overallProgress = 100,
                dg2ImageBytes = dg2Image
            )
        }
        stop()
    }

    fun onError(message: String) {
        _uiState.update {
            it.copy(status = ScanStatus.Error,
                errorMessage = message
            )
        }
    }

    fun onStart() {
        viewModelScope.launch {
            try {
                _uiState.value = ScanUiState(status = ScanStatus.Scanning)
                nfcUseCase.startNFCReader()
            }catch(e: Exception) {
                onError("NFC 시작 실패: ${e.message}")
            }
        }
    }

    fun stop() {
        viewModelScope.launch {
            nfcUseCase.stopNFCReader()
        }
    }

    fun observeData() {
        viewModelScope.launch {
            nfcUseCase.observeNFCData().collect { tag ->
                viewModelScope.launch(Dispatchers.Default) {
                    try {
                        var allReadSize = 0
                        val ePassport = EPassportReader(tag)
                        ePassport.setCallback(object : EPassportCallback {
                            override fun onState(state: State) {
                                when (state) {
                                    is State.CardAccess -> this@EPassportViewModel.onAuthentication("카드 연결")
                                    is State.ChipAuthentication -> this@EPassportViewModel.onAuthentication("칩 인증")
                                    is State.Sign -> this@EPassportViewModel.onAuthentication("서명 검증")
                                    is State.PassiveAuthentication -> this@EPassportViewModel.onAuthentication("패시브 인증")
                                    is State.Reading -> {}
                                }
                            }

                            override fun onProgress(fid: PassportService.EF, currentReadSize: Int, dgAccumulatedReadSize: Int, dgSize: Int, totalDgSize: Int) {
                                allReadSize += currentReadSize
                                val fidProgress = (dgAccumulatedReadSize.toFloat() / dgSize.toFloat() * 100).toInt()
                                val allProgress = (allReadSize.toFloat() / totalDgSize.toFloat() * 100).toInt()
                                this@EPassportViewModel.onProgress(allProgress, fid.toString(), fidProgress)
                            }

                            override fun onComplete() {
                                ePassport.getProfileImage()?.let {
                                    this@EPassportViewModel.onComplete(it)
                                }
                                ePassport.wipe()
                                ePassport.closeService()
                            }

                            override fun onError(t: Throwable) {
                                t.printStackTrace()
                                onError(t.message.toString())
                                ePassport.wipe()
                                ePassport.closeService()
                            }
                        })
                        if (bacKey != null) {
                            ePassport.readPassport(bacKey!!)
                        } else {
                            onError("BACKey가 설정되지 않았습니다.")
                            ePassport.wipe()
                            ePassport.closeService()
                        }
                    }catch (e: Exception) {
                        Log.e("EPassportViewModel", "Error processing ePassport", e)
                        onError("전자여권 처리 중 오류가 발생했습니다: ${e.message}")
                    }
                }
            }
        }
    }

    fun generateAESKey(alias: String, useGcm: Boolean = false) {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyParamBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
            .setBlockModes(
                if(useGcm)
                    KeyProperties.BLOCK_MODE_GCM
                else
                    KeyProperties.BLOCK_MODE_CBC
            )
            .setEncryptionPaddings(
                if(useGcm)
                    KeyProperties.ENCRYPTION_PADDING_NONE
                else
                    KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
            .setKeySize(256)

        val keyGenParameterSpec = if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try{
                keyParamBuilder.setIsStrongBoxBacked(true)
                keyParamBuilder.build()
            }catch(e: StrongBoxUnavailableException) {
                keyParamBuilder.setIsStrongBoxBacked(false)
                keyParamBuilder.build()
            }
        }else {
            keyParamBuilder.build()
        }
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun getKeyStoreKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKeyEntry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
        return secretKeyEntry.secretKey
    }
}