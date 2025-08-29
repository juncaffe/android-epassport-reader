package com.juncaffe.jmrtd_android.presentation

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import com.juncaffe.epassport.mrtd.BACKey

@HiltViewModel
class PassportViewModel @Inject constructor(
): ViewModel() {

    private var bacKey: BACKey? = null

    fun submit(passportNo: ByteArray, birth: ByteArray, expire: ByteArray): String? {
        try {
            bacKey = BACKey(passportNo, birth, expire)
            passportNo.fill(0)
            birth.fill(0)
            expire.fill(0)
            return null
        }catch(e: Exception) {
            e.printStackTrace()
            return e.message
        }
    }

    fun getBACKey(): BACKey? = bacKey
}