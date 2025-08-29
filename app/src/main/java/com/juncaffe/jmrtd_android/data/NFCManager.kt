package com.juncaffe.jmrtd_android.data

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.tech.Ndef
import javax.inject.Inject

class NFCManager @Inject constructor(private val context: Context) {
    private var nfcAdapter: NfcAdapter? = null
    private var currentActivity: Activity? = null
    private var readerCallback: NfcAdapter.ReaderCallback? = null

//    private val nfcReaderCallback = NfcAdapter.ReaderCallback { tag ->
//        try {
//            val ndefTag = Ndef.get(tag)
//            ndefTag.connect()
//
//            val ndefMessage = ndefTag.ndefMessage
//            val records = ndefMessage?.records
//
//            if(records != null && records.isNotEmpty()) {
//                val payload = String(records[0].payload)
//                val nfcTag = NFCTag(
//                    id = tag.id.toHexString(),
//                    data = payload
//                )
//                readerCallback?.invoke(NFCResult.Success(payload, nfcTag))
//            }
//            ndefTag.close()
//        }catch(e: Exception) {
//            readerCallback?.invoke(NFCResult.Error("NFC 읽기 오류 : ${e.message}"))
//        }
//    } as NfcAdapter.ReaderCallback?

    fun enableReaderMode(callback: NfcAdapter.ReaderCallback) {
        nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        readerCallback = callback
        currentActivity?.let {
            nfcAdapter?.enableReaderMode(
                it,
                readerCallback,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B,
                null
            )
        }
    }

    fun disableReaderMode() {
        currentActivity?.let { nfcAdapter?.disableReaderMode(it) }
    }

    fun setCurrentActivity(activity: Activity) {
        currentActivity = activity
    }
}