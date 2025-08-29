package com.juncaffe.epassport.nfc

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.NfcA
import android.nfc.tech.NfcB
import com.juncaffe.epassport.smartcard.APDUEvent
import com.juncaffe.epassport.smartcard.APDUListener
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.CommandAPDU
import com.juncaffe.epassport.smartcard.ResponseAPDU
import java.io.IOException
import java.util.Locale
import java.util.logging.Logger

class IsoDepCardService(tag: Tag): CardService {

    /** The apduListeners.  */
    protected val apduListeners: MutableCollection<APDUListener>

    private var isoDep: IsoDep? = null
    private var apduCount = 0
    protected var state: Int = 0

    init {
        this.apduListeners = HashSet<APDUListener>()
        // NFC 태그 정보 추출
        isoDep = IsoDep.get(tag).apply {
            timeout = 10000
        }
    }

    override fun getAPDUListeners(): MutableCollection<APDUListener> {
        return apduListeners
    }

    /**
     * Notifies listeners about APDU event.
     *
     * @param event the APDU event
     */
    override fun notifyExchangedAPDU(event: APDUEvent?) {

    }

    /**
     * Adds a listener.
     *
     * @param l the listener to add
     */
    override fun addAPDUListener(l: APDUListener?) {
        if (l != null) {
            apduListeners.add(l)
        }
    }

    /**
     * Removes a listener.
     * If the specified listener is not present, this method has no effect.
     *
     * @param l the listener to remove
     */
    override fun removeAPDUListener(l: APDUListener?) {
        apduListeners.remove(l)
    }

    /**
     * ISO-DEP (ISO 14443-4) 기반의 스마트카드 연결 시도
     *
     * @throws com.juncaffe.epassport.smartcard.CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun open() {
        if (!this.isOpen()) {
            try {
                this.isoDep!!.connect()
                if (!this.isoDep!!.isConnected()) {
                    throw CardServiceException("Failed to connect")
                } else {
                    this.state = SESSION_STARTED_STATE
                }
            } catch (e: IOException) {
                throw CardServiceException("Failed to connect", e)
            }
        }
    }

    /**
     * 스마트카드 세션 연결 여부
     *
     * @return
     */
    override fun isOpen(): Boolean {
        return this.isoDep?.let {
                this.state = if (it.isConnected()) SESSION_STARTED_STATE else SESSION_STOPPED_STATE
                it.isConnected()
        }?:let {
            this.state = SESSION_STOPPED_STATE
            false
        }
    }

    /**
     * 스마트카드에 APDU 를 보냄
     *
     * @param commandAPDU 전송할 APDU 명령
     *
     * @return 카드의 응답
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun transmit(commandAPDU: CommandAPDU): ResponseAPDU? {
        return try {
            if (!this.isOpen()) {
                throw CardServiceException("Not connected")
            } else {
//                Log.w("CHJ", "transmit request : ${bytesToHexString(commandAPDU.bytes)}")
                val responseBytes = this.isoDep!!.transceive(commandAPDU.bytes)
                if (responseBytes != null && responseBytes.size >= 2) {
                    val ourResponseAPDU = ResponseAPDU(responseBytes)
//                    this.notifyExchangedAPDU(APDUEvent(this, "ISODep", ++this.apduCount, commandAPDU, ourResponseAPDU))
//                    Log.e("CHJ", "transmit response : ${bytesToHexString(ourResponseAPDU.bytes)}")
                    ourResponseAPDU
                } else {
                    throw CardServiceException("Failed response")
                }
            }
        } catch (cse: CardServiceException) {
            throw cse
        } catch (e: Exception) {
            throw CardServiceException("Could not tranceive APDU", e)
        }
    }

    fun getATR(): ByteArray? {
        if (this.isoDep == null) {
            return null
        } else {
            val tag = this.isoDep!!.getTag()
            if (tag == null) {
                return null
            } else {
                val nfcA = NfcA.get(tag)
                if (nfcA != null) {
                    return this.isoDep!!.getHistoricalBytes()
                } else {
                    val nfcB = NfcB.get(tag)
                    return if (nfcB != null) this.isoDep!!.getHiLayerResponse() else this.isoDep!!.getHistoricalBytes()
                }
            }
        }
    }

    override fun isExtendedAPDULengthSupported(): Boolean {
        return this.isoDep?.isExtendedLengthApduSupported()?:false
    }

    /**
     * 스마트카드 연결 종료
     */
    @Synchronized
    override fun close() {
        try {
            if(this.isOpen()) {
                this.isoDep!!.close()
                this.state = SESSION_STOPPED_STATE
            }
        } catch (e: IOException) {}
    }

    override fun isConnectionLost(e: Exception?): Boolean {
        if (this.isDirectConnectionLost(e)) {
            return true
        } else if (e == null) {
            return false
        } else {
            var cause: Throwable? = null
            var rootCause: Throwable? = e

            while (null != (rootCause!!.cause.also { cause = it }) && rootCause !== cause) {
                rootCause = cause
                if (this.isDirectConnectionLost(cause)) {
                    return true
                }
            }

            return false
        }
    }

    override fun isDirectConnectionLost(e: Throwable?): Boolean {
        if (!this.isISODepConnected()) {
            return true
        } else if (e == null) {
            return false
        } else {
            val exceptionClassName = e.javaClass.getName()
            if (exceptionClassName != null && exceptionClassName.contains("TagLostException")) {
                return true
            } else {
                var message = e.message
                if (message == null) {
                    message = ""
                }

                if (message.lowercase(Locale.getDefault()).contains("tag was lost")) {
                    return true
                } else {
                    if (e is CardServiceException) {
                        if (message.lowercase(Locale.getDefault()).contains("not connected")) {
                            return true
                        }

                        if (message.lowercase(Locale.getDefault()).contains("failed response")) {
                            return true
                        }
                    }

                    return false
                }
            }
        }
    }

    override fun isISODepConnected(): Boolean {
        try {
            return this.isoDep!!.isConnected()
        } catch (e: Exception) {
            return false
        }
    }

    companion object {
        protected const val SESSION_STOPPED_STATE: Int = 0
        protected const val SESSION_STARTED_STATE: Int = 1

        private val LOGGER: Logger = Logger.getLogger("ePassport")
    }

    /** Hex characters.  */
    private val HEXCHARS = "0123456789abcdefABCDEF"

    /**
     * Converts the byte `b` to capitalized hexadecimal text.
     * The result will have length 2 and only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param b the byte to convert.
     *
     * @return capitalized hexadecimal text representation of `b`.
     */
    fun byteToHexString(b: Byte): String {
        val n = b.toInt() and 0x000000FF
        val result = (if (n < 0x00000010) "0" else "") + Integer.toHexString(n)
        return result.uppercase(Locale.getDefault())
    }

    /**
     * Converts a byte array to capitalized hexadecimal text.
     * The length of the resulting string will be twice the length of
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text The byte array to convert.
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    fun bytesToHexString(text: ByteArray?): String {
        return bytesToHexString(text, 1000)
    }

    fun bytesToHexString(text: ByteArray?, numRow: Int): String {
        if (text == null) {
            return "NULL"
        }
        return bytesToHexString(text, 0, text.size, numRow)
    }

    /**
     * Converts a byte array to capitalized hexadecimal text.
     * The length of the resulting string will be twice the length of
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text The byte array to convert.
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    fun toHexString(text: ByteArray): String {
        return bytesToHexString(text, 0, text.size, 1000)
    }


    fun toHexString(text: ByteArray, numRow: Int): String {
        return bytesToHexString(text, 0, text.size, numRow)
    }

    /**
     * Converts part of a byte array to capitalized hexadecimal text.
     * Conversion starts at index `offset` until (excluding)
     * index `offset + length`.
     * The length of the resulting string will be twice the length
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text the byte array to convert.
     * @param offset where to start.
     * @param length how many bytes to convert.
     * @param numRow number of bytes to be put one in one row of output
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    fun bytesToHexString(text: ByteArray?, offset: Int, length: Int, numRow: Int): String {
        if (text == null) {
            return "NULL"
        }
        val result = StringBuilder()
        for (i in 0..<length) {
            if (i != 0 && i % numRow == 0) {
                result.append("\n")
            }
            result.append(byteToHexString(text[offset + i]))
            result.append(" ")
        }
        return result.toString()
    }

    fun bytesToHexString(text: ByteArray?, offset: Int, length: Int): String {
        return bytesToHexString(text, offset, length, 1000)
    }
}