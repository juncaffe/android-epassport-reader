/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2018  The JMRTD team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * $Id: BACProtocol.java 1853 2021-06-26 18:13:26Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.mrtd.APDULevelBACCapable
import com.juncaffe.epassport.mrtd.AccessKeySpec
import com.juncaffe.epassport.mrtd.BACKeySpec
import com.juncaffe.epassport.mrtd.CardServiceProtocolException
import com.juncaffe.epassport.mrtd.utils.Util
import com.juncaffe.epassport.mrtd.utils.MRZUtils
import com.juncaffe.epassport.mrtd.utils.Utils
import com.juncaffe.epassport.smartcard.CardServiceException
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Random
import javax.crypto.SecretKey

/**
 * The Basic Access Control protocol.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1853 $
 *
 * @since 0.5.6
 */
class BACProtocol(private val service: APDULevelBACCapable, private val maxTranceiveLength: Int, private val shouldCheckMAC: Boolean) {
    private val random: Random

    /**
     * Constructs a BAC protocol instance.
     *
     * @param service the service to send APDUs
     * @param maxTranceiveLength the maximal tranceive length (on responses to `READ BINARY`)
     * to use in the resulting secure messaging channel
     * @param shouldCheckMAC whether the resulting secure messaging channel should apply strict MAC
     * checking on response APDUs
     */
    init {
        this.random = SecureRandom()
    }

    /**
     * Performs the Basic Access Control protocol.
     *
     * @param bacKey the key based on the document number,
     * the card holder's birth date,
     * and the document's expiry date
     *
     * @return the BAC result
     *
     * @throws CardServiceException if authentication failed
     */
    @Throws(CardServiceException::class)
    fun doBAC(bacKey: AccessKeySpec): BACResult {
        try {
            val keySeed = bacKey.getKey()
            val kEnc = Util.deriveKey(keySeed, Util.ENC_MODE)
            val kMac = Util.deriveKey(keySeed, Util.MAC_MODE)

            val wrapper = doBACStep(kEnc, kMac)
            return BACResult(bacKey, wrapper)
        } catch (gse: GeneralSecurityException) {
            throw CardServiceException("Error during BAC", gse)
        }
    }

    /**
     * Performs the Basic Access Control protocol.
     * It does BAC using kEnc and kMac keys, usually calculated
     * from the document number, the card holder's date of birth,
     * and the card's date of expiry.
     *
     * @param kEnc the static 3DES key required for BAC
     * @param kMac the static 3DES key required for BAC
     *
     * @return the new secure messaging wrapper
     *
     * @throws CardServiceException if authentication failed
     * @throws GeneralSecurityException on security primitives related problems
     */
    @Throws(CardServiceException::class, GeneralSecurityException::class)
    fun doBAC(kEnc: SecretKey?, kMac: SecretKey?): BACResult {
        return BACResult(doBACStep(kEnc, kMac))
    }

    /**
     * Performs the Basic Access Control protocol.
     *
     * @param kEnc the static 3DES key required for BAC
     * @param kMac the static 3DES key required for BAC
     *
     * @return the new secure messaging wrapper
     *
     * @throws CardServiceException if authentication failed
     * @throws GeneralSecurityException on security primitives related problems
     */
    @Throws(CardServiceException::class, GeneralSecurityException::class)
    private fun doBACStep(kEnc: SecretKey?, kMac: SecretKey?): SecureMessagingWrapper {
        var rndICC: ByteArray? = null
        try {
            rndICC = service.sendGetChallenge()
        } catch (e: Exception) {
            throw CardServiceProtocolException("BAC failed in GET CHALLENGE", 1, e)
        }
        val rndIFD = ByteArray(8)
        random.nextBytes(rndIFD)
        val kIFD = ByteArray(16)
        random.nextBytes(kIFD)
        var response: ByteArray? = null
        try {
            response = service.sendMutualAuth(rndIFD, rndICC, kIFD, kEnc, kMac)
        } catch (e: Exception) {
            throw CardServiceProtocolException("BAC failed in MUTUAL AUTH", 2, e)
        }
        val kICC = ByteArray(16)
        System.arraycopy(response, 16, kICC, 0, 16)

        val keySeed = ByteArray(16)
        for (i in 0..15) {
            keySeed[i] = ((kIFD[i].toInt() and 0xFF) xor (kICC[i].toInt() and 0xFF)).toByte()
        }
        val ksEnc = Util.deriveKey(keySeed, Util.ENC_MODE)
        val ksMac = Util.deriveKey(keySeed, Util.MAC_MODE)
        val ssc: Long = computeSendSequenceCounter(rndICC, rndIFD)

        return DESedeSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, ssc)
    }

    companion object {
        /**
         * Computes the key seed based on the given (MRZ based) BAC key.
         *
         * @param bacKey the BAC key
         *
         * @return the key seed
         *
         * @throws GeneralSecurityException on error applying the low level cryptographic primitives
         */
        @Throws(GeneralSecurityException::class)
        fun computeKeySeedForBAC(bacKey: BACKeySpec): ByteArray {
            var documentNumber = bacKey.getDocumentNumber()
            val dateOfBirth = bacKey.getDateOfBirth()
            val dateOfExpiry = bacKey.getDateOfExpiry()

            require(dateOfBirth.size == 6) { "Wrong date format used for date of birth. Expected yyMMdd, found " + String(dateOfBirth, Charsets.UTF_8) }
            require(dateOfExpiry.size == 6) { "Wrong date format used for date of expiry. Expected yyMMdd, found " + String(dateOfExpiry, Charsets.UTF_8) }
            requireNotNull(documentNumber) { "Wrong document number. Found " + String(documentNumber, Charsets.UTF_8) }

            documentNumber = MRZUtils.fixDocumentNumber(documentNumber)

            return computeKeySeedForBAC(documentNumber, dateOfBirth, dateOfExpiry)
        }

        /**
         * Computes the initial send sequence counter to use,
         * given the randoms generated by PICC and PCD.
         *
         * @param rndICC the PICC's random
         * @param rndIFD the PCD's random
         *
         * @return the initial send sequence counter to use
         */
        fun computeSendSequenceCounter(rndICC: ByteArray, rndIFD: ByteArray): Long {
            check(!(rndICC.size != 8 || rndIFD.size != 8)) { "Wrong length input" }
            var ssc: Long = 0
            for (i in 4..7) {
                ssc = ssc shl 8
                ssc += (rndICC[i].toInt() and 0x000000FF).toLong()
            }
            for (i in 4..7) {
                ssc = ssc shl 8
                ssc += (rndIFD[i].toInt() and 0x000000FF).toLong()
            }
            return ssc
        }

        /**
         * Computes the static key seed to be used in BAC KDF,
         * based on information from the MRZ.
         *
         * @param documentNumber a string containing the document number
         * @param dateOfBirth a string containing the date of birth (YYMMDD)
         * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
         *
         * @return a byte array of length 16 containing the key seed
         *
         * @throws GeneralSecurityException on security error
         */
        @Throws(GeneralSecurityException::class)
        private fun computeKeySeedForBAC(documentNumber: ByteArray, dateOfBirth: ByteArray, dateOfExpiry: ByteArray): ByteArray {
            return Utils.computeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", true)
        }
    }
}
