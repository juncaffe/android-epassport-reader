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
 * $Id: PACEAPDUSender.java 1850 2021-05-21 06:25:03Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.APDULevelPACECapable
import com.juncaffe.epassport.mrtd.utils.Util.toOIDBytes
import com.juncaffe.epassport.smartcard.APDUWrapper
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.CommandAPDU
import com.juncaffe.epassport.smartcard.ISO7816
import com.juncaffe.epassport.smartcard.tlv.TLVUtil.unwrapDO
import com.juncaffe.epassport.smartcard.tlv.TLVUtil.wrapDO
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.logging.Level
import java.util.logging.Logger

/**
 * A low-level APDU sender to support the PACE protocol.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1850 $
 *
 * @since 0.7.0
 */
class PACEAPDUSender(service: CardService) : APDULevelPACECapable {
    private val secureMessagingSender: SecureMessagingAPDUSender

    /**
     * Creates an APDU sender to support the PACE protocol.
     *
     * @param service the card service to tranceive APDUs
     */
    init {
        this.secureMessagingSender = SecureMessagingAPDUSender(service)
    }

    /**
     * The MSE AT APDU for PACE, see ICAO TR-SAC-1.01, Section 3.2.1, BSI TR 03110 v2.03 B11.1.
     * Note that (for now) caller is responsible for prefixing the byte[] params with specified tags.
     *
     * @param wrapper secure messaging wrapper
     * @param oid OID of the protocol to select (this method will prefix `0x80`)
     * @param refPublicKeyOrSecretKey value specifying whether to use MRZ (`0x01`) or CAN (`0x02`) (this method will prefix `0x83`)
     * @param refPrivateKeyOrForComputingSessionKey indicates a private key or reference for computing a session key (this method will prefix `0x84`)
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun sendMSESetATMutualAuth(
        wrapper: APDUWrapper?, oid: String,
        refPublicKeyOrSecretKey: Int, refPrivateKeyOrForComputingSessionKey: ByteArray?
    ) {
        var refPrivateKeyOrForComputingSessionKey = refPrivateKeyOrForComputingSessionKey
        requireNotNull(oid) { "OID cannot be null" }

        val oidBytes = toOIDBytes(oid)

        /*
     * 0x83 Reference of a public key / secret key.
     * The password to be used is indicated as follows: 0x01: MRZ, 0x02: CAN.
     */
        require(refPublicKeyOrSecretKey == MRZ_PACE_KEY_REFERENCE.toInt()) { "Unsupported key type reference, found " + refPublicKeyOrSecretKey }

        val refPublicKeyOrSecretKeyBytes = wrapDO(0x83, byteArrayOf(refPublicKeyOrSecretKey.toByte()))

        /*
     * 0x84 Reference of a private key / Reference for computing a
     * session key.
     * This data object is REQUIRED to indicate the identifier
     * of the domain parameters to be used if the domain
     * parameters are ambiguous, i.e. more than one set of
     * domain parameters is available for PACE.
     */
        if (refPrivateKeyOrForComputingSessionKey != null) {
            refPrivateKeyOrForComputingSessionKey = wrapDO(0x84, refPrivateKeyOrForComputingSessionKey)
        }

        SecureByteArrayOutputStream(true).use {
            try {
                it.write(oidBytes)
                it.write(refPublicKeyOrSecretKeyBytes)
                if (refPrivateKeyOrForComputingSessionKey != null) {
                    it.write(refPrivateKeyOrForComputingSessionKey)
                }
            } catch (ioe: IOException) {
                /* NOTE: should never happen. */
                LOGGER.log(Level.WARNING, "Error while copying data", ioe)
                throw IllegalStateException("Error while copying data")
            }
            val data = it.toByteArray()

            /* Tranceive APDU. */
            val capdu = CommandAPDU(ISO7816.CLA_ISO7816.toInt(), ISO7816.INS_MSE.toInt(), 0xC1, 0xA4, data)
            val rapdu = secureMessagingSender.transmit(wrapper, capdu)

            /* Handle error status word. */
            val sw = rapdu.sW.toShort()
            if (sw != ISO7816.SW_NO_ERROR) {
                throw CardServiceException("Sending MSE AT failed", sw.toInt())
            }
        }
    }

    /**
     * Sends a General Authenticate command.
     *
     * @param wrapper secure messaging wrapper
     * @param data data to be sent, without the `0x7C` prefix (this method will add it)
     * @param le the expected length to send
     * @param isLast indicates whether this is the last command in the chain
     *
     * @return dynamic authentication data without the `0x7C` prefix (this method will remove it)
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun sendGeneralAuthenticate(wrapper: APDUWrapper?, data: ByteArray, le: Int, isLast: Boolean): ByteArray {
        /* Tranceive APDU. */
        val commandData = wrapDO(0x7C, data) // FIXME: constant for 0x7C
        val capdu = CommandAPDU((if (isLast) ISO7816.CLA_ISO7816 else ISO7816.CLA_COMMAND_CHAINING).toInt(), INS_PACE_GENERAL_AUTHENTICATE.toInt(), 0x00, 0x00, commandData, le)
        val rapdu = secureMessagingSender.transmit(wrapper, capdu)

        /* Handle error status word. */
        val sw = rapdu.sW.toShort()
        if (sw != ISO7816.SW_NO_ERROR) {
            throw CardServiceException("Sending general authenticate failed", sw.toInt())
        }
        var responseData = rapdu.data
        responseData = unwrapDO(0x7C, responseData)
        return responseData
    }

    companion object {
        /** Shared secret type for non-PACE key.  */
        const val NO_PACE_KEY_REFERENCE: Byte = 0x00

        /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1.  */
        const val MRZ_PACE_KEY_REFERENCE: Byte = 0x01

        /** The general Authenticate command is used to perform the PACE protocol. See Section 3.2.2 of SAC-TR 1.01.  */
        private val INS_PACE_GENERAL_AUTHENTICATE = 0x86.toByte()

        private val LOGGER: Logger = Logger.getLogger("org.jmrtd.protocol")
    }
}
