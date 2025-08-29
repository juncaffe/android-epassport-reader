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
 * $Id: EACCAAPDUSender.java 1850 2021-05-21 06:25:03Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.APDULevelEACCACapable
import com.juncaffe.epassport.mrtd.utils.Util.i2os
import com.juncaffe.epassport.mrtd.utils.Util.toOIDBytes
import com.juncaffe.epassport.smartcard.APDUWrapper
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.CommandAPDU
import com.juncaffe.epassport.smartcard.ISO7816
import com.juncaffe.epassport.smartcard.ResponseAPDU
import com.juncaffe.epassport.smartcard.tlv.TLVUtil.unwrapDO
import com.juncaffe.epassport.smartcard.tlv.TLVUtil.wrapDO
import java.io.IOException
import java.math.BigInteger
import java.util.logging.Level
import java.util.logging.Logger

/**
 * A low-level APDU sender to support the EAC-CA protocol (version 1).
 * This provides functionality for the "DESede" case and for the "AES" case.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1850 $
 *
 * @since 0.7.0
 */
class EACCAAPDUSender(service: CardService) : APDULevelEACCACapable {
    private val secureMessagingSender: SecureMessagingAPDUSender

    /**
     * Creates an APDU sender for the EAC-CA protocol.
     *
     * @param service the card service for tranceiving APDUs
     */
    init {
        this.secureMessagingSender = SecureMessagingAPDUSender(service)
    }

    /**
     * The MSE KAT APDU, see EAC 1.11 spec, Section B.1.
     * This command is sent in the "DESede" case.
     *
     * @param wrapper secure messaging wrapper
     * @param keyData key data object (tag 0x91)
     * @param idData key id data object (tag 0x84), can be null
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun sendMSEKAT(wrapper: APDUWrapper, keyData: ByteArray, idData: ByteArray?) {
        val data = ByteArray(keyData.size + (if (idData != null) idData.size else 0))
        System.arraycopy(keyData, 0, data, 0, keyData.size)
        if (idData != null) {
            System.arraycopy(idData, 0, data, keyData.size, idData.size)
        }

        val commandAPDU = CommandAPDU(ISO7816.CLA_ISO7816.toInt(), ISO7816.INS_MSE.toInt(), 0x41, 0xA6, data)
        val responseAPDU = secureMessagingSender.transmit(wrapper, commandAPDU)
        val sw = responseAPDU.sW.toShort()
        if (sw != ISO7816.SW_NO_ERROR) {
            throw CardServiceException("Sending MSE KAT failed", sw.toInt())
        }
    }

    /* For Chip Authentication. We prefix 0x80 for OID and 0x84 for keyId. */
    /**
     * The  MSE Set AT for Chip Authentication.
     * This command is the first command that is sent in the "AES" case.
     *
     * @param wrapper secure messaging wrapper
     * @param oid the OID
     * @param keyId the keyId or `null`
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun sendMSESetATIntAuth(wrapper: APDUWrapper?, oid: String, keyId: BigInteger?) {
        val p1 = 0x41
        val p2 = 0xA4
        //  int p2 = 0xA6;
        var rapdu: ResponseAPDU? = null
        if (keyId == null || keyId.compareTo(BigInteger.ZERO) < 0) {
            val capdu = CommandAPDU(ISO7816.CLA_ISO7816.toInt(), ISO7816.INS_MSE.toInt(), p1, p2, toOIDBytes(oid))
            rapdu = secureMessagingSender.transmit(wrapper, capdu)
        } else {
            val oidBytes = toOIDBytes(oid)
            val keyIdBytes = wrapDO(0x84, i2os(keyId))
            SecureByteArrayOutputStream(true).use {
                try {
                    it.write(oidBytes)
                    it.write(keyIdBytes)
                    val capdu = CommandAPDU(ISO7816.CLA_ISO7816.toInt(), ISO7816.INS_MSE.toInt(), p1, p2, it.toByteArray())
                    rapdu = secureMessagingSender.transmit(wrapper, capdu)
                } catch (ioe: IOException) {
                    LOGGER.log(Level.WARNING, "Exception", ioe)
                }
            }
        }
        val sw = if (rapdu == null) -1 else rapdu.sW.toShort()
        if (sw != ISO7816.SW_NO_ERROR) {
            throw CardServiceException("Sending MSE AT failed", sw.toInt())
        }
    }

    /**
     * Sends a General Authenticate command.
     * This command is the second command that is sent in the "AES" case.
     * This uses 256 for the expected length.
     *
     * @param wrapper secure messaging wrapper
     * @param data data to be sent, without the `0x7C` prefix (this method will add it)
     * @param isLast indicates whether this is the last command in the chain
     *
     * @return dynamic authentication data without the `0x7C` prefix (this method will remove it)
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    override fun sendGeneralAuthenticate(wrapper: APDUWrapper?, data: ByteArray, isLast: Boolean): ByteArray {
        return sendGeneralAuthenticate(wrapper, data, 256, isLast)
    }

    /**
     * Sends a General Authenticate command.
     * This command is the second command that is sent in the "AES" case.
     *
     * @param wrapper secure messaging wrapper
     * @param data data to be sent, without the `0x7C` prefix (this method will add it)
     * @param le the expected length
     * @param isLast indicates whether this is the last command in the chain
     *
     * @return dynamic authentication data without the `0x7C` prefix (this method will remove it)
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun sendGeneralAuthenticate(wrapper: APDUWrapper?, data: ByteArray, le: Int, isLast: Boolean): ByteArray {
        val commandData = wrapDO(0x7C, data) // FIXME: constant for 0x7C

        /*
     * NOTE: Support of Protocol Response Data is CONDITIONAL:
     * It MUST be provided for version 2 but MUST NOT be provided for version 1.
     * So, we are expecting 0x7C (= tag), 0x00 (= length) here.
     */
        var capdu = CommandAPDU((if (isLast) ISO7816.CLA_ISO7816 else ISO7816.CLA_COMMAND_CHAINING).toInt(), INS_BSI_GENERAL_AUTHENTICATE.toInt(), 0x00, 0x00, commandData, le)
        var rapdu = secureMessagingSender.transmit(wrapper, capdu)

        /* Handle error status word. */
        val sw = rapdu.sW.toShort()

        if (sw == ISO7816.SW_WRONG_LENGTH) {
            capdu = CommandAPDU((if (isLast) ISO7816.CLA_ISO7816 else ISO7816.CLA_COMMAND_CHAINING).toInt(), INS_BSI_GENERAL_AUTHENTICATE.toInt(), 0x00, 0x00, commandData, 256)
            rapdu = secureMessagingSender.transmit(wrapper, capdu)
        }

        if (sw != ISO7816.SW_NO_ERROR) {
            throw CardServiceException("Sending general authenticate failed", sw.toInt())
        }
        var responseData = rapdu.data
        try {
            responseData = unwrapDO(0x7C, responseData)
        } catch (e: Exception) {
            LOGGER.log(Level.WARNING, "Could not unwrap response to GENERAL AUTHENTICATE", e)
        }
        return responseData
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger("org.jmrtd.protocol")

        /** The general Authenticate command is used to perform the EAC-CA protocol.  */
        private val INS_BSI_GENERAL_AUTHENTICATE = 0x86.toByte()
    }
}
