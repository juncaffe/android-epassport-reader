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
 * $Id: DESedeSecureMessagingWrapper.java 1805 2018-11-26 21:39:46Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.Serializable
import java.security.GeneralSecurityException
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 * Secure messaging wrapper for APDUs.
 * Initially based on Section E.3 of ICAO-TR-PKI.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1805 $
 */
class DESedeSecureMessagingWrapper : SecureMessagingWrapper, Serializable {

    /**
     * Constructs a secure messaging wrapper based on the secure messaging
     * session keys. The initial value of the send sequence counter is set to
     * `0L`.
     *
     * @param ksEnc the session key for encryption
     * @param ksMac the session key for macs
     * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
     *
     * @throws GeneralSecurityException
     * when the available JCE providers cannot provide the necessary
     * cryptographic primitives
     * (`"DESede/CBC/Nopadding"` Cipher, `"ISO9797Alg3Mac"` Mac).
     */
    @Throws(GeneralSecurityException::class)
    constructor(ksEnc: SecretKey?, ksMac: SecretKey?): this(ksEnc, ksMac, true)

    /**
     * Constructs a secure messaging wrapper based on the secure messaging
     * session keys. The initial value of the send sequence counter is set to
     * `0L`.
     *
     * @param ksEnc the session key for encryption
     * @param ksMac the session key for macs
     *
     * @throws GeneralSecurityException
     * when the available JCE providers cannot provide the necessary
     * cryptographic primitives
     * (`"DESede/CBC/Nopadding"` Cipher, `"ISO9797Alg3Mac"` Mac).
     */
    @Throws(GeneralSecurityException::class)
    constructor(ksEnc: SecretKey?, ksMac: SecretKey?, shouldCheckMAC: Boolean = true) : this(ksEnc, ksMac, 256, shouldCheckMAC, 0L)

    /**
     * Constructs a secure messaging wrapper based on the secure messaging
     * session keys and the initial value of the send sequence counter.
     * Used in BAC and EAC 1.
     *
     * @param ksEnc the session key for encryption
     * @param ksMac the session key for macs
     * @param ssc the initial value of the send sequence counter
     *
     * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
     */
    @Throws(GeneralSecurityException::class)
    constructor(ksEnc: SecretKey?, ksMac: SecretKey?, ssc: Long) : this(ksEnc, ksMac, 256, true, ssc)

    /**
     * Constructs a secure messaging wrapper based on the given existing secure messaging wrapper.
     * This is a convenience copy constructor.
     *
     * @param wrapper an existing wrapper
     *
     * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
     */
    @Throws(GeneralSecurityException::class)
    constructor(wrapper: DESedeSecureMessagingWrapper) : this(
        wrapper.getEncryptionKey(),
        wrapper.getMACKey(),
        wrapper.getMaxTranceiveLength(),
        wrapper.shouldCheckMAC(),
        wrapper.getSendSequenceCounter()
    )

    /**
     * Constructs a secure messaging wrapper based on the secure messaging
     * session keys and the initial value of the send sequence counter.
     * Used in BAC and EAC 1.
     *
     * @param ksEnc the session key for encryption
     * @param ksMac the session key for macs
     * @param maxTranceiveLength the maximum tranceive length, typical values are 256 or 65536
     * @param shouldCheckMAC a boolean indicating whether this wrapper will check the MAC in wrapped response APDUs
     * @param ssc the initial value of the send sequence counter
     *
     * @throws GeneralSecurityException when the available JCE providers cannot provide the necessary cryptographic primitives
     */
    @Throws(GeneralSecurityException::class)
    constructor(ksEnc: SecretKey?, ksMac: SecretKey?, maxTranceiveLength: Int, shouldCheckMAC: Boolean, ssc: Long): super(ksEnc, ksMac, "DESede/CBC/NoPadding", "ISO9797Alg3Mac", maxTranceiveLength, shouldCheckMAC, ssc)

    /**
     * Returns the type of secure messaging wrapper.
     * In this case `"DESede"` will be returned.
     *
     * @return the type of secure messaging wrapper
     */
    override val type: String? get() = "DESede"

    /**
     * Returns the length (in bytes) to use for padding.
     * For 3DES this is 8.
     *
     * @return the length to use for padding
     */
    public override fun getPadLength(): Int {
        return 8
    }

    public override fun getEncodedSendSequenceCounter(): ByteArray? {
        return SecureByteArrayOutputStream(true).use {
            try {
                val dataOutputStream = DataOutputStream(it)
                dataOutputStream.writeLong(getSendSequenceCounter())
            } catch (ioe: IOException) {
                /* Never happens. */
                LOGGER.log(Level.FINE, "Error writing to stream", ioe)
            }
            it.toByteArray()
        }
    }

    override fun toString(): String {
        return StringBuilder()
            .append("DESedeSecureMessagingWrapper [")
            .append("ssc: ").append(getSendSequenceCounter())
            .append(", kEnc: ").append(getEncryptionKey())
            .append(", kMac: ").append(getMACKey())
            .append(", shouldCheckMAC: ").append(shouldCheckMAC())
            .append(", maxTranceiveLength: ").append(getMaxTranceiveLength())
            .append("]")
            .toString()
    }

    override fun hashCode(): Int {
        return 31 * super.hashCode() + 13
    }

    override fun getIV(): IvParameterSpec {
        return ZERO_IV_PARAM_SPEC
    }

    companion object {
        private val serialVersionUID = -2859033943345961793L

        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")

        /** Initialization vector consisting of 8 zero bytes.  */
        val ZERO_IV_PARAM_SPEC: IvParameterSpec = IvParameterSpec(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0))
    }
}
