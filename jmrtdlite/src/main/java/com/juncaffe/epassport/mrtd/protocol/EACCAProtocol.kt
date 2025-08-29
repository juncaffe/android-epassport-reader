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
 * $Id: EACCAProtocol.java 1878 2023-07-31 13:19:51Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.mrtd.APDULevelEACCACapable
import com.juncaffe.epassport.mrtd.CardServiceProtocolException
import com.juncaffe.epassport.mrtd.utils.Util
import com.juncaffe.epassport.mrtd.utils.Util.alignKeyDataToSize
import com.juncaffe.epassport.mrtd.utils.Util.deriveKey
import com.juncaffe.epassport.mrtd.utils.Util.getBouncyCastleProvider
import com.juncaffe.epassport.mrtd.utils.Util.i2os
import com.juncaffe.epassport.mrtd.utils.Util.partition
import com.juncaffe.epassport.mrtd.lds.ChipAuthenticationInfo
import com.juncaffe.epassport.mrtd.lds.SecurityInfo
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.tlv.TLVUtil.wrapDO
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.AlgorithmParameterSpec
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.KeyAgreement
import javax.crypto.interfaces.DHPublicKey
import kotlin.math.ceil

/**
 * The EAC Chip Authentication protocol (version 1).
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1878 $
 *
 * @since 0.5.6
 */
class EACCAProtocol
/**
 * Constructs a protocol instance.
 *
 * @param service the card service
 * @param wrapper the existing secure messaging wrapper
 * @param maxTranceiveLength the maximal tranceive length (on responses to `READ BINARY`)
 * to use in the resulting secure messaging channel
 * @param shouldCheckMAC whether the resulting secure messaging channel should apply strict MAC
 * checking on response APDUs
 */(
    private val service: APDULevelEACCACapable,
    /**
     * Returns the secure messaging wrapper currently in use.
     *
     * @return a secure messaging wrapper
     */
    var wrapper: SecureMessagingWrapper?, private val maxTranceiveLength: Int, private val shouldCheckMAC: Boolean
) {
    /**
     * Perform EAC-CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
     * ver. 1.11. In short, we authenticate the chip with DH or ECDH key agreement
     * protocol and create new secure messaging keys.
     *
     * The newly established secure messaging wrapper is made available to the caller in
     * the result.
     *
     * @param keyId passport's public key id (stored in DG14), `null` if none
     * @param oid the object identifier indicating the Chip Authentication protocol
     * @param publicKeyOID the object identifier indicating the type of public key
     * @param piccPublicKey PICC's public key (stored in DG14)
     *
     * @return the Chip Authentication result
     *
     * @throws CardServiceException if Chip Authentication failed or some error occurred
     */
    @Throws(CardServiceException::class)
    fun doCA(keyId: BigInteger?, oid: String?, publicKeyOID: String?, piccPublicKey: PublicKey): EACCAResult {
        var oid = oid
        requireNotNull(piccPublicKey) { "PICC public key is null" }

        if (oid == null) {
            oid = inferChipAuthenticationOIDfromPublicKeyOID(publicKeyOID)
        }

        var agreementAlg: String? = null
        try {
            agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid)
        } catch (nfe: NumberFormatException) {
            LOGGER.log(Level.WARNING, "Unknown object identifier " + oid, nfe)
        }

        require("ECDH" == agreementAlg || "DH" == agreementAlg) { "Unsupported agreement algorithm, expected ECDH or DH, found " + agreementAlg }

        try {
            var params: AlgorithmParameterSpec? = null
            if ("DH" == agreementAlg) {
                val piccDHPublicKey = piccPublicKey as DHPublicKey
                params = piccDHPublicKey.getParams()
            } else if ("ECDH" == agreementAlg) {
                val piccECPublicKey = piccPublicKey as ECPublicKey
                params = piccECPublicKey.getParams()
            }

            /* Generate the inspection system's ephemeral key pair. */
            val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance(agreementAlg, BC_PROVIDER)
            keyPairGenerator.initialize(params)
            val pcdKeyPair = keyPairGenerator.generateKeyPair()
            val pcdPublicKey = pcdKeyPair.getPublic()
            val pcdPrivateKey = pcdKeyPair.getPrivate()

            sendPublicKey(service, wrapper, oid, keyId, pcdPublicKey)

            val keyHash: ByteArray? = getKeyHash(agreementAlg, pcdPublicKey)

            val sharedSecret: ByteArray = computeSharedSecret(agreementAlg, piccPublicKey, pcdPrivateKey)

            wrapper = restartSecureMessaging(oid, sharedSecret, maxTranceiveLength, shouldCheckMAC)

            return EACCAResult(keyId, piccPublicKey, keyHash, pcdPublicKey, pcdPrivateKey, wrapper)
        } catch (e: GeneralSecurityException) {
            throw CardServiceException("Security exception during Chip Authentication", e)
        }
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")

        private val BC_PROVIDER = getBouncyCastleProvider()

        private const val COMMAND_CHAINING_CHUNK_SIZE = 223

        /**
         * Sends the PCD's public key to the PICC.
         *
         * @param service the card service
         * @param wrapper the existing secure messaging wrapper
         * @param oid the Chip Authentication object identifier
         * @param keyId a key identifier or `null`
         * @param pcdPublicKey the public key to send
         *
         * @throws CardServiceException on error
         */
        @Throws(CardServiceException::class)
        fun sendPublicKey(service: APDULevelEACCACapable, wrapper: SecureMessagingWrapper?, oid: String?, keyId: BigInteger?, pcdPublicKey: PublicKey?) {
            val agreementAlg = ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid)
            val cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid)
            val keyData: ByteArray = getKeyData(agreementAlg, pcdPublicKey)

            if (cipherAlg.startsWith("DESede")) {
                var idData: ByteArray? = null
                if (keyId != null) {
                    val keyIdBytes = i2os(keyId)
                    idData = wrapDO(0x84, keyIdBytes) /* FIXME: Constant for 0x84. */
                }
                try {
                    service.sendMSEKAT(wrapper, wrapDO(0x91, keyData), idData) /* FIXME: Constant for 0x91. */
                } catch (e: Exception) {
                    throw CardServiceProtocolException("Exception during MSE KAT", 1, e)
                }
            } else if (cipherAlg.startsWith("AES")) {
                try {
                    service.sendMSESetATIntAuth(wrapper, oid, keyId)
                } catch (e: Exception) {
                    throw CardServiceProtocolException("Exception during MSE Set AT Int Auth", 1, e)
                }

                try {
                    val data = wrapDO(0x80, keyData) /* FIXME: Constant for 0x80. */
                    sendGeneralAuthenticate(service, wrapper, data)
                } catch (e: Exception) {
                    throw CardServiceProtocolException("Exception during General Authenticate", 2, e)
                }
            } else {
                throw IllegalStateException("Cannot set up secure channel with cipher " + cipherAlg)
            }
        }

        /**
         * Performs the key agreement step.
         * Generates a secret based on the PICC's public key and the PCD's private key.
         *
         * @param agreementAlg the agreement algorithm
         * @param piccPublicKey the PICC's public key
         * @param pcdPrivateKey the PCD's private key
         *
         * @return the shared secret
         *
         * @throws NoSuchAlgorithmException if the agreement algorithm is unsupported
         *
         * @throws InvalidKeyException if one of the keys is invalid
         */
        @Throws(NoSuchAlgorithmException::class, InvalidKeyException::class)
        fun computeSharedSecret(agreementAlg: String, piccPublicKey: PublicKey?, pcdPrivateKey: PrivateKey?): ByteArray {
            val agreement: KeyAgreement = KeyAgreement.getInstance(agreementAlg, BC_PROVIDER)
            agreement.init(pcdPrivateKey)
            agreement.doPhase(piccPublicKey, true)
            return agreement.generateSecret()
        }

        /**
         * Restarts secure messaging based on the shared secret.
         *
         * @param oid the Chip Authentication object identifier
         * @param sharedSecret the shared secret
         * @param maxTranceiveLength the maximum APDU tranceive length
         * @param shouldCheckMAC whether to check MAC
         *
         * @return the secure messaging wrapper
         *
         * @throws GeneralSecurityException on error
         */
        @Throws(GeneralSecurityException::class)
        fun restartSecureMessaging(oid: String?, sharedSecret: ByteArray, maxTranceiveLength: Int, shouldCheckMAC: Boolean): SecureMessagingWrapper {
            val cipherAlg = ChipAuthenticationInfo.toCipherAlgorithm(oid)
            val keyLength = ChipAuthenticationInfo.toKeyLength(oid)

            /* Start secure messaging. */
            val ksEnc = deriveKey(sharedSecret, cipherAlg, keyLength, Util.ENC_MODE)
            val ksMac = deriveKey(sharedSecret, cipherAlg, keyLength, Util.MAC_MODE)

            if (cipherAlg.startsWith("DESede")) {
                return DESedeSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, 0L)
            } else if (cipherAlg.startsWith("AES")) {
                return AESSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, 0L)
            } else {
                throw IllegalStateException("Unsupported cipher algorithm " + cipherAlg)
            }
        }

        /**
         * Returns the key hash which will be used as input for Terminal Authentication.
         *
         * @param agreementAlg the agreement algorithm, either `"DH"` or `"ECDH"`
         * @param pcdPublicKey the inspection system's public key
         *
         * @return the key hash
         *
         * @throws NoSuchAlgorithmException on error
         */
        @Throws(NoSuchAlgorithmException::class)
        fun getKeyHash(agreementAlg: String?, pcdPublicKey: PublicKey?): ByteArray? {
            if ("DH" == agreementAlg || pcdPublicKey is DHPublicKey) {
                /* TODO: this is probably wrong, what should be hashed? */
                val md = MessageDigest.getInstance("SHA-1")
                return md.digest(getKeyData(agreementAlg, pcdPublicKey))
            } else if ("ECDH" == agreementAlg || pcdPublicKey is ECPublicKey) {
                val pcdECPublicKey = pcdPublicKey as org.bouncycastle.jce.interfaces.ECPublicKey
                val t = i2os(pcdECPublicKey.getQ().getAffineXCoord().toBigInteger())
                val keySize = ceil(pcdECPublicKey.getParameters().getCurve().getFieldSize() / 8.0).toInt()
                return alignKeyDataToSize(t, keySize)
            }

            throw IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg)
        }

        /**
         * Sends the General Authenticate APDU in the AES case, possibly falling back to Command Chaining.
         *
         * @param service the card service
         * @param wrapper the existing secure messaging wrapper
         * @param data the key data, already wrapped as a data-object
         *
         * @throws CardServiceException on low-level communication error
         */
        @Throws(CardServiceException::class)
        private fun sendGeneralAuthenticate(service: APDULevelEACCACapable, wrapper: SecureMessagingWrapper?, data: ByteArray?) {
            try {
                service.sendGeneralAuthenticate(wrapper, data, true)
            } catch (cse: CardServiceException) {
                LOGGER.log(Level.WARNING, "Failed to send GENERAL AUTHENTICATE, falling back to command chaining", cse)
                val segments = partition(COMMAND_CHAINING_CHUNK_SIZE, data)

                var index = 0
                for (segment in segments) {
                    service.sendGeneralAuthenticate(wrapper, segment, ++index >= segments.size)
                }
            }
        }

        /**
         * Returns the public key data to be sent.
         *
         * @param agreementAlg the agreement algorithm, either `"DH"` or `"ECDH"`
         * @param pcdPublicKey the inspection system's public key
         *
         * @return the key data
         */
        private fun getKeyData(agreementAlg: String?, pcdPublicKey: PublicKey?): ByteArray {
            if ("DH" == agreementAlg) {
                val pcdDHPublicKey = pcdPublicKey as DHPublicKey
                return i2os(pcdDHPublicKey.getY())
            } else if ("ECDH" == agreementAlg) {
                val pcdECPublicKey = pcdPublicKey as org.bouncycastle.jce.interfaces.ECPublicKey
                return pcdECPublicKey.getQ().getEncoded(false)
            }

            throw IllegalArgumentException("Unsupported agreement algorithm " + agreementAlg)
        }

        /**
         * Infers the Chip Authentication OID from a Chip Authentication public key OID.
         * This is a best effort.
         *
         * @param publicKeyOID the Chip Authentication public key OID
         *
         * @return an OID or `null`
         */
        private fun inferChipAuthenticationOIDfromPublicKeyOID(publicKeyOID: String?): String? {
            if (SecurityInfo.ID_PK_ECDH == publicKeyOID) {
                /*
       * This seems to work for French passports (generation 2013, 2014),
       * but it is best effort.
       */
                LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-ECDH-3DES-CBC-CBC")
                return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC
            } else if (SecurityInfo.ID_PK_DH == publicKeyOID) {
                /*
       * Not tested. Best effort.
       */
                LOGGER.warning("Could not determine ChipAuthentication algorithm, defaulting to id-CA-DH-3DES-CBC-CBC")
                return SecurityInfo.ID_CA_DH_3DES_CBC_CBC
            } else {
                LOGGER.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID " + publicKeyOID)
            }

            return null
        }
    }
}
