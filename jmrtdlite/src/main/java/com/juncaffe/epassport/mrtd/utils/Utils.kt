package com.juncaffe.epassport.mrtd.utils

import com.juncaffe.epassport.mrtd.AccessKeySpec
import com.juncaffe.epassport.mrtd.BACKeySpec
import com.juncaffe.epassport.mrtd.PACEKeySpec
import com.juncaffe.epassport.mrtd.lds.LDSFile
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PKCS7Padding
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.logging.Logger

internal object Utils {
    private val LOGGER = Logger.getLogger("org.jmrtd")

    /**
     * Computes the static key seed, based on information from the MRZ.
     *
     * @param documentNumber a string containing the document number
     * @param dateOfBirth a string containing the date of birth (YYMMDD)
     * @param dateOfExpiry a string containing the date of expiry (YYMMDD)
     * @param digestAlg a Java mnemonic algorithm string to indicate the digest algorithm (typically SHA-1)
     * @param doTruncate whether to truncate the resulting output to 16 bytes
     *
     * @return a byte array of length 16 containing the key seed
     *
     * @throws GeneralSecurityException on security error
     */
    @Throws(GeneralSecurityException::class)
    fun computeKeySeed(documentNumber: ByteArray, dateOfBirth: ByteArray, dateOfExpiry: ByteArray, digestAlg: String, doTruncate: Boolean): ByteArray {
        val result: ByteArray
        run {
            val buffer = ByteBuffer.allocate(documentNumber.size + dateOfBirth.size + dateOfExpiry.size + 4)
            buffer.put(documentNumber)
            buffer.put(MRZUtils.checkDigit(documentNumber))
            buffer.put(dateOfBirth)
            buffer.put(MRZUtils.checkDigit(dateOfBirth))
            buffer.put(dateOfExpiry)
            buffer.put(MRZUtils.checkDigit(dateOfExpiry))

            buffer.flip()
            result = ByteArray(buffer.remaining())
            buffer.get(result)
            buffer.clear()
            while (buffer.hasRemaining()) {
                buffer.put(0)
            }
        }
        return computeKeySeed(result, digestAlg, doTruncate)
    }

    /**
     * Computes the key seed from a card access number (CAN) to derive
     * secure messaging keys from.
     *
     * @param cardAccessNumber the card access number
     * @param digestAlg the digest algorithm to use
     * @param doTruncate whether to truncate to 16 bytes or not
     *
     * @return the resulting key seed
     *
     * @throws GeneralSecurityException on error
     */
    @Throws(GeneralSecurityException::class)
    fun computeKeySeed(cardAccessNumber: ByteArray, digestAlg: String, doTruncate: Boolean): ByteArray {
        val shaDigest = MessageDigest.getInstance(digestAlg)
        shaDigest.update(cardAccessNumber)
        val hash = shaDigest.digest()
        cardAccessNumber.fill(0)
        if (doTruncate) {
            val keySeed = ByteArray(16)
            System.arraycopy(hash, 0, keySeed, 0, 16)
            return keySeed
        } else {
            return hash
        }
    }

    /**
     * Computes a key seed given a card access number (CAN).
     *
     * @param cardAccessNumber the card access number
     *
     * @return a key seed for deriving secure messaging keys
     *
     * @throws GeneralSecurityException on error
     */
    @Throws(GeneralSecurityException::class)
    fun computeKeySeedForPACE(cardAccessNumber: ByteArray): ByteArray {
        return computeKeySeed(cardAccessNumber, "SHA-1", false)
    }

    /**
     * Computes a key seed based on an access key.
     *
     * @param accessKey the access key
     *
     * @return a key seed for secure messaging keys
     *
     * @throws GeneralSecurityException on error
     */
    @Throws(GeneralSecurityException::class)
    fun computeKeySeedForPACE(accessKey: AccessKeySpec): ByteArray {
        /* MRZ based key. */
        if (accessKey is BACKeySpec) {
            val bacKey = accessKey
            val documentNumber = bacKey.getDocumentNumber()
            val dateOfBirth = bacKey.getDateOfBirth()
            val dateOfExpiry = bacKey.getDateOfExpiry()
            require(dateOfBirth.size == 6) { "Wrong date format used for date of birth. Expected yyMMdd, found " + dateOfBirth }
            require(dateOfBirth.size == 6) { "Wrong date format used for date of expiry. Expected yyMMdd, found " + dateOfExpiry }

            return computeKeySeedForPACE(documentNumber, dateOfBirth, dateOfExpiry)
        }

        if (accessKey is PACEKeySpec) {
            return accessKey.getKey()
        }

        LOGGER.warning("JMRTD doesn't recognize this type of access key, best effort key derivation!")
        return accessKey.getKey()
    }

    /**
     * Computes the static key seed to be used in PACE KDF, based on information from the MRZ.
     *
     * @param documentNumber a bytes containing the document number
     * @param dateOfBirth a bytes containing the date of birth (YYMMDD)
     * @param dateOfExpiry a bytes containing the date of expiry (YYMMDD)
     *
     * @return a byte array of length 16 containing the key seed
     *
     * @throws GeneralSecurityException on security error
     */
    @Throws(GeneralSecurityException::class)
    private fun computeKeySeedForPACE(documentNumber: ByteArray, dateOfBirth: ByteArray, dateOfExpiry: ByteArray): ByteArray {
        return computeKeySeed(documentNumber, dateOfBirth, dateOfExpiry, "SHA-1", false)
    }

    /**
     * Finds a data group number for an ICAO tag.
     *
     * @param tag an ICAO tag (the first byte of the EF)
     *
     * @return a data group number (1-16)
     */
    @JvmStatic
    fun lookupDataGroupNumberByTag(tag: Int): Int {
        when (tag) {
            LDSFile.EF_DG1_TAG -> return 1
            LDSFile.EF_DG2_TAG -> return 2
            LDSFile.EF_DG14_TAG -> return 14
            else -> throw NumberFormatException("Unknown tag " + Integer.toHexString(tag))
        }
    }

    /**
     * AES256 CBC/PKCS7Padding 복호화
     */
    @JvmStatic
    fun decrypt(orgData: ByteArray, sKey: ByteArray, sIv: ByteArray): ByteArray {
        return crypto(orgData, sKey, sIv, false)
    }

    /**
     * AES256 CBC/PKCS7Padding 암호화
     */
    @JvmStatic
    fun encrypt(orgData: ByteArray, sKey: ByteArray, sIv: ByteArray): ByteArray {
        return crypto(orgData, sKey, sIv, true)
    }

    private fun crypto(orgData: ByteArray, sKey: ByteArray, sIv: ByteArray, forEncryption: Boolean): ByteArray {
        val blockCipher = CBCBlockCipher.newInstance(AESEngine.newInstance())
        val cipher = PaddedBufferedBlockCipher(blockCipher, PKCS7Padding())
        val cipherParam = ParametersWithIV(KeyParameter(sKey), sIv)
        cipher.init(forEncryption, cipherParam)

        val cryptoBytes = ByteArray(cipher.getOutputSize(orgData.size))
        val length = cipher.processBytes(orgData, 0, orgData.size, cryptoBytes, 0)
        val unpaddedLen = cipher.doFinal(cryptoBytes, length)

        val cryptoData = cryptoBytes.copyOf(length + unpaddedLen)
        cryptoBytes.fill(0)

        return cryptoData
    }
}