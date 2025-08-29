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
 * $Id: SODFile.java 1861 2021-10-26 09:12:59Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds

import com.juncaffe.epassport.bouncycastle.icao.DataGroupHash
import com.juncaffe.epassport.bouncycastle.icao.LDSSecurityObject
import com.juncaffe.epassport.bouncycastle.icao.LDSVersionInfo
import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.epassport.mrtd.lds.LDSFile.EF_SOD_TAG
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.ContentInfo
import org.bouncycastle.asn1.pkcs.SignedData
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.NoSuchAlgorithmException
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Arrays
import java.util.List
import java.util.logging.Level
import java.util.logging.Logger
import javax.security.auth.x500.X500Principal

/**
 * File structure for the EF_SOD file (the Document Security Object).
 * Based on Appendix 3 of Doc 9303 Part 1 Vol 2.
 *
 * Basically the Document Security Object is a SignedData type as specified in
 * <a href="http://www.ietf.org/rfc/rfc3369.txt">RFC 3369</a>.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1861 $
 */
class SODFile: AbstractTaggedLDSFile {
  //  private static final String SHA1_HASH_ALG_OID = "1.3.14.3.2.26";
  //  private static final String SHA1_WITH_RSA_ENC_OID = "1.2.840.113549.1.1.5";
  //  private static final String SHA256_HASH_ALG_OID = "2.16.840.1.101.3.4.2.1";
  //  private static final String E_CONTENT_TYPE_OID = "1.2.528.1.1006.1.20.1";

  /**
   * The object identifier to indicate content-type in encapContentInfo.
   *
   * <pre>
   * id-icao-ldsSecurityObject OBJECT IDENTIFIER ::=
   *    {joint-iso-itu-t(2) international-organizations(23) icao(136) mrtd(1) security(1) ldsSecurityObject(1)}
   * </pre>
   */
  private val ICAO_LDS_SOD_OID = "2.23.136.1.1.1"

  /**
   * This TC_SOD_IOD is apparently used in
   * "PKI for Machine Readable Travel Documents Offering ICC Read-Only Access Version - 1.1, Annex C".
   * Seen in live French and Belgian MRTDs.
   *
   * <pre>
   * id-icao-ldsSecurityObjectid OBJECT IDENTIFIER ::=
   *    {iso(1) identified-organization(3) icao(27) atn-end-system-air(1) security(1) ldsSecurityObject(1)}
   * </pre>
   */
    private val ICAO_LDS_SOD_ALT_OID = "1.3.27.1.1.1"

  /**
   * This is used in some test MRTDs.
   * Appears to have been included in a "worked example" somewhere and perhaps used in live documents.
   *
   * <pre>
   * id-sdu-ldsSecurityObjectid OBJECT IDENTIFIER :=
   *    {iso(1) member-body(2) nl(528) nederlandse-organisatie(1) enschede-sdu(1006) 1 20 1}
   * </pre>
   */
  private val SDU_LDS_SOD_OID = "1.2.528.1.1006.1.20.1"

  /*
   * FIXME: This field is now transient, but probably shouldn't be!
   *
   * - We can either leave this transient and explicitly (de)serialize it in
   *   readObject/writeObject (using BC's getEncoded())
   * - Or replace this field with something that implements Serializable and that we control.
   */
    @Transient
    private lateinit var signedData: SignedData

  /**
   * Constructs a Security Object data structure.
   *
   * @param inputStream some inputstream
   *
   * @throws IOException if something goes wrong
   */
  @Throws(IOException::class)
  constructor(inputStream: InputStream, onProgress: PassportService.ProgressListener? = null): super(EF_SOD_TAG, inputStream, onProgress) {
    /* Will throw IAE if no signer info. */
    SignedDataUtil.getSignerInfo(signedData)
  }

  @Throws(IOException::class)
  override fun readContent(inputStream: InputStream)  {
    this.signedData = SignedDataUtil.readSignedData(inputStream);
  }

  @Throws(IOException::class)
  override fun writeContent(outputStream: OutputStream) {
    SignedDataUtil.writeData(this.signedData, outputStream);
  }

  /**
   * Returns the stored data group hashes indexed by data group number.
   *
   * @return data group hashes indexed by data group number (1 to 16)
   */
  fun getDataGroupHashes(): Map<Int, ByteArray> {
    val hashObjects = getLDSSecurityObject(signedData).getDatagroupHash()
    val hashMap = mutableMapOf<Int, ByteArray>()
    for (hashObject in hashObjects) {
      hashObject?.let {
        val number = it.getDataGroupNumber()
        val hashValue = it.getDataGroupHashValue()?.getOctets()?:byteArrayOf()
        hashMap[number] = hashValue
      }
    }
    return hashMap
  }

  /**
   * Returns the signature (the encrypted digest) over the hashes.
   *
   * @return the encrypted digest
   */
  fun getEncryptedDigest(): ByteArray {
    return SignedDataUtil.getEncryptedDigest(signedData)
  }

  /**
   * Returns the parameters of the digest encryption (signature) algorithm.
   * For instance for {@code "RSASSA/PSS"} this includes the hash algorithm
   * and the salt length.
   *
   * @return the algorithm parameters
   */
  fun getDigestEncryptionAlgorithmParams(): AlgorithmParameterSpec {
    return SignedDataUtil.getDigestEncryptionAlgorithmParams(signedData)
  }

  /**
   * Returns the encoded contents of the signed data over which the
   * signature is to be computed.
   *
   * @return the encoded contents
   *
   * @throws SignatureException if the contents do not check out
   */
  @Throws(SignatureException::class)
  fun getEContent(): ByteArray {
    return SignedDataUtil.getEContent(signedData)
  }

  /**
   * Returns the name of the algorithm used in the data group hashes.
   *
   * @return an algorithm string such as "SHA-1" or "SHA-256"
   */
  fun getDigestAlgorithm(): String? {
    return getDigestAlgorithm(getLDSSecurityObject(signedData))
  }

  /**
   * Extracts the digest algorithm from the security object.
   *
   * @param ldsSecurityObject the security object
   *
   * @return a mnemonic (Java JCE) string representation of the digest algorithm
   */
  private fun getDigestAlgorithm(ldsSecurityObject: LDSSecurityObject): String? {
    try {
      return SignedDataUtil.lookupMnemonicByOID(ldsSecurityObject.getDigestAlgorithmIdentifier()!!.getAlgorithm().getId())
    } catch (nsae: NoSuchAlgorithmException ) {
      LOGGER.log(Level.WARNING, "Exception", nsae)
      return null
    }
  }

  /**
   * Returns the name of the digest algorithm used in the signature.
   *
   * @return an algorithm string such as "SHA-1" or "SHA-256"
   */
  fun getSignerInfoDigestAlgorithm(): String {
    return SignedDataUtil.getSignerInfoDigestAlgorithm(signedData)
  }

  /**
   * Returns the name of the digest encryption algorithm used in the signature.
   *
   * @return an algorithm string such as "SHA256withRSA"
   */
  fun getDigestEncryptionAlgorithm(): String {
    return SignedDataUtil.getDigestEncryptionAlgorithm(signedData)
  }

  /**
   * Returns the version of the LDS if stored in the Security Object (SOd).
   *
   * @return the version of the LDS in "aabb" format or null if LDS &lt; V1.8
   *
   * @since LDS V1.8
   */
  fun getLDSVersion(): String? {
    val ldsVersionInfo = getLDSSecurityObject(signedData).getVersionInfo()
    return ldsVersionInfo?.getLdsVersion()
  }

  /**
   * Returns the version of unicode if stored in the Security Object (SOd).
   *
   * @return the unicode version in "aabbcc" format or null if LDS &lt; V1.8
   *
   * @since LDS V1.8
   */
  fun getUnicodeVersion(): String? {
    val ldsVersionInfo = getLDSSecurityObject(signedData).getVersionInfo()
    return ldsVersionInfo?.getUnicodeVersion()
  }

  /**
   * Returns any embedded (document signing) certificates.
   *
   * If the document signing certificate is embedded, a list of size 1 is returned.
   * If a document signing certificate is not embedded, the empty list is returned.
   *
   * Doc 9303 part 10 (in our interpretation) does not allow multiple certificates
   * here, PKCS7 does allow this.
   *
   * @return the document signing certificate
   */
  fun getDocSigningCertificates(): List<X509Certificate> {
    return SignedDataUtil.getCertificates(signedData) as List<X509Certificate>
  }

  /**
   * Returns the embedded document signing certificate (if present) or
   * {@code null} if not present.
   * Use this certificate to verify that <i>eSignature</i> is a valid
   * signature for <i>eContent</i>. This certificate itself is signed
   * using the country signing certificate.
   *
   * @return the document signing certificate
   */
  fun getDocSigningCertificate(): X509Certificate? {
    val certificates = getDocSigningCertificates()
    if (certificates.isEmpty()) {
      return null
    }

    return certificates.last()
  }

  /**
   * Returns the issuer name of the document signing certificate
   * as it appears in the signer-info in the signed-data structure
   * This returns {@code null} when the signer is identified through
   * subject-key-identifier instead.
   *
   * @return a certificate issuer, or {@code null} if not present
   */
  fun getIssuerX500Principal(): X500Principal? {
    try {
      val issuerAndSerialNumber = SignedDataUtil.getIssuerAndSerialNumber(signedData)
      return issuerAndSerialNumber?.name?.let { name ->
          X500Principal(name.getEncoded(ASN1Encoding.DER))
      }
    } catch (ioe: IOException) {
      LOGGER.log(Level.WARNING, "Could not get issuer", ioe)
      return null
    }
  }

  /**
   * Returns the serial number as it appears in the signer-info in the
   * signed-data structure.
   * This returns {@code null} when the signer is identified through
   * subject-key-identifier instead.
   *
   * @return a certificate serial number, or {@code null} if not present
   */
  fun getSerialNumber(): BigInteger? {
    val issuerAndSerialNumber = SignedDataUtil.getIssuerAndSerialNumber(signedData)
    return issuerAndSerialNumber?.toASN1Primitive().let {
      ((it as ASN1Sequence).getObjectAt(1) as ASN1Integer).value
    }
  }

  /**
   * Returns a textual representation of this file.
   *
   * @return a textual representation of this file
   */
  override fun toString(): String {
    try {
      val result = StringBuilder()
      result.append("SODFile ")
      val certificates = getDocSigningCertificates()
      for (certificate in certificates) {
        result.append(certificate.getIssuerX500Principal().getName())
        result.append(", ")
      }
      return result.toString()
    } catch (e: Exception) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e)
      return "SODFile"
    }
  }

  override fun equals(obj: Any?): Boolean {
    if (obj == null) {
      return false
    }
    if (obj == this) {
      return true
    }
    if (!obj.javaClass.equals(this.javaClass)) {
      return false
    }

    val other = obj as SODFile
    return Arrays.equals(getEncoded(), other.getEncoded())
  }

  override fun hashCode(): Int {
    return 11 * Arrays.hashCode(getEncoded()) + 111
  }

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Encodes a content info for the hash table.
   *
   * @param contentTypeOID the content info OID to use
   * @param digestAlgorithm the digest algorithm
   * @param dataGroupHashes the hash table
   * @param ldsVersion the LDS version
   * @param unicodeVersion the Unicode version
   *
   * @return the content info
   *
   * @throws NoSuchAlgorithmException on error
   * @throws IOException on error writing to memory
   */
  @Throws(NoSuchAlgorithmException::class, IOException::class)
  private fun toContentInfo(contentTypeOID: String, digestAlgorithm: String, dataGroupHashes: Map<Int, ByteArray>, ldsVersion: String?, unicodeVersion: String): ContentInfo {
    val dataGroupHashesArray = arrayOfNulls<DataGroupHash>(dataGroupHashes.size)

    var i = 0
    for(dataGroupNumber in dataGroupHashes.keys) {
      val hashBytes = dataGroupHashes.get(dataGroupNumber)
      val hash = DataGroupHash(dataGroupNumber, DEROctetString(hashBytes))
      dataGroupHashesArray[i++] = hash
    }

    val digestAlgorithmIdentifier = AlgorithmIdentifier(ASN1ObjectIdentifier(SignedDataUtil.lookupOIDByMnemonic(digestAlgorithm)))
    val securityObject = if (ldsVersion == null) {
      LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray)
    } else {
      LDSSecurityObject(digestAlgorithmIdentifier, dataGroupHashesArray, LDSVersionInfo(ldsVersion, unicodeVersion))
    }

    return ContentInfo(ASN1ObjectIdentifier(contentTypeOID), DEROctetString(securityObject))
  }

  /**
   * Reads the security object (containing the hashes
   * of the data groups) found in the {@code SignedData} field.
   *
   * @param signedData the signed data to read from
   *
   * @return the security object
   *
   * @throws IOException on error parsing the signed data
   */
  private fun getLDSSecurityObject(signedData: SignedData): LDSSecurityObject {
    try {
      val signedDataSeq = signedData.toASN1Primitive() as ASN1Sequence
      val encapContentInfoObj = signedDataSeq.getObjectAt(2)
      val encapContentInfo = ContentInfo.getInstance(encapContentInfoObj)
      val contentType = encapContentInfo.getContentType().getId()
      val eContent = encapContentInfo.getContent() as ASN1OctetString
      if (!(ICAO_LDS_SOD_OID.equals(contentType)
          || SDU_LDS_SOD_OID.equals(contentType)
          || ICAO_LDS_SOD_ALT_OID.equals(contentType))) {
        LOGGER.warning("SignedData does not appear to contain an LDS SOd. (content type is " + contentType + ", was expecting " + ICAO_LDS_SOD_OID + ")")
      }
      val inputStream = ASN1InputStream(ByteArrayInputStream(eContent.getOctets()))
      return inputStream.use {
        val firstObject = inputStream.readObject()
        if (!(firstObject is ASN1Sequence)) {
          throw IllegalStateException("Expected ASN1Sequence, found " + firstObject.javaClass.simpleName)
        }
        val sod = LDSSecurityObject.getInstance(firstObject)
        val nextObject = inputStream.readObject()
        if (nextObject != null) {
          LOGGER.warning("Ignoring extra object found after LDSSecurityObject...")
        }
        sod
      }
    } catch (ioe: IOException) {
      throw IllegalStateException("Could not read security object in signedData", ioe)
    }
  }

  companion object {
      private const val serialVersionUID = -1081347374739311111L
      private val LOGGER = Logger.getLogger("org.jmrtd")
  }
}
