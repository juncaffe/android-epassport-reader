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
 * $Id: PassportService.java 1850 2021-05-21 06:25:03Z martijno $
 */

package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.mrtd.lds.DataGroup
import com.juncaffe.epassport.mrtd.lds.icao.DG14File
import com.juncaffe.epassport.mrtd.lds.icao.DG1File
import com.juncaffe.epassport.mrtd.lds.icao.DG2File
import com.juncaffe.epassport.mrtd.protocol.BACAPDUSender
import com.juncaffe.epassport.mrtd.protocol.BACProtocol
import com.juncaffe.epassport.mrtd.protocol.BACResult
import com.juncaffe.epassport.mrtd.protocol.EACCAAPDUSender
import com.juncaffe.epassport.mrtd.protocol.EACCAProtocol
import com.juncaffe.epassport.mrtd.protocol.EACCAResult
import com.juncaffe.epassport.mrtd.protocol.PACEAPDUSender
import com.juncaffe.epassport.mrtd.protocol.PACEProtocol
import com.juncaffe.epassport.mrtd.protocol.PACEResult
import com.juncaffe.epassport.mrtd.protocol.ReadBinaryAPDUSender
import com.juncaffe.epassport.mrtd.protocol.SecureMessagingWrapper
import com.juncaffe.epassport.smartcard.APDUEvent
import com.juncaffe.epassport.smartcard.APDUListener
import com.juncaffe.epassport.smartcard.CardFileInputStream
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import java.util.logging.Logger
import javax.crypto.SecretKey

/**
 * Card service for reading files (such as data groups) and using the various
 * access control protocols (BAC, PACE, EAC-TA), clone-detection verification
 * protocols (AA, EAC-CA), and the resulting secure messaging as implemented
 * by the MRTD ICC.
 *
 * Based on ICAO Doc 9303 2015.
 * Originally based on ICAO-TR-PKI and ICAO-TR-LDS.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision:352 $
 */
class PassportService(service: CardService): AbstractMRTDCardService(service) {

  companion object {
    val LOGGER: Logger = Logger.getLogger("org.jmrtd")

    /** Shared secret type for non-PACE key. */
    const val NO_PACE_KEY_REFERENCE: Byte = 0x00

    /** Shared secret type for PACE according to BSI TR-03110 v2.03 B.11.1. */
    const val MRZ_PACE_KEY_REFERENCE: Byte = 0x01

    /** The default maximal blocksize used for unencrypted APDUs. */
    const val DEFAULT_MAX_BLOCKSIZE: Int = 223

    /** The normal maximal tranceive length of APDUs. */
    const val NORMAL_MAX_TRANCEIVE_LENGTH: Int = 256

    /** The extended maximal tranceive length of APDUs. */
    const val EXTENDED_MAX_TRANCEIVE_LENGTH: Int = 65536

    /** The applet we select when we start a session. */
    @JvmField
    val APPLET_AID: ByteArray = byteArrayOf(0xA0.toByte(), 0x00.toByte(), 0x00.toByte(), 0x02.toByte(), 0x47.toByte(), 0x10.toByte(), 0x01.toByte())
  }

  /**
   * Elementary File
   */
  enum class EF(val fid: Short) {
    /** Card Access. */
    CARD_ACCESS(0x011C),
    /** The data group presence list */
    COM(0x011E),
    /** The security document */
    SOD(0x011D),
    /** File identifier for data group 1. Data group 1 contains the MRZ. */
    DG1(0x0101),
    /** File identifier for data group 2. Data group 2 contains face image data. */
    DG2(0x0102),
    /** 칩 인증과 PACE 등 보안 프로토콜 관련 정보 (ChipAuthenticationInfo, ChipAuthenticationPublicKeyInfo, PACEInfo) */
    DG14(0x010E);

    fun getSodKey(): Int {
      return when(this) {
        DG1 -> 1
        DG2 -> 2
        DG14 -> 14
        else -> -1
      }
    }

    fun selectApdu(): ByteArray {
      val i = fid.toInt() and 0xFFFF
      return byteArrayOf(
        0x00.toByte(), // CLA
        0xA4.toByte(), // INS (SELECT FILE)
        0x02.toByte(), // P1 (by FID)
        0x0C.toByte(), // P2 (no FCI : File Control Info)
        0x02.toByte(), // Lc (length of FID)
        ((i shr 8) and 0xFF).toByte(), // DATA (FID)
        (i and 0xFF).toByte() // DATA (FID)
      )
    }
  }

  /**
   * The file read block size, some passports cannot handle large values.
   */
  private var maxBlockSize: Int = 0
  private var wrapper: SecureMessagingWrapper? = null
  private var maxTranceiveLengthForSecureMessaging: Int = 0
  private var maxTranceiveLengthForPACEProtocol: Int = 0
  private var shouldCheckMAC: Boolean = false
  private var isAppletSelected: Boolean = false

  private lateinit var rootFileSystem: DefaultFileSystem
  private lateinit var appletFileSystem: DefaultFileSystem

  private lateinit var bacSender: BACAPDUSender
  private lateinit var paceSender: PACEAPDUSender
  private lateinit var eacCASender: EACCAAPDUSender
  private lateinit var readBinarySender: ReadBinaryAPDUSender

  /**
   * Creates a new passport service for accessing the passport.
   *
   * @param service another service which will deal with sending the APDUs to the card
   * @param maxTranceiveLengthForPACEProtocol maximum length  to use in PACE protocol steps, {@code 256} or {@code 65536}
   * @param maxTranceiveLengthForSecureMessaging maximum length to use in secure messaging APDUs, {@code 256} or {@code 65536}
   * @param maxBlockSize maximum buffer size for plain text APDUs
   * @param isSFIEnabled whether short file identifiers should be used for read binaries when possible
   * @param shouldCheckMAC whether the secure messaging channels, resulting from BAC, PACE, EAC-CA, should
   *                       check MACs on response APDUs
   */
  constructor(service: CardService, maxTranceiveLengthForPACEProtocol: Int = NORMAL_MAX_TRANCEIVE_LENGTH, maxTranceiveLengthForSecureMessaging: Int, maxBlockSize: Int, shouldCheckMAC: Boolean) : this(service) {
    this.service = service
    this.maxTranceiveLengthForPACEProtocol = maxTranceiveLengthForPACEProtocol
    this.maxTranceiveLengthForSecureMessaging = maxTranceiveLengthForSecureMessaging
    this.maxBlockSize = maxBlockSize
    this.shouldCheckMAC = shouldCheckMAC
    this.isAppletSelected = false

    this.bacSender = BACAPDUSender(service)
    this.paceSender = PACEAPDUSender(service)
    this.eacCASender = EACCAAPDUSender(service)
    this.readBinarySender = ReadBinaryAPDUSender(service)

    this.rootFileSystem = DefaultFileSystem(readBinarySender)
    this.appletFileSystem = DefaultFileSystem(readBinarySender)
  }

  fun getDataGroupSize(list: List<EF> = listOf(EF.DG1, EF.DG2, EF.DG14)): Int {
    return if (!isAppletSelected) {
      synchronized(rootFileSystem) {
        list.sumOf { rootFileSystem.getFileTotalLength(it.fid) }.also {
          rootFileSystem.wipe()
        }
      }
    }else {
      synchronized(appletFileSystem) {
        list.sumOf { appletFileSystem.getFileTotalLength(it.fid) }.also {
          appletFileSystem.wipe()
        }
      }
    }
  }

  /**
   * Selects the card side applet. If PACE has been executed successfully previously, then the ICC has authenticated
   * us and a secure messaging channel has already been established. If not, then the caller should request BAC execution as a next
   * step.
   *
   * @param hasPACESucceeded indicates whether PACE has been executed successfully (in which case a secure messaging channel has been established)
   *
   * @throws CardServiceException on error
   */
  @Throws(CardServiceException::class)
  override fun sendSelectApplet(hasPACESucceeded: Boolean) {
    if (isAppletSelected) {
      LOGGER.info("Re-selecting ICAO applet")
    }

    if (hasPACESucceeded) {
      /* Use SM as set up by doPACE() */
      readBinarySender.sendSelectApplet(wrapper, APPLET_AID)
    } else {
      /* Use plain messaging to select the applet, caller will have to do doBAC. */
      readBinarySender.sendSelectApplet(null, APPLET_AID)
    }
    isAppletSelected = true
  }


  /**
   * Sends a {@code SELECT MF} command to the card.
   *
   * @throws CardServiceException on tranceive error
   */
  @Throws(CardServiceException::class)
  override fun sendSelectMF() {
    readBinarySender.sendSelectMF()
    wrapper = null
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   *
   * @param bacKey the key based on the document number,
   *               the card holder's birth date,
   *               and the document's expiration date
   *
   * @return the BAC result
   *
   * @throws CardServiceException if authentication failed
   */
  @Synchronized
  @Throws(CardServiceException::class)
  override fun doBAC(bacKey: AccessKeySpec): BACResult {
    require(bacKey is BACKeySpec) { "Unsupported key type" }
    val bacResult = BACProtocol(bacSender, maxTranceiveLengthForSecureMessaging, shouldCheckMAC).doBAC(bacKey)
    wrapper = bacResult.wrapper
    appletFileSystem.setWrapper(wrapper)
    return bacResult
  }

  /**
   * Performs the <i>Basic Access Control</i> protocol.
   * It does BAC using kEnc and kMac keys, usually calculated
   * from the document number, the card holder's date of birth,
   * and the card's date of expiry.
   *
   * A secure messaging channel is set up as a result.
   *
   * @param kEnc static 3DES key required for BAC
   * @param kMac static 3DES key required for BAC
   *
   * @return the result
   *
   * @throws CardServiceException if authentication failed
   * @throws GeneralSecurityException on security primitives related problems
   */
  @Synchronized
  @Throws(CardServiceException::class, GeneralSecurityException::class)
  override fun doBAC(kEnc: SecretKey, kMac: SecretKey): BACResult {
    val bacResult = BACProtocol(bacSender, maxTranceiveLengthForSecureMessaging, shouldCheckMAC).doBAC(kEnc, kMac)
    wrapper = bacResult.wrapper
    appletFileSystem.setWrapper(wrapper)
    return bacResult
  }

  /**
   * Performs the PACE 2.0 / SAC protocol.
   * A secure messaging channel is set up as a result.
   *
   * @param keySpec the MRZ
   * @param oid as specified in the PACEInfo, indicates GM or IM or CAM, DH or ECDH, cipher, digest, length
   * @param params explicit static domain parameters the domain params for DH or ECDH
   * @param parameterId parameter identifier or {@code null}
   *
   * @return the result
   *
   * @throws CardServiceException on error
   */
  @Synchronized
  @Throws(CardServiceException::class)
  override fun doPACE(keySpec: AccessKeySpec, oid: String, params: AlgorithmParameterSpec, parameterId: BigInteger?): PACEResult {
    val paceResult = PACEProtocol(paceSender, wrapper, maxTranceiveLengthForPACEProtocol, maxTranceiveLengthForSecureMessaging, shouldCheckMAC).doPACE(keySpec, oid, params, parameterId)
    wrapper = paceResult.wrapper
    appletFileSystem.setWrapper(wrapper)
    if(keySpec is PACEKeySpec)
      keySpec.wipe()
    return paceResult
  }
  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   * A new secure messaging channel is set up as a result.
   *
   * @param keyId passport's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the object identifier indicating the public key algorithm used
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  @Synchronized
  @Throws(CardServiceException::class)
  override fun doEACCA(keyId: BigInteger?, oid: String?, publicKeyOID: String, publicKey: PublicKey): EACCAResult {
    // keyId가 nullable일 수 있음을 명시
    val caResult = EACCAProtocol(eacCASender, getWrapper(), maxTranceiveLengthForSecureMessaging, shouldCheckMAC)
      .doCA(keyId, oid, publicKeyOID, publicKey)
    wrapper = caResult.wrapper
    appletFileSystem.setWrapper(wrapper)
    return caResult
  }

  fun wipe() {
    rootFileSystem.wipe()
    appletFileSystem.wipe()
  }

  /**
   * Closes this service.
   */
  override fun close() {
    wipe()
    service.close()
    wrapper = null
  }

  /**
   * Returns the maximum tranceive length of (protected) APDUs.
   *
   * @return the maximum APDU tranceive length
   */
  fun getMaxTranceiveLength(): Int {
    return maxTranceiveLengthForSecureMessaging
  }

  /**
   * Returns the secure messaging wrapper currently in use.
   * Returns {@code null} until access control has been performed.
   *
   * @return the wrapper
   */
  override fun getWrapper(): SecureMessagingWrapper? { // 반환 타입 nullable로 변경
    val ldsSecureMessagingWrapper = appletFileSystem.getWrapper() as? SecureMessagingWrapper // 안전한 캐스팅
    // wrapper가 null일 수 있으므로 null 검사 강화
    val currentWrapper = wrapper
    if (ldsSecureMessagingWrapper != null && (currentWrapper == null || ldsSecureMessagingWrapper.getSendSequenceCounter() > currentWrapper.getSendSequenceCounter())) {
      wrapper = ldsSecureMessagingWrapper
    }
    return wrapper
  }

    /**
   * Whether secure channels should check the MAC on response APDUs sent by the ICC.
   *
   * @return a boolean indicating whether the MAC should be checked
   */
  fun shouldCheckMAC(): Boolean {
    return shouldCheckMAC
  }

  /**
   * Returns the file indicated by the file identifier as an input stream.
   * The resulting input stream will send APDUs to the card as it is being read.
   *
   * @param fid the file identifier
   * @param maxBlockSize the blocksize to request in plain READ BINARY commands
   *
   * @return the file as an input stream
   *
   * @throws CardServiceException if the file cannot be read
   */
  @Synchronized
  @Throws(CardServiceException::class)
  override fun getInputStream(fid: EF, maxBlockSize: Int): CardFileInputStream {
    return if (!isAppletSelected) {
      synchronized(rootFileSystem) {
        rootFileSystem.selectFile(fid.fid)
        CardFileInputStream(maxBlockSize, rootFileSystem)
      }
    } else {
      synchronized(appletFileSystem) {
        appletFileSystem.selectFile(fid.fid)
        CardFileInputStream(maxBlockSize, appletFileSystem)
      }
    }
  }

  fun getDGFile(fid: EF, onProgress: ProgressListener? = null): DataGroup? {
    val inputStream = getInputStream(fid, DEFAULT_MAX_BLOCKSIZE)
    return when(fid) {
      EF.DG1 -> DG1File(inputStream, onProgress)
      EF.DG2 -> DG2File(inputStream, onProgress)
      EF.DG14 -> DG14File(inputStream, onProgress)
      else -> null
    }
  }

  /**
   * Returns the currently set maximum length to be requested in READ BINARY commands.
   * If the applet file system has not been selected, this will return
   * {@link #NORMAL_MAX_TRANCEIVE_LENGTH}.
   *
   * @return the currently set maximum length to be requested in READ BINARY commands
   */
  override fun getMaxReadBinaryLength(): Int {
    // appletFileSystem이 non-null 프로퍼티이므로 null 체크 불필요 (생성자에서 초기화)
    return appletFileSystem.getMaxReadBinaryLength()
  }

  override fun getAPDUListeners(): MutableCollection<APDUListener> {
    return service.getAPDUListeners()
  }

  override fun notifyExchangedAPDU(event: APDUEvent?) {
    val apduListeners = getAPDUListeners()

    apduListeners.takeIf { it.isNotEmpty() }?.forEach { apduListener ->
      apduListener.exchangedAPDU(event)
    }
  }

  fun interface ProgressListener {
    fun onProgress(currentReadSize: Int, accumulatedReadSize: Int, totalReadSize: Int)
  }
}
