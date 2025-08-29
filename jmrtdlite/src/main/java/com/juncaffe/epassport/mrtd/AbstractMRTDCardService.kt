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
 * $Id: AbstractMRTDCardService.java 1850 2021-05-21 06:25:03Z martijno $
 */

package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.mrtd.protocol.BACResult
import com.juncaffe.epassport.mrtd.protocol.EACCAResult
import com.juncaffe.epassport.mrtd.protocol.PACEResult
import com.juncaffe.epassport.mrtd.protocol.SecureMessagingWrapper
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import java.math.BigInteger
import java.security.GeneralSecurityException
import java.security.PublicKey
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.SecretKey

/**
 * Base class for MRTD card services.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1850 $
 *
 * @since 0.7.0
 */
abstract class AbstractMRTDCardService(service: CardService): FileSystemCardService(service) {

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
  @Throws(CardServiceException::class)
  abstract fun doBAC(bacKey: AccessKeySpec): BACResult

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
  @Throws(CardServiceException::class, GeneralSecurityException::class)
  abstract fun doBAC(kEnc: SecretKey, kMac: SecretKey):BACResult

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
   * @throws CardServiceException if authentication failed or on error
   */
  @Throws(CardServiceException::class)
  abstract fun doPACE(keySpec: AccessKeySpec, oid: String, params: AlgorithmParameterSpec, parameterId: BigInteger?): PACEResult

  /**
   * Selects the card side applet. If PACE has been executed successfully previously, then the card has authenticated
   * us and a secure messaging channel has already been established. If not, then the caller should request BAC execution
   * as a next step.
   *
   * @param shouldUseSecureMessaging indicates whether a secure messaging channel has already been established
   *                                 (which is the case if PACE has been executed)
   *
   * @throws CardServiceException on error
   */
  @Throws(CardServiceException::class)
  abstract fun sendSelectApplet(shouldUseSecureMessaging: Boolean)

  /**
   * Selects the master file.
   *
   * @throws CardServiceException on error
   */
  @Throws(CardServiceException::class)
  abstract fun sendSelectMF()

  /**
   * Perform CA (Chip Authentication) part of EAC (version 1). For details see TR-03110
   * ver. 1.11. In short, we authenticate the chip with (EC)DH key agreement
   * protocol and create new secure messaging keys.
   * A new secure messaging channel is set up as a result.
   *
   * @param keyId the chip's public key id (stored in DG14), {@code null} if none
   * @param oid the object identifier indicating the Chip Authentication protocol
   * @param publicKeyOID the object identifier indicating the public key algorithm used
   * @param publicKey passport's public key (stored in DG14)
   *
   * @return the Chip Authentication result
   *
   * @throws CardServiceException if CA failed or some error occurred
   */
  @Throws(CardServiceException::class)
  abstract fun doEACCA(keyId: BigInteger?, oid: String?, publicKeyOID: String, publicKey: PublicKey): EACCAResult

  /**
   * Returns the secure messaging wrapper currently in use.
   *
   * @return the secure messaging wrapper
   */
  abstract fun getWrapper(): SecureMessagingWrapper?

  /**
   * Returns the currently set maximum length to be requested in READ BINARY commands.
   * If the applet file system has not yet been selected, this will return the normal
   * length.
   *
   * @return the currently set maximum length to be requested in READ BINARY commands
   */
  abstract fun getMaxReadBinaryLength(): Int
}
