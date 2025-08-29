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
 * $Id: PACEKeySpec.java 1816 2019-07-15 13:02:26Z martijno $
 */

package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.mrtd.utils.Utils.computeKeySeedForPACE
import com.juncaffe.epassport.smartcard.util.Hex
import java.security.GeneralSecurityException
import java.util.Arrays

/**
 * A key for PACE, can be CAN, MRZ, PIN, or PUK.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1816 $
 *
 * (Contributions by g.giorkhelidze.)
 */
class PACEKeySpec: AccessKeySpec {

  private var key: ByteArray

  @JvmField
  var keyReference: Byte = PassportService.MRZ_PACE_KEY_REFERENCE

  /**
   * Creates a PACE key from relevant details from a Machine Readable Zone.
   *
   * @param mrz the details from the Machine Readable Zone
   *
   * @return the PACE key
   *
   * @throws GeneralSecurityException on error
   */
  @Throws(GeneralSecurityException::class)
  constructor(mrz: BACKeySpec) {
    this.key = computeKeySeedForPACE(mrz)
    this.keyReference = PassportService.MRZ_PACE_KEY_REFERENCE
    mrz.wipe()
  }


  /**
   * Returns the algorithm.
   *
   * @return the algorithm
   */
  override fun getAlgorithm(): String {
    return "PACE"
  }

  /**
   * Returns the type of key, valid values are
   * {@code MRZ_PACE_KEY_REFERENCE}, {@code CAN_PACE_KEY_REFERENCE},
   * {@code PIN_PACE_KEY_REFERENCE}, {@code PUK_PACE_KEY_REFERENCE}.
   *
   * @return the type of key
   */
  fun getKeyReference(): Byte {
    return keyReference
  }

  /**
   * Returns the key bytes.
   *
   * @return the key bytes
   */
  override fun getKey(): ByteArray {
    return key
  }

  override fun wipe() {
    key.fill(0)
  }

  override fun hashCode(): Int {
    val prime = 31
    var result = 1
    result = prime * result + Arrays.hashCode(key)
    result = prime * result + keyReference
    return result
  }

  override fun equals(obj: Any?): Boolean {
    if (this == obj) {
      return true
    }
    if (obj == null) {
      return false
    }
    if (this.javaClass != obj.javaClass) {
      return false
    }
    val other = obj as PACEKeySpec
    if (!Arrays.equals(key, other.key)) {
      return false
    }
    if (keyReference != other.keyReference) {
      return false
    }
    return true
  }

  override fun toString(): String {
    return StringBuilder()
      .append("PACEKeySpec [")
      .append("key: ").append(Hex.bytesToHexString(key)).append(", ")
      .append("keyReference: ").append(keyReferenceToString(keyReference))
      .append("]")
      .toString()
  }

  /**
   * Returns a textual representation of the given key reference parameter.
   *
   * @param keyReference a key reference parameter
   *
   * @return a textual representation of the key reference
   */
  private fun keyReferenceToString(keyReference: Byte): String  {
    when (keyReference) {
     PassportService.MRZ_PACE_KEY_REFERENCE -> return "MRZ"
     PassportService.NO_PACE_KEY_REFERENCE -> return "NO"
      else -> return keyReference.toString()
    }
  }
}

