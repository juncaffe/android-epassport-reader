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
 * $Id: BACKey.java 1808 2019-03-07 21:32:19Z martijno $
 */

package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.extension.trim
import com.juncaffe.epassport.mrtd.utils.MRZUtils
import com.juncaffe.epassport.mrtd.utils.Utils
import java.security.GeneralSecurityException

/**
 * A BAC key.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
class BACKey: BACKeySpec {
  private var documentNumber: ByteArray
  private var dateOfBirth: ByteArray
  private var dateOfExpiry: ByteArray
  private var accessKey: ByteArray

  constructor(mrz2Info: ByteArray): this(mrz2Info, mrz2Info.trim())

  private constructor(mrz2Info: ByteArray, mrzTrimmed: ByteArray = mrz2Info.trim()): this(
    mrzTrimmed.also { require(it.size >= 27) { "Invalid MRZ2 length" } }.sliceArray(0 .. 8),
    mrzTrimmed.sliceArray(13 .. 18),
    mrzTrimmed.sliceArray(21 .. 26).also {
      mrzTrimmed.fill(0)
    }
  )

  constructor(documentNumber: ByteArray, dateOfBirth: ByteArray, dateOfExpiry: ByteArray) {
    requireNotNull(documentNumber) { "Illegal document number" }
    require(dateOfBirth.size == 6) { "Illegal date : ${String(dateOfBirth, Charsets.UTF_8)}" }
    require(dateOfExpiry.size == 6) { "Illegal date : ${String(dateOfExpiry, Charsets.UTF_8)}" }
    this.documentNumber = MRZUtils.fixDocumentNumber(documentNumber).copyOf()
    this.dateOfBirth = dateOfBirth.copyOf()
    this.dateOfExpiry = dateOfExpiry.copyOf()
    try {
      accessKey = Utils.computeKeySeed(this.documentNumber, this.dateOfBirth, this.dateOfExpiry, "SHA-1", true)
    } catch (gse: GeneralSecurityException) {
      throw IllegalArgumentException("Unexpected exception", gse)
    }
  }

  /**
   * Returns the document number bytes
   *
   * @return the document number bytes
   */
  override fun getDocumentNumber(): ByteArray {
    return documentNumber
  }

  /**
   * Returns the date of birth bytes.
   *
   * @return a date in <i>yymmdd</i> format
   */
  override fun getDateOfBirth(): ByteArray {
    return dateOfBirth
  }

  /**
   * Returns the date of expiry bytes.
   *
   * @return a date in <i>yymmdd</i> format
   */
  override fun getDateOfExpiry(): ByteArray {
    return dateOfExpiry
  }

  /**
   * Returns a textual representation of this BAC key.
   *
   * @return a textual representation of this BAC key
   */
  override fun toString(): String {
    return String(documentNumber, Charsets.UTF_8) + ", " + String(dateOfBirth, Charsets.UTF_8) + ", " + String(dateOfExpiry, Charsets.UTF_8)
  }

  /**
   * Computes the hash code of this BAC key.
   * Document number, date of birth, and date of expiry (with year in <i>yy</i> precision) are taken into account.
   *
   * @return a hash code
   */
  override fun hashCode(): Int {
    var result = 5
    result = 61 * result + documentNumber.hashCode()
    result = 61 * result + dateOfBirth.hashCode()
    result = 61 * result + dateOfExpiry.hashCode()
    return result
  }

  /**
   * Tests equality of this BAC key with respect to another object.
   *
   * @param other another object
   *
   * @return whether this BAC key equals another object
   */
  override fun equals(other: Any?): Boolean {
    if (other == null) {
      return false
    }
    if (!other.javaClass.equals(this.javaClass)) {
      return false
    }
    if (other == this) {
      return true
    }
    val previous = other as BACKey
    return documentNumber.equals(previous.documentNumber) &&
            dateOfBirth.equals(previous.dateOfBirth) &&
            dateOfExpiry.equals(previous.dateOfExpiry)
  }


  /**
   * The algorithm of this key specification.
   *
   * @return constant &quot;BAC&quot;
   */
  override fun getAlgorithm(): String {
    return "BAC"
  }

  /**
   * Returns the encoded key (key seed) for use in key derivation.
   *
   * @return the encoded key
   */
  override fun getKey(): ByteArray {
      return accessKey
  }

  override fun wipe() {
    documentNumber.fill(0)
    dateOfBirth.fill(0)
    dateOfExpiry.fill(0)
    accessKey.fill(0)
  }
}
