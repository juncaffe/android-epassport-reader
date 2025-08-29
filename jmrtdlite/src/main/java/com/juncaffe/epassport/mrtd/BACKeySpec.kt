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
 * $Id: BACKeySpec.java 1786 2018-07-08 21:06:32Z martijno $
 */

package com.juncaffe.epassport.mrtd

/**
 * A BAC key.
 *
 * @author The JMRTD team
 *
 * @version $Revision: 1786 $
 */
interface BACKeySpec: AccessKeySpec {

  /**
   * Returns the document number. This does not include a check digit.
   * The result may include filler characters to make sure the resulting
   * length is at least 9.
   *
   * @return the document number
   */
  fun getDocumentNumber(): ByteArray

  /**
   * Returns the date of birth bytes.
   *
   * @return a <i>yymmdd</i> bytes
   */
  fun getDateOfBirth(): ByteArray

  /**
   * Returns the date of expiry bytes.
   *
   * @return a <i>yymmdd</i> bytes
   */
  fun getDateOfExpiry(): ByteArray
}
