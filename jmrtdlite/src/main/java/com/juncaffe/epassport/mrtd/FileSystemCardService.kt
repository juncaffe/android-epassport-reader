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
 * $Id: FileSystemCardService.java 1839 2020-08-27 06:28:31Z martijno $
 */

package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.smartcard.APDUListener
import com.juncaffe.epassport.smartcard.CardFileInputStream
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.CommandAPDU
import com.juncaffe.epassport.smartcard.ResponseAPDU

/**
 * A card service that acts as a (file identifier indexed) file system.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1839 $
 */
abstract class FileSystemCardService(service: CardService): CardService {

  lateinit var service: CardService

  init {
      this.service = service
  }

  /**
   * Returns an input stream to access the file indicated by the file identifier.
   *
   * @param fid the file identifier
   * @param maxBlockSize maximum block size to use for read binaries
   *
   * @return a stream to read from
   *
   * @throws CardServiceException on error creating the stream
   */
  @Throws(CardServiceException::class)
  abstract fun getInputStream(fid: PassportService.EF, maxBlockSize: Int): CardFileInputStream


  override fun isConnectionLost(e: Exception?): Boolean {
    return service.isConnectionLost(e)
  }

  override fun isDirectConnectionLost(e: Throwable?): Boolean {
    return service.isDirectConnectionLost(e)
  }

  override fun isISODepConnected(): Boolean {
    return service.isISODepConnected()
  }

  override fun addAPDUListener(l: APDUListener?) {
    return service.addAPDUListener(l)
  }

  override fun removeAPDUListener(l: APDUListener?) {
    return service.removeAPDUListener(l)
  }

  override fun open() {
    return service.open()
  }

  override fun isOpen(): Boolean {
    return service.isOpen()
  }

  override fun transmit(commandAPDU: CommandAPDU): ResponseAPDU? {
    return service.transmit(commandAPDU)
  }

  override fun isExtendedAPDULengthSupported(): Boolean {
    return service.isExtendedAPDULengthSupported()
  }
}
