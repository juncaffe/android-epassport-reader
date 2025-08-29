/*
* This file is part of the SCUBA smart card framework.
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
* Copyright (C) 2009 - 2023  The SCUBA team.
*
* $Id: CardService.java 321 2023-03-09 15:35:49Z martijno $
*/
package com.juncaffe.epassport.smartcard

interface CardService {
    fun getAPDUListeners(): MutableCollection<APDUListener>

    /**
     * Notifies listeners about APDU event.
     *
     * @param event the APDU event
     */
    fun notifyExchangedAPDU(event: APDUEvent?)

    /**
     * Adds a listener.
     *
     * @param l the listener to add
     */
    fun addAPDUListener(l: APDUListener?)

    /**
     * Removes a listener.
     * If the specified listener is not present, this method has no effect.
     *
     * @param l the listener to remove
     */
    fun removeAPDUListener(l: APDUListener?)

    /**
     * ISO-DEP (ISO 14443-4) 기반의 스마트카드 연결 시도
     *
     * @throws CardServiceException on error
     */
    @Throws(CardServiceException::class)
    fun open()

    /**
     * 스마트카드 세션 연결 여부
     *
     * @return
     */
    fun isOpen(): Boolean

    /**
     * 스마트카드에 APDU 를 보냄
     *
     * @param commandAPDU 전송할 APDU 명령
     *
     * @return 카드의 응답
     */
    @Throws(CardServiceException::class)
    fun transmit(commandAPDU: CommandAPDU): ResponseAPDU?

    fun isExtendedAPDULengthSupported(): Boolean

    /**
     * 스마트카드 연결 종료
     */
    fun close()

    fun isConnectionLost(e: Exception?): Boolean

    fun isDirectConnectionLost(e: Throwable?): Boolean

    fun isISODepConnected(): Boolean
}