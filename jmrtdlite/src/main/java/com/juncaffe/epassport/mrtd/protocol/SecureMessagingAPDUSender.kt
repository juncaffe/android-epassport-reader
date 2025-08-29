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
 * $Id: SecureMessagingAPDUSender.java 1841 2020-09-18 19:11:27Z martijno $
 */
package com.juncaffe.epassport.mrtd.protocol

import com.juncaffe.epassport.mrtd.WrappedAPDUEvent
import com.juncaffe.epassport.smartcard.APDUEvent
import com.juncaffe.epassport.smartcard.APDUListener
import com.juncaffe.epassport.smartcard.APDUWrapper
import com.juncaffe.epassport.smartcard.CardService
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.CommandAPDU
import com.juncaffe.epassport.smartcard.ISO7816
import com.juncaffe.epassport.smartcard.ResponseAPDU
import com.juncaffe.epassport.smartcard.util.Hex.bytesToHexString
import java.util.logging.Logger

/**
 * An APDU sender for tranceiving wrapped APDUs.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1841 $
 *
 * @since 0.7.0
 */
class SecureMessagingAPDUSender
/**
 * Creates an APDU sender for tranceiving wrapped APDUs.
 *
 * @param service the card service for tranceiving the APDUs
 */(private val service: CardService) {
    private var apduCount = 0

    /**
     * Transmits an APDU.
     *
     * @param wrapper the secure messaging wrapper
     * @param commandAPDU the APDU to send
     *
     * @return the APDU received from the PICC
     *
     * @throws CardServiceException if tranceiving failed
     */
    @Throws(CardServiceException::class)
    fun transmit(wrapper: APDUWrapper?, commandAPDU: CommandAPDU): ResponseAPDU {
        var commandAPDU = commandAPDU
        val plainCapdu = commandAPDU
        if (wrapper != null) {
            commandAPDU = wrapper.wrap(commandAPDU)
        }
        var responseAPDU = service.transmit(commandAPDU)
        val rawRapdu = responseAPDU
        val sw = responseAPDU!!.sW
        if (wrapper == null) {
            notifyExchangedAPDU(APDUEvent(this, "PLAIN", ++apduCount, commandAPDU, responseAPDU))
        } else {
            try {
                if ((sw and ISO7816.SW_WRONG_LENGTH.toInt()) == ISO7816.SW_WRONG_LENGTH.toInt()) {
                    return responseAPDU
                }
                if (responseAPDU.bytes!!.size <= 2) {
                    throw CardServiceException("Exception during transmission of wrapped APDU C=" + bytesToHexString(plainCapdu.bytes), sw)
                }

                responseAPDU = wrapper.unwrap(responseAPDU)
            } catch (cse: CardServiceException) {
                throw cse
            } catch (e: Exception) {
                throw CardServiceException("Exception during transmission of wrapped APDU, C=" + bytesToHexString(plainCapdu.bytes), e, sw)
            } finally {
                notifyExchangedAPDU(WrappedAPDUEvent(this, wrapper.type, ++apduCount, plainCapdu, responseAPDU, commandAPDU, rawRapdu))
            }
        }

        return responseAPDU
    }

    /**
     * Adds a listener.
     *
     * @param l the listener to add
     */
    fun addAPDUListener(l: APDUListener?) {
        service.addAPDUListener(l)
    }

    /**
     * Removes a listener.
     * If the specified listener is not present, this method has no effect.
     *
     * @param l the listener to remove
     */
    fun removeAPDUListener(l: APDUListener?) {
        service.removeAPDUListener(l)
    }

    /**
     * Notifies listeners about APDU event.
     *
     * @param event the APDU event
     */
    protected fun notifyExchangedAPDU(event: APDUEvent?) {
        val apduListeners = service.getAPDUListeners()
        if (apduListeners.isEmpty()) {
            return
        }

        for (listener in apduListeners) {
            listener.exchangedAPDU(event)
        }
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger("org.jmrtd.protocol")
    }
}
