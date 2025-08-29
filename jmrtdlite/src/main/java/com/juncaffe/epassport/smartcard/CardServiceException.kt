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
 * $Id: CardServiceException.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard

import java.util.Locale

/**
 * CardServiceExceptions are used to signal error Response APDUs , ie responses
 * different from 0x9000, but also low level errors.
 *
 * @author erikpoll
 *
 * @version $Revision: 321 $
 */
open class CardServiceException : Exception {
    /**
     * Gets the status word.
     *
     * @return the status word that caused this exception
     */
    /**
     * The status word that caused this exception, or -1 if not known or recorded.
     */
    val sW: Int

    /**
     * Creates a CardServiceException with a status word.
     *
     * @param msg a message
     * @param this.sW the status word that caused this CardServiceException
     */
    /**
     * Creates a CardServiceException.
     *
     * @param msg a message
     */
    @JvmOverloads
    constructor(msg: String?, sw: Int = SW_NONE) : super(msg) {
        this.sW = sw
    }

    /**
     * Creates an exception while indicating the cause.
     *
     * @param msg a message
     * @param cause the cause
     * @param this.sW the status word that caused this CardServiceException
     */
    /**
     * Creates an exception while indicating the cause.
     *
     * @param msg a message
     * @param cause the cause
     */
    @JvmOverloads
    constructor(msg: String?, cause: Throwable?, sw: Int = getSW(cause)) : super(msg, cause) {
        this.sW = sw
    }

    override val message: String?
        /**
         * Gets the message.
         *
         * @return the message
         */
        get() {
            if (this.sW == SW_NONE) {
                return super.message
            } else {
                return super.message + " (SW = 0x" + Integer.toHexString(this.sW).uppercase(Locale.getDefault()) + ": " + statusWordToString(
                    sW.toShort()
                ) + ")"
            }
        }

    companion object {
        private const val serialVersionUID = 4489156194716970879L

        val SW_NONE: Int = -1

        private fun getSW(cause: Throwable?): Int {
            if (cause is CardServiceException) {
                return cause.sW
            }

            return SW_NONE
        }

        private fun statusWordToString(sw: Short): String {
            when (sw) {
                ISO7816.SW_END_OF_FILE -> return "END OF FILE"
                ISO7816.SW_LESS_DATA_RESPONDED_THAN_REQUESTED -> return "LESS DATA RESPONDED THAN REQUESTED"
                ISO7816.SW_WRONG_LENGTH -> return "WRONG LENGTH"
                ISO7816.SW_LOGICAL_CHANNEL_NOT_SUPPORTED -> return "LOGICAL CHANNEL NOT SUPPORTED"
                ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED -> return "SECURE MESSAGING NOT SUPPORTED"
                ISO7816.SW_LAST_COMMAND_EXPECTED -> return "LAST COMMAND EXPECTED"
                ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED -> return "SECURITY STATUS NOT SATISFIED"
                ISO7816.SW_FILE_INVALID -> return "FILE INVALID"
                ISO7816.SW_DATA_INVALID -> return "DATA INVALID"
                ISO7816.SW_CONDITIONS_NOT_SATISFIED -> return "CONDITIONS NOT SATISFIED"
                ISO7816.SW_COMMAND_NOT_ALLOWED -> return "COMMAND NOT ALLOWED"
                ISO7816.SW_EXPECTED_SM_DATA_OBJECTS_MISSING -> return "EXPECTED SM DATA OBJECTS MISSING"
                ISO7816.SW_SM_DATA_OBJECTS_INCORRECT -> return "SM DATA OBJECTS INCORRECT"
                ISO7816.SW_APPLET_SELECT_FAILED -> return "APPLET SELECT FAILED"
                ISO7816.SW_KEY_USAGE_ERROR -> return "KEY USAGE ERROR"
                ISO7816.SW_WRONG_DATA ->         /* case ISO7816.SW_FILEHEADER_INCONSISTENT: */
                    return "WRONG DATA or FILEHEADER INCONSISTENT"

                ISO7816.SW_FUNC_NOT_SUPPORTED -> return "FUNC NOT SUPPORTED"
                ISO7816.SW_FILE_NOT_FOUND -> return "FILE NOT FOUND"
                ISO7816.SW_RECORD_NOT_FOUND -> return "RECORD NOT FOUND"
                ISO7816.SW_OUT_OF_MEMORY ->         /* case ISO7816.SW_FILE_FULL: */
                    return "OUT OF MEMORY or FILE FULL"

                ISO7816.SW_INCORRECT_P1P2 -> return "INCORRECT P1P2"
                ISO7816.SW_KEY_NOT_FOUND -> return "KEY NOT FOUND"
                ISO7816.SW_WRONG_P1P2 -> return "WRONG P1P2"
                ISO7816.SW_INS_NOT_SUPPORTED -> return "INS NOT SUPPORTED"
                ISO7816.SW_CLA_NOT_SUPPORTED -> return "CLA NOT SUPPORTED"
                ISO7816.SW_UNKNOWN -> return "UNKNOWN"
                ISO7816.SW_CARD_TERMINATED -> return "CARD TERMINATED"
                ISO7816.SW_NO_ERROR -> return "NO ERROR"
                else -> {
                    if ((sw.toInt() and 0xFF00) == ISO7816.SW_BYTES_REMAINING_00.toInt()) {
                        return "BYTES REMAINING " + (sw.toInt() and 0xFF).toString()
                    }

                    if ((sw.toInt() and 0xFF00) == ISO7816.SW_CORRECT_LENGTH_00.toInt()) {
                        return "CORRECT LENGTH " + (sw.toInt() and 0xFF).toString()
                    }

                    if ((sw.toInt() and 0xFFF0) == ISO7816.SW_NON_VOLATILE_MEMORY_CHANGED_COUNTER_0.toInt()) {
                        return "NON VOLATILE MEMORY CHANGED COUNT " + (sw.toInt() and 0xF).toString()
                    }

                    return "Unknown"
                }
            }
        }
    }
}