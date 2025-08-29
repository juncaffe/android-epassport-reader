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
 * $Id: Hex.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard.util

import java.util.Locale

/**
 * Some static helper methods for dealing with hexadecimal notation.
 *
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 *
 * @version $Revision: 321 $
 */
object Hex {
    /**
     * Converts the byte `b` to capitalized hexadecimal text.
     * The result will have length 2 and only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param b the byte to convert.
     *
     * @return capitalized hexadecimal text representation of `b`.
     */
    @JvmStatic
    fun byteToHexString(b: Byte): String {
        val n = b.toInt() and 0x000000FF
        val result = (if (n < 0x00000010) "0" else "") + Integer.toHexString(n)
        return result.uppercase(Locale.getDefault())
    }

    /**
     * Converts a byte array to capitalized hexadecimal text.
     * The length of the resulting string will be twice the length of
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text The byte array to convert.
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    @JvmStatic
    fun bytesToHexString(text: ByteArray?): String {
        return bytesToHexString(text, 1000)
    }

    fun bytesToHexString(text: ByteArray?, numRow: Int): String {
        if (text == null) {
            return "NULL"
        }
        return bytesToHexString(text, 0, text.size, numRow)
    }

    /**
     * Converts a byte array to capitalized hexadecimal text.
     * The length of the resulting string will be twice the length of
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text The byte array to convert.
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    fun toHexString(text: ByteArray): String {
        return bytesToHexString(text, 0, text.size, 1000)
    }


    fun toHexString(text: ByteArray, numRow: Int): String {
        return bytesToHexString(text, 0, text.size, numRow)
    }

    /**
     * Converts part of a byte array to capitalized hexadecimal text.
     * Conversion starts at index `offset` until (excluding)
     * index `offset + length`.
     * The length of the resulting string will be twice the length
     * `text` and will only contain the characters '0', '1',
     * '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'.
     *
     * @param text the byte array to convert.
     * @param offset where to start.
     * @param length how many bytes to convert.
     * @param numRow number of bytes to be put one in one row of output
     *
     * @return capitalized hexadecimal text representation of
     * `text`.
     */
    fun bytesToHexString(text: ByteArray?, offset: Int, length: Int, numRow: Int): String {
        if (text == null) {
            return "NULL"
        }
        val result = StringBuilder()
        for (i in 0..<length) {
            if (i != 0 && i % numRow == 0) {
                result.append("\n")
            }
            result.append(byteToHexString(text[offset + i]))
            result.append(" ")
        }
        return result.toString()
    }

    fun bytesToHexString(text: ByteArray?, offset: Int, length: Int): String {
        return bytesToHexString(text, offset, length, 1000)
    }
}