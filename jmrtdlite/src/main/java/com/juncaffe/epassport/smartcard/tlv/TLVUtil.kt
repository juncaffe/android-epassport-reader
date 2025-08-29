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
 * $Id: TLVUtil.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard.tlv

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import java.io.ByteArrayInputStream
import java.io.IOException
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.experimental.or
import kotlin.math.ln

/* FIXME: make class package visible only. */ /**
 * Static helper utilities for the TLV streams and states.
 *
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 *
 * @version $Revision: 321 $
 */
object TLVUtil {
    private val LOGGER: Logger = Logger.getLogger("org.jmrtd.smartcards.tlv")

    @JvmStatic
    fun isPrimitive(tag: Int): Boolean {
        var i = 3
        while (i >= 0) {
            val mask = (0xFF shl (8 * i))
            if ((tag and mask) != 0x00) {
                break
            }
            i--
        }
        val msByte = (((tag and (0xFF shl (8 * i))) shr (8 * i)) and 0xFF)
        return ((msByte and 0x20) == 0x00)
    }

    @JvmStatic
    fun getTagLength(tag: Int): Int {
        return getTagAsBytes(tag).size
    }

    @JvmStatic
    fun getLengthLength(length: Int): Int {
        return getLengthAsBytes(length).size
    }

    /**
     * The tag bytes of this object.
     *
     * @param tag the tag
     *
     * @return the tag bytes of this object.
     */
    @JvmStatic
    fun getTagAsBytes(tag: Int): ByteArray {
        return SecureByteArrayOutputStream(true).use {
            val byteCount = (ln(tag.toDouble()) / ln(256.0)).toInt() + 1
            for (i in 0..<byteCount) {
                val pos = 8 * (byteCount - i - 1)
                it.write((tag and (0xFF shl pos)) shr pos)
            }
            val tagBytes = it.toByteArray()
            when (getTagClass(tag)) {
                // ASN1Constants.APPLICATION_CLASS
                1 -> tagBytes[0] = tagBytes[0] or 0x40.toByte()
                // ASN1Constants.CONTEXT_SPECIFIC_CLASS
                2 -> tagBytes[0] = tagBytes[0] or 0x80.toByte()
                // ASN1Constants.PRIVATE_CLASS
                3 -> tagBytes[0] = tagBytes[0] or 0xC0.toByte()
                else -> {}
            }
            if (!isPrimitive(tag)) {
                tagBytes[0] = tagBytes[0] or 0x20.toByte()
            }
            tagBytes
        }
    }

    /**
     * The length bytes of this object.
     *
     * @param length the length
     *
     * @return length of encoded value as bytes
     */
    @JvmStatic
    fun getLengthAsBytes(length: Int): ByteArray {
        val out = SecureByteArrayOutputStream(true)
        if (length < 0x80) {
            /* short form */
            out.write(length)
        } else {
            val byteCount = log(length, 256)
            out.write(0x80 or byteCount)
            for (i in 0..<byteCount) {
                val pos = 8 * (byteCount - i - 1)
                out.write((length and (0xFF shl pos)) shr pos)
            }
        }
        return out.toByteArray()
    }

    /**
     * TLV encodes an encoded data object with a tag.
     *
     * @param tag the tag
     * @param data the data to encode
     *
     * @return the TLV encoded data
     */
    @JvmStatic
    fun wrapDO(tag: Int, data: ByteArray): ByteArray {
        requireNotNull(data) { "Data to wrap is null" }

        return SecureByteArrayOutputStream(true).use {
            try {
                val tlvOutputStream = TLVOutputStream(it)
                tlvOutputStream.writeTag(tag)
                tlvOutputStream.writeValue(data)
                tlvOutputStream.flush()
                tlvOutputStream.close()
                it.toByteArray()
            } catch (ioe: IOException) {
                // Never happens.
                throw IllegalStateException("Error writing stream", ioe)
            }
        }
    }

    /**
     * TLV decodes tagged TLV data object.
     *
     * @param expectedTag the tag to expect, an `IllegalArgumentException` will be throws if a different tag is read
     * @param wrappedData the encoded data
     *
     * @return the decoded data
     */
    @JvmStatic
    fun unwrapDO(expectedTag: Int, wrappedData: ByteArray): ByteArray {
        require(!(wrappedData.size < 2)) { "Wrapped data is null or length < 2" }

        val byteArrayInputStream = ByteArrayInputStream(wrappedData)
        val tlvInputStream = TLVInputStream(byteArrayInputStream)

        try {
            val actualTag = tlvInputStream.readTag()
            require(actualTag == expectedTag) { "Expected tag " + Integer.toHexString(expectedTag) + ", found tag " + Integer.toHexString(actualTag) }

            val length = tlvInputStream.readLength()
            val value = tlvInputStream.readValue()
            val result = ByteArray(length)
            System.arraycopy(value, 0, result, 0, length)
            value.fill(0)
            return result
        } catch (ioe: IOException) {
            // Never happens.
            throw IllegalStateException("Error reading from stream", ioe)
        } finally {
            try {
                tlvInputStream.close()
                //        byteArrayInputStream.close();
            } catch (ioe: IOException) {
                LOGGER.log(Level.FINE, "Error closing stream", ioe)
            }
        }
    }

    fun getTagClass(tag: Int): Int {
        var i = 3
        while (i >= 0) {
            val mask = (0xFF shl (8 * i))
            if ((tag and mask) != 0x00) {
                break
            }
            i--
        }
        val msByte = (((tag and (0xFF shl (8 * i))) shr (8 * i)) and 0xFF)
        when (msByte and 0xC0) {
            0x00 -> return 0 // ASN1Constants.UNIVERSAL_CLASS
            0x40 -> return 1 // ASN1Constants.APPLICATION_CLASS
            0x80 -> return 2 // ASN1Constants.CONTEXT_SPECIFIC_CLASS
            0xC0 -> return 3 // ASN1Constants.PRIVATE_CLASS
            else -> return 3 //ASN1Constants.PRIVATE_CLASS
        }
    }

    private fun log(n: Int, base: Int): Int {
        var n = n
        var result = 0
        while (n > 0) {
            n = n / base
            result++
        }
        return result
    }
}