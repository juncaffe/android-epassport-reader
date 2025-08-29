/*
 * Copyright (c) 2005, 2006, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package com.juncaffe.epassport.smartcard

import java.io.IOException
import java.io.ObjectInputStream
import java.io.Serializable
import java.nio.ByteBuffer

/**
 * A command APDU following the structure defined in ISO/IEC 7816-4.
 * It consists of a four byte header and a conditional body of variable length.
 * This class does not attempt to verify that the APDU encodes a semantically
 * valid command.
 *
 *
 * Note that when the expected length of the response APDU is specified
 * in the [constructors][.CommandAPDU],
 * the actual length (Ne) must be specified, not its
 * encoded form (Le). Similarly, [.getNe] returns the actual
 * value Ne. In other words, a value of 0 means "no data in the response APDU"
 * rather than "maximum length."
 *
 *
 * This class supports both the short and extended forms of length
 * encoding for Ne and Nc. However, note that not all terminals and Smart Cards
 * are capable of accepting APDUs that use the extended form.
 *
 *
 * For the header bytes CLA, INS, P1, and P2 the Java type `int`
 * is used to represent the 8 bit unsigned values. In the constructors, only
 * the 8 lowest bits of the `int` value specified by the application
 * are significant. The accessor methods always return the byte as an unsigned
 * value between 0 and 255.
 *
 *
 * Instances of this class are immutable. Where data is passed in or out
 * via byte arrays, defensive cloning is performed.
 *
 * @see ResponseAPDU
 *
 * @see CardChannel.transmit CardChannel.transmit
 *
 *
 * @since   1.6
 * @author  Andreas Sterbenz
 * @author  JSR 268 Expert Group
 */
class CommandAPDU : Serializable {
    /** @serial
     */
    private var apdu: ByteArray = byteArrayOf()

    /**
     * Returns the number of data bytes in the command body (Nc) or 0 if this
     * APDU has no body. This call is equivalent to
     * `getData().length`.
     *
     * @return the number of data bytes in the command body or 0 if this APDU
     * has no body.
     */
    // value of nc
    @Transient
    var nc: Int = 0

    /**
     * Returns the maximum number of expected data bytes in a response
     * APDU (Ne).
     *
     * @return the maximum number of expected data bytes in a response APDU.
     */
    // value of ne
    @Transient
    var ne: Int = 0

    // index of start of data within the apdu array
    @Transient
    private var dataOffset = 0

    /**
     * Constructs a CommandAPDU from a byte array containing the complete
     * APDU contents (header and body).
     *
     *
     * Note that the apdu bytes are copied to protect against
     * subsequent modification.
     *
     * @param apdu the complete command APDU
     *
     * @throws NullPointerException if apdu is null
     * @throws IllegalArgumentException if apdu does not contain a valid
     * command APDU
     */
    constructor(apdu: ByteArray) {
        this.apdu = apdu.clone()
        parse()
    }


    /**
     * Creates a CommandAPDU from the ByteBuffer containing the complete APDU
     * contents (header and body).
     * The buffer's `position` must be set to the start of the APDU,
     * its `limit` to the end of the APDU. Upon return, the buffer's
     * `position` is equal to its limit; its limit remains unchanged.
     *
     *
     * Note that the data in the ByteBuffer is copied to protect against
     * subsequent modification.
     *
     * @param apdu the ByteBuffer containing the complete APDU
     *
     * @throws NullPointerException if apdu is null
     * @throws IllegalArgumentException if apdu does not contain a valid
     * command APDU
     */
    constructor(apdu: ByteBuffer) {
        this.apdu = ByteArray(apdu.remaining())
        apdu.get(this.apdu)
        parse()
    }

    /**
     * Constructs a CommandAPDU from a byte array containing the complete
     * APDU contents (header and body). The APDU starts at the index
     * `apduOffset` in the byte array and is `apduLength`
     * bytes long.
     *
     *
     * Note that the apdu bytes are copied to protect against
     * subsequent modification.
     *
     * @param apdu the complete command APDU
     * @param apduOffset the offset in the byte array at which the apdu
     * data begins
     * @param apduLength the length of the APDU
     *
     * @throws NullPointerException if apdu is null
     * @throws IllegalArgumentException if apduOffset or apduLength are
     * negative or if apduOffset + apduLength are greater than apdu.length,
     * or if the specified bytes are not a valid APDU
     */
    constructor(apdu: ByteArray, apduOffset: Int, apduLength: Int) {
        checkArrayBounds(apdu, apduOffset, apduLength)
        this.apdu = ByteArray(apduLength)
        System.arraycopy(apdu, apduOffset, this.apdu, 0, apduLength)
        parse()
    }

    private fun checkArrayBounds(b: ByteArray?, ofs: Int, len: Int) {
        require(!((ofs < 0) || (len < 0))) { "Offset and length must not be negative" }
        if (b == null) {
            require(!((ofs != 0) && (len != 0))) { "offset and length must be 0 if array is null" }
        } else {
            require(ofs <= b.size - len) { "Offset plus length exceed array size" }
        }
    }

    /**
     * Command APDU encoding options:
     *
     * case 1:  |CLA|INS|P1 |P2 |                                 len = 4
     * case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
     * case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
     * case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
     * case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
     * case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
     * case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len =10..65544
     *
     * LE, LE1, LE2 may be 0x00.
     * LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00
     */
    private fun parse() {
        require(apdu.size >= 4) { "apdu must be at least 4 bytes long" }
        if (apdu.size == 4) {
            // case 1
            return
        }
        val l1 = apdu[4].toInt() and 0xff
        if (apdu.size == 5) {
            // case 2s
            this.ne = if (l1 == 0) 256 else l1
            return
        }
        if (l1 != 0) {
            if (apdu.size == 4 + 1 + l1) {
                // case 3s
                this.nc = l1
                this.dataOffset = 5
                return
            } else if (apdu.size == 4 + 2 + l1) {
                // case 4s
                this.nc = l1
                this.dataOffset = 5
                val l2 = apdu[apdu.size - 1].toInt() and 0xff
                this.ne = if (l2 == 0) 256 else l2
                return
            } else {
                throw IllegalArgumentException("Invalid APDU: length=" + apdu.size + ", b1=" + l1)
            }
        }
        require(apdu.size >= 7) { "Invalid APDU: length=" + apdu.size + ", b1=" + l1 }
        val l2 = ((apdu[5].toInt() and 0xff) shl 8) or (apdu[6].toInt() and 0xff)
        if (apdu.size == 7) {
            // case 2e
            this.ne = if (l2 == 0) 65536 else l2
            return
        }
        require(l2 != 0) {
            ("Invalid APDU: length="
                    + apdu.size + ", b1=" + l1 + ", b2||b3=" + l2)
        }
        if (apdu.size == 4 + 3 + l2) {
            // case 3e
            this.nc = l2
            this.dataOffset = 7
            return
        } else if (apdu.size == 4 + 5 + l2) {
            // case 4e
            this.nc = l2
            this.dataOffset = 7
            val leOfs = apdu.size - 2
            val l3 = ((apdu[leOfs].toInt() and 0xff) shl 8) or (apdu[leOfs + 1].toInt() and 0xff)
            this.ne = if (l3 == 0) 65536 else l3
        } else {
            throw IllegalArgumentException(
                ("Invalid APDU: length="
                        + apdu.size + ", b1=" + l1 + ", b2||b3=" + l2)
            )
        }
    }

    /**
     * Constructs a CommandAPDU from the four header bytes and the expected
     * response data length. This is case 2 in ISO 7816, empty command data
     * field with Ne specified. If Ne is 0, the APDU is encoded as ISO 7816
     * case 1.
     *
     * @param cla the class byte CLA
     * @param ins the instruction byte INS
     * @param p1 the parameter byte P1
     * @param p2 the parameter byte P2
     * @param ne the maximum number of expected data bytes in a response APDU
     *
     * @throws IllegalArgumentException if ne is negative or greater than
     * 65536
     */
    constructor(cla: Int, ins: Int, p1: Int, p2: Int, ne: Int): this(cla, ins, p1, p2, null, 0, 0, ne)

    /**
     * Constructs a CommandAPDU from the four header bytes, command data,
     * and expected response data length. This is case 4 in ISO 7816,
     * command data and Le present. The value Nc is taken as
     * <code>dataLength</code>.
     * If Ne or Nc
     * are zero, the APDU is encoded as case 1, 2, or 3 per ISO 7816.
     *
     * <p>Note that the data bytes are copied to protect against
     * subsequent modification.
     *
     * @param cla the class byte CLA
     * @param ins the instruction byte INS
     * @param p1 the parameter byte P1
     * @param p2 the parameter byte P2
     * @param data the byte array containing the data bytes of the command body
     * @param dataOffset the offset in the byte array at which the data
     *   bytes of the command body begin
     * @param dataLength the number of the data bytes in the command body
     * @param ne the maximum number of expected data bytes in a response APDU
     *
     * @throws NullPointerException if data is null and dataLength is not 0
     * @throws IllegalArgumentException if dataOffset or dataLength are
     *   negative or if dataOffset + dataLength are greater than data.length,
     *   or if ne is negative or greater than 65536,
     *   or if dataLength is greater than 65535
     */
    constructor(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray): this(cla, ins, p1, p2, data, 0, arrayLength(data), 0)

    /**
     * Constructs a CommandAPDU from the four header bytes, command data,
     * and expected response data length. This is case 4 in ISO 7816,
     * command data and Ne present. The value Nc is taken as data.length
     * if <code>data</code> is non-null and as 0 otherwise. If Ne or Nc
     * are zero, the APDU is encoded as case 1, 2, or 3 per ISO 7816.
     *
     * <p>Note that the data bytes are copied to protect against
     * subsequent modification.
     *
     * @param cla the class byte CLA
     * @param ins the instruction byte INS
     * @param p1 the parameter byte P1
     * @param p2 the parameter byte P2
     * @param data the byte array containing the data bytes of the command body
     * @param ne the maximum number of expected data bytes in a response APDU
     *
     * @throws IllegalArgumentException if data.length is greater than 65535
     *   or if ne is negative or greater than 65536
     */
    constructor(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray, ne: Int = 0): this(cla, ins, p1, p2, data, 0, arrayLength(data), ne)

    /**
     * Constructs a CommandAPDU from the four header bytes and command data.
     * This is case 3 in ISO 7816, command data present and Ne absent. The
     * value Nc is taken as dataLength. If `dataLength`
     * is 0, the APDU is encoded as ISO 7816 case 1.
     *
     *
     * Note that the data bytes are copied to protect against
     * subsequent modification.
     *
     * @param cla the class byte CLA
     * @param ins the instruction byte INS
     * @param p1 the parameter byte P1
     * @param p2 the parameter byte P2
     * @param data the byte array containing the data bytes of the command body
     * @param dataOffset the offset in the byte array at which the data
     * bytes of the command body begin
     * @param dataLength the number of the data bytes in the command body
     *
     * @throws NullPointerException if data is null and dataLength is not 0
     * @throws IllegalArgumentException if dataOffset or dataLength are
     * negative or if dataOffset + dataLength are greater than data.length
     * or if dataLength is greater than 65535
     */
    constructor(cla: Int, ins: Int, p1: Int, p2: Int, data: ByteArray? = null, dataOffset: Int = 0, dataLength: Int = 0, ne: Int? = 0) {
        checkArrayBounds(data, dataOffset, dataLength)
        require(dataLength <= 65535) { "dataLength is too large" }
        require(ne != null && ne >= 0) { "ne must not be negative" }
        require(ne <= 65536) { "ne is too large" }
        this.ne = ne
        this.nc = dataLength
        if (dataLength == 0) {
            if (ne == 0) {
                // case 1
                this.apdu = ByteArray(4)
                setHeader(cla, ins, p1, p2)
            } else {
                // case 2s or 2e
                if (ne <= 256) {
                    // case 2s
                    // 256 is encoded as 0x00
                    val len = if (ne != 256) ne.toByte() else 0
                    this.apdu = ByteArray(5)
                    setHeader(cla, ins, p1, p2)
                    this.apdu[4] = len
                } else {
                    // case 2e
                    val l1: Byte
                    val l2: Byte
                    // 65536 is encoded as 0x00 0x00
                    if (ne == 65536) {
                        l1 = 0
                        l2 = 0
                    } else {
                        l1 = (ne shr 8).toByte()
                        l2 = ne.toByte()
                    }
                    this.apdu = ByteArray(7)
                    setHeader(cla, ins, p1, p2)
                    this.apdu[5] = l1
                    this.apdu[6] = l2
                }
            }
        } else {
            if (ne == 0) {
                // case 3s or 3e
                if (dataLength <= 255) {
                    // case 3s
                    apdu = ByteArray(4 + 1 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = dataLength.toByte()
                    this.dataOffset = 5
                    System.arraycopy(data, dataOffset, apdu, 5, dataLength)
                } else {
                    // case 3e
                    apdu = ByteArray(4 + 3 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = 0
                    apdu[5] = (dataLength shr 8).toByte()
                    apdu[6] = dataLength.toByte()
                    this.dataOffset = 7
                    System.arraycopy(data, dataOffset, apdu, 7, dataLength)
                }
            } else {
                // case 4s or 4e
                if ((dataLength <= 255) && (ne <= 256)) {
                    // case 4s
                    apdu = ByteArray(4 + 2 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = dataLength.toByte()
                    this.dataOffset = 5
                    System.arraycopy(data, dataOffset, apdu, 5, dataLength)
                    apdu[apdu.size - 1] = if (ne != 256) ne.toByte() else 0
                } else {
                    // case 4e
                    apdu = ByteArray(4 + 5 + dataLength)
                    setHeader(cla, ins, p1, p2)
                    apdu[4] = 0
                    apdu[5] = (dataLength shr 8).toByte()
                    apdu[6] = dataLength.toByte()
                    this.dataOffset = 7
                    System.arraycopy(data, dataOffset, apdu, 7, dataLength)
                    if (ne != 65536) {
                        val leOfs = apdu.size - 2
                        apdu[leOfs] = (ne shr 8).toByte()
                        apdu[leOfs + 1] = ne.toByte()
                    } // else le == 65536: no need to fill in, encoded as 0
                }
            }
        }
    }

    private fun setHeader(cla: Int, ins: Int, p1: Int, p2: Int) {
        apdu[0] = cla.toByte()
        apdu[1] = ins.toByte()
        apdu[2] = p1.toByte()
        apdu[3] = p2.toByte()
    }

    /**
     * Returns the value of the class byte CLA.
     *
     * @return the value of the class byte CLA.
     */
    val cLA: Int get() = apdu[0].toInt() and 0xff

    /**
     * Returns the value of the instruction byte INS.
     *
     * @return the value of the instruction byte INS.
     */
    val iNS: Int get() = apdu[1].toInt() and 0xff

    /**
     * Returns the value of the parameter byte P1.
     *
     * @return the value of the parameter byte P1.
     */
    val p1: Int get() = apdu[2].toInt() and 0xff

    /**
     * Returns the value of the parameter byte P2.
     *
     * @return the value of the parameter byte P2.
     */
    val p2: Int get() = apdu[3].toInt() and 0xff

    /**
     * Returns a copy of the data bytes in the command body. If this APDU as
     * no body, this method returns a byte array with length zero.
     *
     * @return a copy of the data bytes in the command body or the empty
     * byte array if this APDU has no body.
     */
    val data: ByteArray get() {
            val data = ByteArray(nc)
            System.arraycopy(apdu, dataOffset, data, 0, nc)
            return data
        }

    /**
     * Returns a copy of the bytes in this APDU.
     *
     * @return a copy of the bytes in this APDU.
     */
    val bytes: ByteArray get() = apdu.clone()

    /**
     * Returns a string representation of this command APDU.
     *
     * @return a String representation of this command APDU.
     */
    override fun toString(): String {
        return "CommmandAPDU: " + apdu.size + " bytes, nc=" + nc + ", ne=" + ne
    }

    /**
     * Compares the specified object with this command APDU for equality.
     * Returns true if the given object is also a CommandAPDU and its bytes are
     * identical to the bytes in this CommandAPDU.
     *
     * @param obj the object to be compared for equality with this command APDU
     * @return true if the specified object is equal to this command APDU
     */
    override fun equals(obj: Any?): Boolean {
        if (this === obj) {
            return true
        }
        if (obj is CommandAPDU == false) {
            return false
        }
        val other = obj
        return this.apdu.contentEquals(other.apdu)
    }

    /**
     * Returns the hash code value for this command APDU.
     *
     * @return the hash code value for this command APDU.
     */
    override fun hashCode(): Int {
        return apdu.contentHashCode()
    }

    @Throws(IOException::class, ClassNotFoundException::class)
    private fun readObject(`in`: ObjectInputStream) {
        apdu = `in`.readUnshared() as ByteArray
        // initialize transient fields
        parse()
    }

    companion object {
        private const val serialVersionUID = 398698301286670877L

        @Suppress("unused")
        private const val MAX_APDU_SIZE = 65544

        private fun arrayLength(b: ByteArray?): Int {
            return if (b != null) b.size else 0
        }
    }
}