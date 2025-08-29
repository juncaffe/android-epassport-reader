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
 * $Id: TLVOutputState.java 321 2023-03-09 15:35:49Z martijno $
 */

package com.juncaffe.epassport.smartcard.tlv

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.smartcard.util.Hex
import java.io.IOException
import java.util.ArrayDeque
import java.util.Deque
import java.util.logging.Level
import java.util.logging.Logger

/**
 * State to keep track of where we are in a TLV stream.
 * This variant also stores values that were encountered, to be used in
 * [TLVOutputStream].
 *
 * @author Martijn Oostdijk
 * @version $Revision: 321 $
 */
class TLVOutputState {

    companion object {
        private val LOGGER: Logger = Logger.getLogger("net.sf.scuba.tlv")
    }

    /** Encoded the tags, lengths, and (partial) values. */
    private var state: Deque<TLVStruct>

    /*
     * Encoded position, only one can be true.
     *
     * TFF: ^TLVVVVVV
     * FTF: T^LVVVVVV
     * FFT: TL^VVVVVV
     * FFT: TLVVVV^VV
     * TFF: ^
     */
    @JvmField
    var isAtStartOfTag: Boolean
    @JvmField
    var isAtStartOfLength: Boolean
    private var isReadingValue: Boolean

    constructor() : this(ArrayDeque(), true, false, false)

    constructor(original: TLVOutputState) : this(
        original.getDeepCopyOfState(),
        original.isAtStartOfTag,
        original.isAtStartOfLength,
        original.isReadingValue
    )

    private constructor(
        state: Deque<TLVStruct>,
        isAtStartOfTag: Boolean,
        isAtStartOfLength: Boolean,
        isReadingValue: Boolean
    ) {
        this.state = state
        this.isAtStartOfTag = isAtStartOfTag
        this.isAtStartOfLength = isAtStartOfLength
        this.isReadingValue = isReadingValue
    }

    fun isAtStartOfTag(): Boolean = isAtStartOfTag
    fun isAtStartOfLength(): Boolean = isAtStartOfLength
    fun isProcessingValue(): Boolean = isReadingValue

    fun getTag(): Int {
        if (state.isEmpty()) throw IllegalStateException("Tag not yet read.")
        val currentObject = state.peek()
        return currentObject.tag
    }

    fun getLength(): Int {
        if (state.isEmpty()) throw IllegalStateException("Length not yet known.")
        val currentObject = state.peek()
        val length = currentObject.length
        if (length < 0) throw IllegalStateException("Length not yet known.")
        return length
    }

    fun getValueBytesProcessed(): Int {
        val currentObject = state.peek()
        return currentObject.getValueBytesProcessed()
    }

    fun getValueBytesLeft(): Int {
        if (state.isEmpty()) throw IllegalStateException("Length of value is unknown.")
        val currentObject = state.peek()
        val currentLength = currentObject.length
        val valueBytesRead = currentObject.getValueBytesProcessed()
        return currentLength - valueBytesRead
    }

    fun setTagProcessed(tag: Int) {
        // Length is set to MAX INT, we will update it when caller calls our setLengthProcessed.
        val obj = TLVStruct(tag)
        if (!state.isEmpty()) {
            val parent = state.peek()
            val tagBytes = TLVUtil.getTagAsBytes(tag)
            parent.secureWrite(tagBytes, 0, tagBytes.size)
        }
        state.push(obj)
        isAtStartOfTag = false
        isAtStartOfLength = true
        isReadingValue = false
    }

    /** We've passed the length in the stream, but we don't know what it is yet... */
    fun setDummyLengthProcessed() {
        isAtStartOfTag = false
        isAtStartOfLength = false
        isReadingValue = true
        // NOTE: doesn't call setLength, so that isLengthSet in stackFrame will remain false.
    }

    fun isDummyLengthSet(): Boolean {
        if (state.isEmpty()) return false
        return !state.peek().isLengthSet
    }

    fun setLengthProcessed(length: Int) {
        require(length >= 0) { "Cannot set negative length (length = $length)." }
        val obj = state.pop()
        if (!state.isEmpty()) {
            val parent = state.peek()
            val lengthBytes = TLVUtil.getLengthAsBytes(length)
            parent.secureWrite(lengthBytes, 0, lengthBytes.size)
        }
        obj.setLength(length)
        state.push(obj)
        isAtStartOfTag = false
        isAtStartOfLength = false
        isReadingValue = true
    }

    fun updatePreviousLength(byteCount: Int) {
        if (state.isEmpty()) return
        val currentObject = state.peek()

        if (currentObject.isLengthSet && currentObject.length == byteCount) return

        currentObject.setLength(byteCount)

        if (currentObject.getValueBytesProcessed() == currentObject.length) {
            /* Update parent. */
            val obj = state.pop()
            val lengthBytes = TLVUtil.getLengthAsBytes(byteCount)
            val value = currentObject.getValue()
            updateValueBytesProcessed(lengthBytes, 0, lengthBytes.size)
            updateValueBytesProcessed(value, 0, value.size)
            isAtStartOfTag = true
            isAtStartOfLength = false
            isReadingValue = false
            obj.wipe()
        }
    }

    fun updateValueBytesProcessed(bytes: ByteArray?, offset: Int, length: Int) {
        if (state.isEmpty()) return
        bytes ?: throw IllegalArgumentException("bytes == null")

        val currentObject = state.peek()
        val bytesLeft = currentObject.length - currentObject.getValueBytesProcessed()
        if (length > bytesLeft) {
            throw IllegalArgumentException(
                "Cannot process $length bytes! Only $bytesLeft bytes left in this TLV object $currentObject"
            )
        }
        currentObject.write(bytes, offset, length)

        if (currentObject.getValueBytesProcessed() == currentObject.length) {
            /* Stand back! I'm going to try recursion! Update parent(s)... */
            val obj = state.pop()
            updateValueBytesProcessed(currentObject.getValue(), 0, currentObject.length)
            isAtStartOfTag = true
            isAtStartOfLength = false
            isReadingValue = false
            obj.wipe()
        } else {
            /* We already have these values?!? */
            isAtStartOfTag = false
            isAtStartOfLength = false
            isReadingValue = true
        }
    }

    fun getValue(): ByteArray {
        if (state.isEmpty()) throw IllegalStateException("Cannot get value yet.")
        return state.peek().getValue()
    }

    override fun toString(): String = state.toString()

    /*
     * TODO: ?? canBeWritten() <==> (state.size() == 1 && state.peek().isLengthSet()
     */
    fun canBeWritten(): Boolean {
        for (stackFrame in state) {
            if (!stackFrame.isLengthSet) return false
        }
        return true
    }

    private fun getDeepCopyOfState(): Deque<TLVStruct> {
        val newStack: Deque<TLVStruct> = ArrayDeque(state.size)
        for (tlvStruct in state) {
            newStack.add(TLVStruct(tlvStruct))
        }
        return newStack
    }

    fun wipeAll() {
        for (tlvStruct in state) {
            tlvStruct.wipe()
        }
        state.clear()
        isAtStartOfTag = true
        isAtStartOfLength = false
        isReadingValue = false
    }

    private class TLVStruct {
        var tag: Int
            private set
        var length: Int
            private set
        var isLengthSet: Boolean
            private set
        private val value: SecureByteArrayOutputStream = SecureByteArrayOutputStream()

        constructor(original: TLVStruct) : this(
            original.tag,
            original.length,
            original.isLengthSet,
            original.getValue()
        )

        constructor(tag: Int) : this(tag, Int.MAX_VALUE, false, null)

        constructor(tag: Int, length: Int, isLengthSet: Boolean, value: ByteArray?) {
            this.tag = tag
            this.length = length
            this.isLengthSet = isLengthSet
            if (value != null) {
                try {
                    this.value.setWipe(true)
                    this.value.write(value)
                    this.value.setWipe(false)
                } catch (ioe: IOException) {
                    LOGGER.log(Level.FINE, "Exception writing bytes in memory", ioe)
                }
            }
        }

        fun setLength(length: Int) {
            this.length = length
            this.isLengthSet = true
        }

        fun wipe() {
            this.value.wipe()
        }

        fun getValueBytesProcessed(): Int = value.size()

        fun getValue(): ByteArray = value.toByteArray()

        fun write(bytes: ByteArray, offset: Int, length: Int) {
            value.write(bytes, offset, length)
        }

        fun secureWrite(bytes: ByteArray, offset: Int, length: Int) {
            this.value.setWipe(true)
            value.write(bytes, offset, length)
            this.value.setWipe(false)
        }

        override fun toString(): String {
            val valueBytes = value.toByteArray()
            return "[TLVStruct ${Integer.toHexString(tag)}, " +
                    "${if (isLengthSet) length else "UNDEFINED"}, " +
                    "${Hex.bytesToHexString(valueBytes)}(${valueBytes.size}) ]"
        }
    }
}