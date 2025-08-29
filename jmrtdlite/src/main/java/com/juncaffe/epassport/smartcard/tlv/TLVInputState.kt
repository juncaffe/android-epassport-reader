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
 * $Id: TLVInputState.java 321 2023-03-09 15:35:49Z martijno $
 */

package com.juncaffe.epassport.smartcard.tlv

import java.util.ArrayDeque
import java.util.Deque

/**
 * State keeps track of where we are in a TLV stream.
 *
 * @author The SCUBA team
 * @version $Revision: 321 $
 */
class TLVInputState {

    /**
     * Encodes tags, lengths, and number of valueBytes encountered thus far.
     */
    private var state: Deque<TLStruct>

    /*
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

    constructor(original: TLVInputState) : this(
        original.getDeepCopyOfState(),
        original.isAtStartOfTag,
        original.isAtStartOfLength,
        original.isReadingValue
    )

    private constructor(
        state: Deque<TLStruct>,
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
        if (state.isEmpty()) {
            throw IllegalStateException("Tag not yet read.")
        }
        val currentObject = state.peek()
        return currentObject.tag
    }

    fun getLength(): Int {
        if (state.isEmpty()) {
            throw IllegalStateException("Length not yet known.")
        }
        val currentObject = state.peek()
        return currentObject.length
    }

    fun getValueBytesProcessed(): Int {
        val currentObject = state.peek()
        return currentObject.getValueBytesProcessed()
    }

    fun getValueBytesLeft(): Int {
        if (state.isEmpty()) {
            throw IllegalStateException("Length of value is unknown.")
        }
        val currentObject = state.peek()
        val currentLength = currentObject.length
        val valueBytesRead = currentObject.getValueBytesProcessed()
        return currentLength - valueBytesRead
    }

    fun setTagProcessed(tag: Int, byteCount: Int) {
        // Length is set to MAX INT, we will update it when caller calls our setLengthProcessed.
        val obj = TLStruct(tag)
        if (!state.isEmpty()) {
            val parent = state.peek()
            parent.updateValueBytesProcessed(byteCount)
        }
        state.push(obj)
        isAtStartOfTag = false
        isAtStartOfLength = true
        isReadingValue = false
    }

    fun setDummyLengthProcessed() {
        isAtStartOfTag = false
        isAtStartOfLength = false
        isReadingValue = true
    }

    fun setLengthProcessed(length: Int, byteCount: Int) {
        require(length >= 0) {
            "Cannot set negative length (length = $length, 0x${Integer.toHexString(length)} for tag ${Integer.toHexString(getTag())})."
        }
        val obj = state.pop()
        if (!state.isEmpty()) {
            val parent = state.peek()
            parent.updateValueBytesProcessed(byteCount)
        }
        obj.setLength(length)
        state.push(obj)
        isAtStartOfTag = false
        isAtStartOfLength = false
        isReadingValue = true
    }

    fun updateValueBytesProcessed(byteCount: Int) {
        if (state.isEmpty()) return
        val currentObject = state.peek()
        val bytesLeft = currentObject.length - currentObject.getValueBytesProcessed()
        if (byteCount > bytesLeft) {
            throw IllegalArgumentException(
                "Cannot process $byteCount bytes! Only $bytesLeft bytes left in this TLV object $currentObject"
            )
        }
        currentObject.updateValueBytesProcessed(byteCount)
        val currentLength = currentObject.length
        if (currentObject.getValueBytesProcessed() == currentLength) {
            state.pop()
            // Stand back! I'm going to try recursion! Update parent(s)...
            updateValueBytesProcessed(currentLength)
            isAtStartOfTag = true
            isAtStartOfLength = false
            isReadingValue = false
        } else {
            isAtStartOfTag = false
            isAtStartOfLength = false
            isReadingValue = true
        }
    }

    override fun toString(): String = state.toString()

    private fun getDeepCopyOfState(): Deque<TLStruct> {
        val newStack: Deque<TLStruct> = ArrayDeque(state.size)
        for (tlStruct in state) {
            newStack.addLast(TLStruct(tlStruct))
        }
        return newStack
    }

    private class TLStruct {
        var tag: Int
            private set
        var length: Int
            private set
        private var valueBytesRead: Int

        constructor(tag: Int) : this(tag, Int.MAX_VALUE, 0)

        constructor(original: TLStruct) : this(original.tag, original.length, original.valueBytesRead)

        constructor(tag: Int, length: Int, valueBytesRead: Int) {
            this.tag = tag
            this.length = length
            this.valueBytesRead = valueBytesRead
        }

        fun setLength(length: Int) {
            this.length = length
        }

        fun getValueBytesProcessed(): Int = valueBytesRead

        fun updateValueBytesProcessed(n: Int) {
            valueBytesRead += n
        }

        override fun toString(): String {
            return "[TLStruct ${Integer.toHexString(tag)}, $length, $valueBytesRead]"
        }
    }
}