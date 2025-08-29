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
 * $Id: TLVInputStream.java 321 2023-03-09 15:35:49Z martijno $
 */

package com.juncaffe.epassport.smartcard.tlv

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.logging.Logger
import kotlin.math.min

/**
 * An input-stream for parsing TLV structures that wraps an existing input-stream.
 *
 * @author Martijn Oostdijk
 * @version $Revision: 321 $
 */
class TLVInputStream(private val orgInputStream: InputStream, private val onProgress: ((Int) -> Unit)? = null) : InputStream() {

    companion object Companion {
        private val LOGGER: Logger = Logger.getLogger("net.sf.scuba.tlv")
    }

    private var state: TLVInputState = TLVInputState()
    private var markedState: TLVInputState? = null

    @Throws(IOException::class)
    private fun readUnsignedByte(): Int {
        val b = orgInputStream.read()
        if(b < 0) throw IOException("EOF while reading byte")
        return b and 0xFF
    }

    @Throws(IOException::class)
    private fun readFullyExact(dst: ByteArray, off: Int, len: Int) {
        var read = 0
        while(read < len) {
            val n = orgInputStream.read(dst, off + read, len - read)
            if(n < 0) throw IOException("EOF while reading $len bytes (read=$read)")
            read += n
        }
    }

    @Throws(IOException::class)
    private fun skipExact(n: Int): Int {
        var remain = n
        var skippedTotal = 0
        while(remain > 0) {
            val k = orgInputStream.skip(remain.toLong()).toInt()
            if(k == 0) {
                if(orgInputStream.read() < 0) break
                skippedTotal += 1
                remain -= 1
            }else {
                skippedTotal += k
                remain -= k
            }
        }
        return skippedTotal
    }

    /**
     * Reads a tag.
     * @return the tag just read
     */
    @Throws(IOException::class)
    fun readTag(): Int {
        if (!state.isAtStartOfTag && !state.isProcessingValue()) throw IllegalStateException("Not at start of tag")

        var bytesRead = 0
        var b = readUnsignedByte()
        bytesRead++
        while (b == 0x00 || b == 0xFF) { // padding(00, FF) skip
            b = readUnsignedByte()
            bytesRead++
        }
        val tag = when (b and 0x1F) {
            0x1F -> {
                var tmpTag = b // store the first byte including LHS nibble
                b = readUnsignedByte()
                bytesRead++
                while (b and 0x80 == 0x80) {
                    tmpTag = (tmpTag shl 8) or (b and 0x7F)
                    b = readUnsignedByte()
                    bytesRead++
                }
                tmpTag = (tmpTag shl 8) or (b and 0x7F)
                tmpTag
            }
            else -> b
        }
        state.setTagProcessed(tag, bytesRead)
        onProgress?.invoke(bytesRead)
        return tag
    }

    /**
     * Reads a length.
     * @return the length just read
     */
    @Throws(IOException::class)
    fun readLength(): Int {
        if (!state.isAtStartOfLength) {
            throw IllegalStateException("Not at start of length")
        }
        var bytesRead = 0
        var b = readUnsignedByte()
        bytesRead++
        val length = when(b and 0x80) {
            /* short form */
            0x00 -> b
            /* long form */
            else -> {
                val count = b and 0x7F
                require(count > 0) { "Invalid TLV length-of-length = 0" }
                var acc = 0
                repeat(count) {
                    b = readUnsignedByte()
                    bytesRead++
                    acc = (acc shl 8) or b
                }
                acc
            }
        }
        state.setLengthProcessed(length, bytesRead)
        return length
    }

    /**
     * Reads a value.
     * value 전체를 새 배열로 변환
     * @return the value just read
     */
    @Throws(IOException::class)
    fun readValue(): ByteArray {
        if (!state.isProcessingValue()) throw IllegalStateException("Not yet processing value!")
        val length = state.getLength()
        val value = ByteArray(length)
        readFullyExact(value, 0, length)
        state.updateValueBytesProcessed(length)
        onProgress?.invoke(length)
        return value
    }

    /**
     * Value 를 호출자가 넘긴 버퍼에 채워 넣음
     * @param dst 대상 버퍼 (깊이는 state.length 이상)
     * @return
     */
    @Throws(IOException::class)
    fun readValueInto(dst: ByteArray, offset: Int = 0): Int {
        if (!state.isProcessingValue()) throw IllegalStateException("Not yet processing value!")
        val length = state.getLength()
        require(offset >= 0 && offset + length <= dst.size) { "dst too small: need=$length at offset=$offset" }
        readFullyExact(dst, 0, length)
        state.updateValueBytesProcessed(length)
        onProgress?.invoke(length)
        return length
    }

    /**
     * Value 를 OutputStream 으로 스트리밍 복사
     * @param out 대상 스트림
     * @param scratchSize 내부 스크래치 버퍼 크기(기본 4KB)
     * @param wipeScratch true: 각 루프마다 scratch를 0으로 덮어 씌움
     * @return 전달한 총 바이트 수
     */
    @Throws(IOException::class)
    fun readValueTo(out: OutputStream, scratchSize: Int = 4096, wipeScratch: Boolean = false): Int {
        if (!state.isProcessingValue()) throw IllegalStateException("Not yet processing value!")
        val total = state.getLength()
        var left = total
        val buf = ByteArray(min(scratchSize, maxOf(1, total)))
        while(left > 0) {
            val chunk = min(buf.size, left)
            readFullyExact(buf, 0, chunk)
            out.write(buf, 0, chunk)
            if(wipeScratch) buf.fill(0)
            left -= chunk
        }
        state.updateValueBytesProcessed(total)
        onProgress?.invoke(total)
        return total
    }

    @Throws(IOException::class)
    private fun skipValue(): Long {
        if (state.isAtStartOfTag || state.isAtStartOfLength) return 0
        val bytesLeft = state.getValueBytesLeft()
        val skipped = skipExact(bytesLeft)
        state.updateValueBytesProcessed(skipped)
        onProgress?.invoke(skipped)
        return skipped.toLong()
    }

    /**
     * Skips in this stream until a given tag is found (depth first).
     */
    @Throws(IOException::class)
    fun skipToTag(searchTag: Int) {
        while (true) {
            if (state.isAtStartOfTag) {
                // Nothing
            } else if (state.isAtStartOfLength) {
                readLength()
                if (TLVUtil.isPrimitive(state.getTag()))
                    skipValue()
            } else {
                if (TLVUtil.isPrimitive(state.getTag()))
                    skipValue()
            }
            val tag = readTag()
            if (tag == searchTag)
                return

            if (TLVUtil.isPrimitive(tag)) {
                val length = readLength()
                val skippedBytes = skipValue().toInt()
                if (skippedBytes < length) {
                    // Could only skip less than length bytes, probably EOF
                    break
                }
            }
        }
    }

    @Throws(IOException::class)
    override fun read(): Int {
        val result = orgInputStream.read()
        if (result < 0) return -1
        state.updateValueBytesProcessed(1)
        onProgress?.invoke(1)
        return result
    }

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val n = orgInputStream.read(b, off, len)
        if(n >0) {
            state.updateValueBytesProcessed(n)
            onProgress?.invoke(n)
        }
        return n
    }

    @Throws(IOException::class)
    override fun skip(n: Long): Long {
        if (n <= 0) return 0
        val result = orgInputStream.skip(n)
        state.updateValueBytesProcessed(result.toInt())
        onProgress?.invoke(result.toInt())
        return result
    }

    @Throws(IOException::class)
    override fun available(): Int = orgInputStream.available()

    @Synchronized
    override fun mark(readLimit: Int) {
        orgInputStream.mark(readLimit)
        markedState = TLVInputState(state)
    }

    override fun markSupported(): Boolean = orgInputStream.markSupported()

    @Synchronized
    @Throws(IOException::class)
    override fun reset() {
        if (!markSupported()) throw IOException("mark/reset not supported")
        orgInputStream.reset()
        state = markedState ?: throw IOException("No marked state")
        markedState = null
    }

    @Throws(IOException::class)
    override fun close() {
        try {
            super.close()
        }finally {
            orgInputStream.close()
        }
    }

    override fun toString(): String = state.toString()
}