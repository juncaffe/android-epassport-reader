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
 * $Id: TLVOutputStream.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard.tlv

import java.io.DataOutputStream
import java.io.IOException
import java.io.OutputStream

/**
 * An output-stream for constructing TLV structures which wraps an existing
 * output-stream.
 *
 * Typical use is to first write a tag using `writeTag(int)`,
 * and then:
 *
 *  * either directly write a value using `writeValue(byte[])`
 * (which will cause the length and that value to be written),
 *
 *  * or use a series of lower-level output-stream `write` calls to write
 * the value and terminate with a `writeValueEnd()`
 * (which will cause the length and value to be computed and written).
 *
 *
 *
 * Nested structures can be constructed by writing new tags during value construction.
 *
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 *
 * @version $Revision: 321 $
 */
class TLVOutputStream(outputStream: OutputStream?) : OutputStream() {
    private val outputStream: DataOutputStream
    private val state: TLVOutputState

    /**
     * Constructs a TLV output-stream by wrapping an existing output-stream.
     *
     * @param outputStream the existing output-stream
     */
    init {
        this.outputStream = if (outputStream is DataOutputStream) outputStream else DataOutputStream(outputStream)
        this.state = TLVOutputState()
    }

    /**
     * Writes a tag to the output-stream (if TLV state allows it).
     *
     * @param tag the tag to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    fun writeTag(tag: Int) {
        val tagAsBytes = TLVUtil.getTagAsBytes(tag)
        if (state.canBeWritten()) {
            outputStream.write(tagAsBytes)
        }
        state.setTagProcessed(tag)
    }

    /**
     * Writes a length to the output-stream (if TLV state allows it).
     *
     * @param length the length to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    fun writeLength(length: Int) {
        val lengthAsBytes = TLVUtil.getLengthAsBytes(length)
        state.setLengthProcessed(length)
        if (state.canBeWritten()) {
            outputStream.write(lengthAsBytes)
        }
    }

    /**
     * Writes a value at once.
     * If no tag was previously written, an exception is thrown.
     * If no length was previously written, this method will write the length before writing `value`.
     * If length was previously written, this method will check whether the length is consistent with `value`'s length.
     *
     * @param value the value to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    fun writeValue(value: ByteArray?) {
        requireNotNull(value) { "Cannot write null." }
        check(!state.isAtStartOfTag) { "Cannot write value bytes yet. Need to write a tag first." }
        if (state.isAtStartOfLength) {
            writeLength(value.size)
            write(value)
        } else {
            write(value)
            state.updatePreviousLength(value.size)
        }
    }

    /**
     * Writes the specified byte to this output-stream.
     * Note that this can only be used for writing value bytes and
     * will throw an exception unless we have already written a tag.
     *
     * @param b the byte to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    /**
     * Writes the specified bytes to this output-stream.
     * Note that this can only be used for writing value bytes and
     * will throw an exception unless we have already written a tag.
     *
     * @param bytes the bytes to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    override fun write(bytes: ByteArray) {
        write(bytes, 0, bytes.size)
    }

    /**
     * Writes the specified number of bytes to this output-stream starting at the
     * specified offset.
     * Note that this can only be used for writing value bytes and
     * will throw an exception unless we have already written a tag.
     *
     * @param bytes the bytes to write
     * @param offset the offset
     * @param length the number of bytes to write
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    override fun write(bytes: ByteArray?, offset: Int, length: Int) {
        check(!state.isAtStartOfTag) { "Cannot write value bytes yet. Need to write a tag first." }
        if (state.isAtStartOfLength) {
            state.setDummyLengthProcessed()
        }
        state.updateValueBytesProcessed(bytes, offset, length)
        if (state.canBeWritten()) {
            outputStream.write(bytes, offset, length)
        }
    }

    /**
     * Marks the end of the value written thus far. This will adjust the length and
     * write the buffer to the underlying output-stream.
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    fun writeValueEnd() {
        check(!state.isAtStartOfLength) { "Not processing value yet." }
        if (state.isAtStartOfTag && !state.isDummyLengthSet()) {
            return  /* TODO: check if this case ever happens. */
        }
        val bufferedValueBytes = state.getValue()
        val length = bufferedValueBytes.size
        state.updatePreviousLength(length)
        if (state.canBeWritten()) {
            val lengthAsBytes = TLVUtil.getLengthAsBytes(length)
            outputStream.write(lengthAsBytes)
            outputStream.write(bufferedValueBytes)
        }
    }

    /**
     * Flushes the underlying output-stream. Note that this does not
     * flush the value buffer if the current value has not been completed.
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    override fun flush() {
        outputStream.flush()
    }

    fun wipe() {
        state.wipeAll()
    }

    /**
     * Closes this output-stream and releases any system resources
     * associated with this stream.
     *
     * @throws IOException on error writing to the underlying output-stream
     */
    @Throws(IOException::class)
    override fun close() {
        wipe()
        check(state.canBeWritten()) { "Cannot close stream yet, illegal TLV state." }
        outputStream.close()
    }
}