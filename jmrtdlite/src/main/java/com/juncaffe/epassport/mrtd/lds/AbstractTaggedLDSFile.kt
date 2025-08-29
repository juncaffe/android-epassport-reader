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
 * $Id: AbstractTaggedLDSFile.java 1811 2019-05-27 14:08:20Z martijno $
 */
package com.juncaffe.epassport.mrtd.lds

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.epassport.smartcard.tlv.TLVInputStream
import com.juncaffe.epassport.smartcard.tlv.TLVOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.logging.Logger

/**
 * Base class for TLV based LDS files.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1811 $
 */
abstract class AbstractTaggedLDSFile : AbstractLDSFile {
    /**
     * Returns the tag that identifies this LDS file.
     *
     * @return the tag of this LDS file
     */
    private var tag: Int
    private var length: Int = 0
    private var accumulatedReadSize: Int = 0

    private var onProgress: PassportService.ProgressListener? = null

    /**
     * Constructs a data group. This constructor
     * is only visible to the other classes in this package.
     *
     * @param dataGroupTag data group tag
     */
    constructor(dataGroupTag: Int) {
        this.tag = dataGroupTag
    }

    /**
     * Constructs a data group from the DER encoded data in the
     * given input stream.
     *
     * @param tag the tag
     * @param inputStream an input stream
     *
     * @throws IOException on error reading input stream
     */
    constructor(tag: Int, inputStream: InputStream, onProgress: PassportService.ProgressListener? = null) {
        this.tag = tag
        this.onProgress = onProgress
        readObject(inputStream)
    }

    /**
     * Reads the contents of this LDS file, including tag and length from an input stream.
     *
     * @param inputStream the stream to read from
     *
     * @throws IOException if reading from the stream fails
     */
    @Throws(IOException::class)
    override fun readObject(inputStream: InputStream) {
        val tlvIn = TLVInputStream(inputStream){ inc(it) }
        tlvIn.use {
            val inputTag = tlvIn.readTag()
            require(inputTag == tag) { "Was expecting tag " + Integer.toHexString(tag) + ", found " + Integer.toHexString(inputTag) }
            length = tlvIn.readLength()
            readContent(tlvIn)
        }
    }

    @Throws(IOException::class)
    override fun writeObject(outputStream: OutputStream) {
        val tlvOut = if (outputStream is TLVOutputStream) outputStream else TLVOutputStream(outputStream)
        val ourTag = this.tag
        tlvOut.writeTag(ourTag)
        val value = getContent()
        val ourLength = value.size
        if (length != ourLength) {
            length = ourLength
        }
        tlvOut.writeValue(value)
    }

    /**
     * Reads the contents of the data group from an input stream.
     * Client code implementing this method should only read the contents
     * from the input stream, not the tag or length of the data group.
     *
     * @param inputStream the input stream to read from
     *
     * @throws IOException on error reading from input stream
     */
    @Throws(IOException::class)
    protected abstract fun readContent(inputStream: InputStream)

    /**
     * Writes the contents of the data group to an output stream.
     * Client code implementing this method should only write the contents
     * to the output stream, not the tag or length of the data group.
     *
     * @param outputStream the output stream to write to
     *
     * @throws IOException on error writing to output stream
     */
    @Throws(IOException::class)
    protected abstract fun writeContent(outputStream: OutputStream)

    /**
     * Returns a textual representation of this file.
     *
     * @return a textual representation of this file
     */
    override fun toString(): String {
        return "TaggedLDSFile [" + Integer.toHexString(this.tag) + " (" + getLength() + ")]"
    }

    /**
     * Returns the tag that identifies this LDS file.
     *
     * @return the tag of this LDS file
     */
    fun getTag(): Int {
        return tag
    }

    /**
     * The length of the value of the data group.
     *
     * @return the length of the value of the data group
     */
    override fun getLength(): Int {
        if (length <= 0) {
            length = getContent().size
        }
        return length
    }

    /**
     * Returns the value part of this LDS file.
     *
     * @return the value as byte array
     */
    private fun getContent(): ByteArray {
        return SecureByteArrayOutputStream(true).use {
            try {
                writeContent(it)
                it.flush()
                it.toByteArrayAndWipe()
            }catch (ioe: IOException) {
                throw java.lang.IllegalStateException("Could not get DG content", ioe)
            }
        }
    }

    protected fun inc(currentReadSize: Int) {
        if(currentReadSize <= 0) return
        accumulatedReadSize += currentReadSize
        notifyProgress(currentReadSize)
    }

    protected fun notifyProgress(currentReadSize: Int) {
        onProgress?.let {
            if(length > 0) {
                val accumulatedReadSize = accumulatedReadSize.coerceAtMost(length)
                it.onProgress(currentReadSize, accumulatedReadSize, length)
            }
        }
    }

    companion object {
        private val serialVersionUID = -4761360877353069639L

        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")
    }
}
