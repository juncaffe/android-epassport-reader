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
 * $Id: DefaultFileSystem.java 1850 2021-05-21 06:25:03Z martijno $
 */
package com.juncaffe.epassport.mrtd

import com.juncaffe.epassport.mrtd.io.FragmentBuffer
import com.juncaffe.epassport.mrtd.protocol.ReadBinaryAPDUSender
import com.juncaffe.epassport.mrtd.protocol.SecureMessagingWrapper
import com.juncaffe.epassport.smartcard.APDUWrapper
import com.juncaffe.epassport.smartcard.CardServiceException
import com.juncaffe.epassport.smartcard.FileInfo
import com.juncaffe.epassport.smartcard.ISO7816
import com.juncaffe.epassport.smartcard.tlv.TLVInputStream
import com.juncaffe.epassport.smartcard.util.Hex.bytesToHexString
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.Serializable
import java.util.logging.Level
import java.util.logging.Logger
import kotlin.math.min

/**
 * A file system for ICAO MRTDs (and similar file systems).
 * This translates abstract high level selection and read binary commands to
 * concrete low level file related APDUs which are sent to the ICC through the
 * card service.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1850 $
 *
 * @since 0.7.0
 */
class DefaultFileSystem @JvmOverloads constructor(private val service: ReadBinaryAPDUSender) {

    /** Indicates the file that is (or should be) selected.  */
    private var selectedFID: Short = 0
    /**
     * A boolean indicating whether we actually already
     * sent the SELECT command to select {@ code selectedFID}.
     */
    private var isSelected = false

    private var maxReadBinaryLength: Int = PassportService.EXTENDED_MAX_TRANCEIVE_LENGTH

    private val fileInfos: MutableMap<Short?, DefaultFileInfo?> = HashMap()

    private var wrapper: APDUWrapper? = null
    private var oldWrapper: APDUWrapper? = null

    /**
     * Returns the currently set maximum length to be requested in READ BINARY commands.
     *
     * @return the currently set maximum length to be requested in READ BINARY commands
     */
    fun getMaxReadBinaryLength(): Int {
        return maxReadBinaryLength
    }

    /**
     * Sets the current wrapper to the given APDU wrapper.
     * Subsequent APDUs will be wrapped before sending to the ICC.
     *
     * @param wrapper an APDU wrapper
     */
    fun setWrapper(wrapper: APDUWrapper?) {
        oldWrapper = this.wrapper
        this.wrapper = wrapper
    }

    /**
     * Returns the wrapper (secure messaging) currently in use.
     *
     * @return the wrapper
     */
    fun getWrapper(): APDUWrapper? {
        return wrapper
    }

    /**
     * Returns the selected path.
     *
     * @return the path components
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun getSelectedPath(): Array<FileInfo>? {
        return this.getFileInfo()?.let {
            arrayOf(it)
        }
    }

    /*
   * NOTE: This doesn't actually send a select file command. ReadBinary will do so
   * if needed.
   */
    /**
     * Selects a file.
     *
     * @param fid indicates the file to select
     *
     * @throws CardServiceException on error communicating over the service
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun selectFile(fid: Short) {
        if (selectedFID != fid) {
            selectedFID = fid
            isSelected = false
        }
    }

    /**
     * Reads a block of bytes.
     *
     * @param offset offset index in the selected file
     * @param length the number of bytes to read
     *
     * @return a copy of the bytes read
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun readBinary(offset: Int, length: Int): ByteArray {
        val readLength = min(length, maxReadBinaryLength)
        var fileInfo: DefaultFileInfo? = null
        try {
            if (selectedFID <= 0) throw CardServiceException("No file selected")

            /* Check buffer to see if we already have some of the bytes. */
            fileInfo = this.getFileInfo()?: throw IllegalStateException("Could not get file info")

            val fragment: FragmentBuffer.Fragment = fileInfo.getSmallestUnbufferedFragment(offset, readLength)
            var responseLength = readLength

            if (fragment.length > 0) {
                if (!isSelected) {
                    sendSelectFile(selectedFID)
                    isSelected = true
                }
                val bytes = sendReadBinary(fragment.getOffset(), fragment.getLength(), offset > 32767)?: throw IllegalStateException("Could not read bytes")

                if(bytes.isNotEmpty()) {
                    fileInfo.addFragment(fragment.offset, bytes)
                }
                /*
                 * If we request a block of data, create the return buffer from the actual response length, not the requested Le.
                 * The latter causes issues when the returned block has a one byte padding (only 0x80) which ends up being removed but
                 * the length is not kept track of, leaving an unwanted 0-byte at the end of the data block, which now has a length
                 * of Le, but actually contained Le - 1 data bytes.
                 *
                 * Bug reproduced using org.jmrtd.AESSecureMessagingWrapper with AES-256.
                 */
                if (bytes.size < fragment.getLength()) {
                    responseLength = bytes.size
                }
            }
            /* Shrink wrap the bytes that are now buffered. */
            /* NOTE: That arraycopy looks costly, consider using dest array and offset params instead of byte[] result... -- MO */
            val buffer = fileInfo.getBuffer()
            val result = ByteArray(responseLength)
            System.arraycopy(buffer, offset, result, 0, responseLength)
            return result
        } catch (cse: CardServiceException) {
            val sw = cse.sW.toShort()
            if ((sw.toInt() and ISO7816.SW_WRONG_LENGTH.toInt()) == ISO7816.SW_WRONG_LENGTH.toInt() && maxReadBinaryLength > PassportService.DEFAULT_MAX_BLOCKSIZE) {
                wrapper = oldWrapper
                maxReadBinaryLength = PassportService.DEFAULT_MAX_BLOCKSIZE
                return byteArrayOf()
            }
            throw CardServiceException("Read binary failed on file " + (fileInfo ?: Integer.toHexString(selectedFID.toInt())), cse)
        } catch (e: Exception) {
            throw CardServiceException("Read binary failed on file " + (fileInfo ?: Integer.toHexString(selectedFID.toInt())), e)
        }
    }

    /**
     * 헤더에서 파일 크기만 읽음
     */
    fun getFileTotalLength(fid: Short): Int {
        selectFile(fid)
        try {
            if (!isSelected) {
                sendSelectFile(selectedFID)
                isSelected = true
            }

            val prefix = sendReadBinary(0, READ_AHEAD_LENGTH, false)
            if (prefix == null || prefix.isEmpty()) {
                LOGGER.warning("Something is wrong with prefix, prefix = " + bytesToHexString(prefix))
                return -1
            }
            /* We got less than asked for, assume prefix is the complete file. */
            if (prefix.size < READ_AHEAD_LENGTH) return prefix.size

            return ByteArrayInputStream(prefix).use {
                TLVInputStream(it).use { tlvIn ->
                    tlvIn.readTag()
                    tlvIn.readLength()
                }
            }
        } catch (ioe: IOException) {
            throw CardServiceException("Error getting file info for " + Integer.toHexString(selectedFID.toInt()), ioe)
        }
    }

    /**
     * Returns the file info object for the currently selected file. If this
     * executes normally the result is non-null. If the file has not been
     * read before this will send a READ_BINARY to determine length.
     *
     * @return a non-null MRTDFileInfo
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    private fun getFileInfo(): DefaultFileInfo? {
        if (selectedFID <= 0) throw CardServiceException("No file selected")

        /* If known file, use file info from cache. */
        fileInfos[selectedFID]?.let { return it }

        /* Not cached, actually read some bytes to determine file info. */
        try {
            /*
             * Each passport file consists of a TLV structure, read ahead to determine length.
             */
            if (!isSelected) {
                sendSelectFile(selectedFID)
                isSelected = true
            }

            var prefix = sendReadBinary(0, READ_AHEAD_LENGTH, false)
            if (prefix == null || prefix.isEmpty()) {
                LOGGER.warning("Something is wrong with prefix, prefix = " + bytesToHexString(prefix))
                return null
            }
            val fileLength: Int = getFileLength(selectedFID, READ_AHEAD_LENGTH, prefix)
            if (fileLength < prefix.size) {
                /* We got more than the file's length. Ignore trailing bytes. */
                prefix = prefix.copyOf(fileLength)
            }
            val fileInfo = DefaultFileInfo(selectedFID, fileLength)
            fileInfo.addFragment(0, prefix)
            fileInfos[selectedFID] = fileInfo
            return fileInfo
        } catch (ioe: IOException) {
            throw CardServiceException("Error getting file info for " + Integer.toHexString(selectedFID.toInt()), ioe)
        }
    }

    /**
     * Determines the file length by inspecting a prefix of bytes read from
     * the (TLV contents of a) file.
     *
     * @param fid the file identifier
     * @param le the requested length while requesting the prefix
     * @param prefix the prefix read from the file
     *
     * @return the file length
     *
     * @throws IOException on error reading the prefix as a TLV sequence
     */
    @Throws(IOException::class)
    private fun getFileLength(fid: Short, le: Int, prefix: ByteArray): Int {
        /* We got less than asked for, assume prefix is the complete file. */
        if (prefix.size < le) return prefix.size

        val byteArrayInputStream = ByteArrayInputStream(prefix)
        val tlvInputStream = TLVInputStream(byteArrayInputStream)
        return try {
            tlvInputStream.readTag()
            /* Determine length based on TLV. */
            val valueLength = tlvInputStream.readLength()
            /* NOTE: we're using a specific property of ByteArrayInputStream's available method here! */
            val tlLength = prefix.size - byteArrayInputStream.available()
            tlLength + valueLength
        } finally {
            try {
                tlvInputStream.close()
            } catch (ioe: IOException) {
                LOGGER.log(Level.FINE, "Error closing stream", ioe)
            }
        }
    }

    /**
     * Selects a file within the MRTD application.
     *
     * @param fid a file identifier
     *
     * @throws CardServiceException on error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun sendSelectFile(fid: Short) {
        service.sendSelectFile(wrapper, fid)
    }

    /**
     * Sends a `READ BINARY` command for the already selected file to the passport,
     * using the wrapper when a secure channel has been set up.
     *
     * @param offset offset into the file
     * @param le the expected length of the file to read
     * @param isTLVEncodedOffsetNeeded whether to encode the offset in a TLV object (typically for offset larger than 32767)
     *
     * @return a byte array of length `le` with (the specified part of) the contents of the currently selected file
     *
     * @throws CardServiceException on tranceive error
     */
    @Synchronized
    @Throws(CardServiceException::class)
    fun sendReadBinary(offset: Int, le: Int, isTLVEncodedOffsetNeeded: Boolean): ByteArray? {
        oldWrapper = if (wrapper is SecureMessagingWrapper) SecureMessagingWrapper.getInstance(wrapper as SecureMessagingWrapper) else wrapper
        return service.sendReadBinary(wrapper, offset, le, isTLVEncodedOffsetNeeded)
    }

    /**
     * A file info for the ICAO MRTD file system.
     *
     * @param fid indicates which file
     * @param length length of the contents of the file
     *
     * @author The JMRTD team (info@jmrtd.org)
     *
     * @version $Revision: 1850 $
     */
    private class DefaultFileInfo(private val fid: Short, length: Int) : FileInfo(), Serializable {

        @Transient
        private val fragmentBuffer: FragmentBuffer = FragmentBuffer(length)

        /**
         * Returns the file identifier.
         *
         * @return file identifier
         */
        override fun getFID(): Short = fid

        /**
         * Returns the length of the file.
         *
         * @return the length of the file
         */
        override fun getFileLength(): Int = fragmentBuffer.length

        /**
         * Returns the buffer.
         *
         * @return the buffer
         */
        fun getBuffer(): ByteArray? = fragmentBuffer.buffer

        /**
         * Returns a textual representation of this file info.
         *
         * @return a textual representation of this file info
         */
        override fun toString(): String = Integer.toHexString(fid.toInt())

        /**
         * Returns the smallest unbuffered fragment included in `offset` and `offset + length - 1`.
         *
         * @param offset the offset
         * @param length the length
         *
         * @return a fragment smaller than or equal to the fragment indicated by `offset` and `length`
         */
        fun getSmallestUnbufferedFragment(offset: Int, length: Int): FragmentBuffer.Fragment {
            return fragmentBuffer.getSmallestUnbufferedFragment(offset, length)
        }

        /**
         * Adds a fragment of bytes at a specific offset to this file.
         *
         * @param offset the offset
         * @param bytes the bytes to be added
         */
        fun addFragment(offset: Int, bytes: ByteArray?) {
            fragmentBuffer.addFragment(offset, bytes)
        }

        fun wipe() {
            fragmentBuffer.wipe()
        }
    }

    fun wipe() {
        fileInfos.values.forEach { it?.wipe() }
        fileInfos.clear()
    }

    fun clearCache() {
        fileInfos[selectedFID]?.wipe()
    }

    companion object {
        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")
        /** Number of bytes to read at start of file to determine file length.  */
        private const val READ_AHEAD_LENGTH = 8
    }
}
