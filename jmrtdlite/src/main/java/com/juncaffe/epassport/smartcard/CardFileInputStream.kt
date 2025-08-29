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
 * $Id: CardFileInputStream.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard

import com.juncaffe.epassport.mrtd.DefaultFileSystem
import java.io.IOException
import java.io.InputStream
import kotlin.math.min

/**
 * Inputstream for reading files on ISO 7816 file system cards.
 *
 * @author Martijn Oostdijk (martijn.oostdijk@gmail.com)
 */
class CardFileInputStream(maxBlockSize: Int, private val fs: DefaultFileSystem) : InputStream() {
    private val path: Array<FileInfo>
    val buffer: ByteArray
    private var bufferLength = 0
    private var offsetBufferInFile = 0
    private var offsetInBuffer = 0
    private var markedOffset = 0

    /**
     * Gets the length of the underlying card file.
     *
     * @return the length of the underlying card file.
     */
    var length: Int = 0

    /**
     * An input stream for reading from the currently selected file in the indicated file system.
     *
     * @param maxBlockSize maximum block size to use for read binaries
     * @param fs the file system
     *
     * @throws net.sf.scuba.smartcards.CardServiceException on error
     */
    init {
        synchronized(this.fs) {
            val fsPath = fs.getSelectedPath()
            if (fsPath == null || fsPath.size < 1) {
                throw CardServiceException("No valid file selected, path = " + fsPath.contentToString())
            }
            this.path = arrayOfNulls<FileInfo>(fsPath.size) as Array<FileInfo>
            System.arraycopy(fsPath, 0, this.path, 0, fsPath.size)
            this.length = fsPath[fsPath.size - 1]!!.getFileLength()
            buffer = ByteArray(maxBlockSize)
            bufferLength = 0
            offsetBufferInFile = 0
            offsetInBuffer = 0
            markedOffset = -1
        }
    }

    @Throws(IOException::class)
    override fun read(): Int {
        synchronized(fs) {
            try {
                if (!path.contentEquals(fs.getSelectedPath())) {
                    for (fileInfo in path) {
                        fs.selectFile(fileInfo.getFID())
                    }
                }
            } catch (cse: CardServiceException) {
                /* ERROR: selecting proper path failed. */
                throw IOException("Unexpected exception", cse) // FIXME: proper error handling here
            }
            val offsetInFile = offsetBufferInFile + offsetInBuffer
            if (offsetInFile >= this.length) {
                return -1
            }
            if (offsetInBuffer >= bufferLength) {
                val le = min(buffer.size, this.length - offsetInFile)
                try {
                    /* NOTE: using tmp variables here, in case fill throws an exception (which we don't catch). */
                    val newOffsetBufferInFile = offsetBufferInFile + bufferLength
                    val newOffsetInBuffer = 0
                    var newBufferLength = 0
                    while (newBufferLength == 0) {
                        newBufferLength = fillBufferFromFile(path, newOffsetBufferInFile, le)
                    }
                    offsetBufferInFile = newOffsetBufferInFile
                    offsetInBuffer = newOffsetInBuffer
                    bufferLength = newBufferLength
                } catch (cse: CardServiceException) {
                    throw IOException("Unexpected exception", cse)
                } catch (e: Exception) {
                    throw IOException("Unexpected exception", e)
                }
            }
            val result = buffer[offsetInBuffer].toInt() and 0xFF
            offsetInBuffer++
            return result
        }
    }

    override fun skip(n: Long): Long {
        synchronized(fs) {
            if (n < (bufferLength - offsetInBuffer)) {
                offsetInBuffer += n.toInt()
            } else {
                var offsetInFile = offsetBufferInFile + offsetInBuffer
                offsetBufferInFile = (offsetInFile + n).toInt() /* FIXME: shouldn't we check for EOF? We know fileLength... */
                offsetInBuffer = 0
                bufferLength = 0
                offsetInFile = offsetBufferInFile + offsetInBuffer
            }
            return n
        }
    }

    @Synchronized
    override fun available(): Int {
        return bufferLength - offsetInBuffer
    }

    override fun mark(readLimit: Int) {
        synchronized(fs) {
            markedOffset = offsetBufferInFile + offsetInBuffer
        }
    }

    @Throws(IOException::class)
    override fun reset() {
        synchronized(fs) {
            if (markedOffset < 0) {
                throw IOException("Mark not set")
            }
            offsetBufferInFile = markedOffset
            offsetInBuffer = 0
            bufferLength = 0
        }
    }

    override fun markSupported(): Boolean {
        synchronized(fs) {
            return true
        }
    }

    val postion: Int
        get() = offsetBufferInFile + offsetInBuffer

    /**
     * Reads from file with id `fid`.
     *
     * @param fid the file to read
     * @param offsetInFile starting offset in file
     * @param length the number of bytes to read, or -1 to read until EOF
     *
     * @return the number of bytes that were actually buffered (at most `le`)
     */
    @Throws(CardServiceException::class)
    private fun fillBufferFromFile(path: Array<FileInfo>, offsetInFile: Int, le: Int): Int {
        synchronized(fs) {
            require(le <= buffer.size) { "length too big" }
            if (!fs.getSelectedPath().contentEquals(path)) {
                for (fileInfo in path) {
                    fs.selectFile(fileInfo.getFID())
                }
            }
            val data = fs.readBinary(offsetInFile, le)
            val length = data.size

            System.arraycopy(data, 0, buffer, 0, length)
            data.fill(0)
            return length
        }
    }

    fun wipe() {
        buffer.fill(0)
        bufferLength = 0
        offsetBufferInFile = 0
        offsetInBuffer = 0
        markedOffset = 0
    }

    override fun close() {
        try {
            super.close()
        }finally {
            wipe()
        }
    }
}