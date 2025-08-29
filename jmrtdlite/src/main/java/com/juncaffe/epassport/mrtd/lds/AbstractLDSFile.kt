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
 * $Id: AbstractLDSFile.java 1775 2018-04-09 10:13:04Z martijno $
 */
package com.juncaffe.epassport.mrtd.lds

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Base class for all files (EF_COM, EF_SOD, and data groups) in the LDS.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1775 $
 */
abstract class AbstractLDSFile : LDSFile {
    /**
     * Returns the contents of this file as byte array,
     * includes the ICAO tag and length.
     *
     * @return a byte array containing the file
     */
    override fun getEncoded(): ByteArray? {
        return SecureByteArrayOutputStream(true).use {
            try {
                writeObject(it)
                it.flush()
                it.toByteArrayAndWipe()
            } catch (ioe: IOException) {
                LOGGER.log(Level.WARNING, "Exception", ioe)
                return null
            }
        }
    }

    /**
     * Reads the file from an input stream.
     *
     * @param inputStream the input stream to read from
     *
     * @throws IOException if reading fails
     */
    @Throws(IOException::class)
    protected abstract fun readObject(inputStream: InputStream)

    /**
     * Writes the file to an output stream.
     *
     * @param outputStream the output stream to write to
     *
     * @throws IOException if writing fails
     */
    @Throws(IOException::class)
    protected abstract fun writeObject(outputStream: OutputStream)

    companion object {
        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")

        private val serialVersionUID = -4908935713109830409L
    }
}
