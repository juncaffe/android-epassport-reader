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
 * $Id: DG1File.java 1808 2019-03-07 21:32:19Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds.icao

import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.epassport.mrtd.lds.DataGroup
import com.juncaffe.epassport.mrtd.lds.LDSFile.EF_DG1_TAG
import com.juncaffe.epassport.smartcard.tlv.TLVInputStream
import com.juncaffe.epassport.smartcard.tlv.TLVOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class DG1File(inputStream: InputStream, onProgress: PassportService.ProgressListener? = null) : DataGroup(EF_DG1_TAG, inputStream, onProgress) {
    private var mrzInfo: MRZInfo? = null

    fun getMRZInfo(): MRZInfo? {
        return mrzInfo
    }

    @Throws(IOException::class)
    override fun readContent(inputStream: InputStream) {
        val tlvIn = if (inputStream is TLVInputStream) inputStream else TLVInputStream(inputStream)
        tlvIn.skipToTag(MRZ_INFO_TAG)
        val length = tlvIn.readLength()
        mrzInfo = MRZInfo(tlvIn, length)
    }

    override fun toString(): String {
        return "DG1File " + mrzInfo.toString().replace("\n".toRegex(), "").trim { it <= ' ' }
    }

    override fun equals(obj: Any?): Boolean {
        if (obj == null) {
            return false
        }
        if (obj.javaClass != this.javaClass) {
            return false
        }
        val other = obj as DG1File

        return mrzInfo == other.mrzInfo
    }

    override fun hashCode(): Int {
        return 3 * mrzInfo.hashCode() + 57
    }

    @Throws(IOException::class)
    override fun writeContent(out: OutputStream) {
        val tlvOut = if (out is TLVOutputStream) out else TLVOutputStream(out)
        tlvOut.use {
            it.writeTag(MRZ_INFO_TAG)
            val value = mrzInfo?.encoded
            it.writeValue(value)
            it.wipe()
        }
    }

    override fun wipe() {
        mrzInfo?.wipe()
    }

    companion object Companion {
        private const val MRZ_INFO_TAG: Int = 24351
    }
}