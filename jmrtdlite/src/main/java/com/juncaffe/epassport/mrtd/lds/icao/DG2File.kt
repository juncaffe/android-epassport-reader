/*
 * JMRTD - A Java API for accessing machine readable travel documents.
 *
 * Copyright (C) 2006 - 2025  The JMRTD team
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
 * $Id: DG2File.java 1897 2025-05-27 12:34:36Z martijno $
 */
package com.juncaffe.epassport.mrtd.lds.icao

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.epassport.mrtd.cbeff.ISO781611
import com.juncaffe.epassport.mrtd.cbeff.StandardBiometricHeader
import com.juncaffe.epassport.mrtd.lds.DataGroup
import com.juncaffe.epassport.mrtd.lds.LDSFile.EF_DG2_TAG
import com.juncaffe.epassport.mrtd.lds.iso19794.FaceInfo
import com.juncaffe.epassport.smartcard.tlv.TLVInputStream
import com.juncaffe.epassport.smartcard.tlv.TLVOutputStream
import com.juncaffe.epassport.smartcard.tlv.TLVUtil
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.logging.Logger

class DG2File(inputStream: InputStream, onProgress: PassportService.ProgressListener? = null) : DataGroup(EF_DG2_TAG, inputStream, onProgress) {
    private val LOGGER: Logger = Logger.getLogger("org.jmrtd")

    private var _faceInfos: MutableList<FaceInfo>? = null
    var faceInfos = _faceInfos?.toList()

    @Throws(IOException::class)
    override fun readContent(inputStream: InputStream) {
        if(_faceInfos == null)
            _faceInfos = mutableListOf<FaceInfo>()
        val tlvIn = if (inputStream is TLVInputStream) inputStream else TLVInputStream(inputStream)
        val groupTag = tlvIn.readTag()
        require(groupTag == ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG) { "Expected tag ${Integer.toHexString(ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG)}, found ${Integer.toHexString(groupTag)}"}

        tlvIn.readLength()
        val countTag = tlvIn.readTag()
        require(countTag == ISO781611.BIOMETRIC_INFO_COUNT_TAG) { "Expected tag ${Integer.toHexString(ISO781611.BIOMETRIC_INFO_COUNT_TAG)}, found ${Integer.toHexString(countTag)}"}
        val countLen = tlvIn.readLength()
        require(countLen == 1) { "BIT count length must be 1, got $countLen"}
        val count = (tlvIn.readValue()[0].toInt() and 0xFF)

        repeat(count) { index ->
            readBIT(tlvIn, index)
        }
    }

    @Throws(IOException::class)
    private fun readBIT(tlvIn: TLVInputStream, index: Int) {
        val infoTag = tlvIn.readTag()
        require(infoTag == ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG) { "Expected tag ${Integer.toHexString(ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG)}, found ${Integer.toHexString(infoTag)}"}
        val infoLen = tlvIn.readLength()

        val bhtTag = tlvIn.readTag()
        require((bhtTag and 0xA0) == 0xA0) { "Unsupported BHT tag ${Integer.toHexString(bhtTag)}"}
        val bhtLen = tlvIn.readLength()

        val sbh = readBHT(tlvIn, bhtTag, bhtLen)
        // FaceInfo
        val bdbTag = tlvIn.readTag()
        require(bdbTag == ISO781611.BIOMETRIC_DATA_BLOCK_TAG) { "Expected tag ${Integer.toHexString(ISO781611.BIOMETRIC_DATA_BLOCK_TAG)}, found ${Integer.toHexString(bdbTag)}" }
        val bdbLen = tlvIn.readLength()
        val face = FaceInfo(sbh, tlvIn)
        _faceInfos!! += face
        inc(bdbLen)
    }

    @Throws(IOException::class)
    private fun readBHT(tlvIn: TLVInputStream, bhtTag: Int, bhtLen: Int): StandardBiometricHeader {
        val expected = (ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG and 0xFF)
        if(bhtTag != expected)
            LOGGER.warning("Expected tag ${Integer.toHexString(ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG)}, found ${Integer.toHexString(bhtTag)}")

        val elements = mutableMapOf<Int, ByteArray>()
        var consumed = 0
        while(consumed < bhtLen) {
            val tag = tlvIn.readTag()
            consumed += TLVUtil.getTagLength(tag)
            val len = tlvIn.readLength()
            consumed += TLVUtil.getLengthLength(len)
            val value = tlvIn.readValue()
            consumed += value.size
            elements[tag] = value
        }
        return StandardBiometricHeader(elements)
    }

    @Throws(IOException::class)
    override fun writeContent(outputStream: OutputStream) {
        val tlvOut = if (outputStream is TLVOutputStream) outputStream else TLVOutputStream(outputStream)
        tlvOut.writeTag(ISO781611.BIOMETRIC_INFORMATION_GROUP_TEMPLATE_TAG)
        val dg2Out = SecureByteArrayOutputStream()
        TLVOutputStream(dg2Out).use { out ->
            // 02 (count)
            out.writeTag(ISO781611.BIOMETRIC_INFO_COUNT_TAG)
            out.writeValue(byteArrayOf(_faceInfos!!.size.toByte()))
            // BIT(7F60)
            _faceInfos!!.forEach { face ->
                // BIT : BIOMETRIC INFORMATION TEMPLATE 시작
                out.writeTag(ISO781611.BIOMETRIC_INFORMATION_TEMPLATE_TAG)

                val bitValue = SecureByteArrayOutputStream()
                TLVOutputStream(bitValue).use { bitOut ->
                    val sbh = face.getStandardBiometricHeader()
                    val bhtTag = ISO781611.BIOMETRIC_HEADER_TEMPLATE_BASE_TAG
                    bitOut.writeTag(bhtTag)

                    val bhtValue = SecureByteArrayOutputStream()
                    TLVOutputStream(bhtValue).use { bhtOut ->
                        sbh.elements.forEach { (tag, value) ->
                            bhtOut.writeTag(tag)
                            bhtOut.writeValue(value)
                        }
                    }
                    bitOut.writeValue(bhtValue.toByteArrayAndWipe())

                    bitOut.writeTag(ISO781611.BIOMETRIC_DATA_BLOCK_TAG)
                    val faceValue = SecureByteArrayOutputStream()
                    face.writeObject(faceValue)
                    bitOut.writeValue(faceValue.toByteArrayAndWipe())
                }
                out.writeValue(bitValue.toByteArrayAndWipe())
            }
        }
        tlvOut.writeValue(dg2Out.toByteArrayAndWipe())
    }

    override fun wipe() {
        _faceInfos?.forEach {
            it.wipe()
        }
    }

    /**
     * Returns a textual representation of this file.
     *
     * @return a textual representation of this file
     */
    override fun toString(): String {
        return "DG2File [${_faceInfos?.joinToString { it.toString() }}]"
    }

    override fun equals(other: Any?): Boolean {
        if(this === other) return true
        if(other !is DG2File) return false
        return _faceInfos == other._faceInfos
    }

    override fun hashCode(): Int {
        var result = 1234567891
        _faceInfos?.forEach {
            result = 5 * (result + it.hashCode()) + 7
        }
        result = 17 * result + 123
        return 7 * result + 11
    }
}
