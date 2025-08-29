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
 * $Id: MRZInfo.java 1898 2025-06-04 12:05:45Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds.icao

import com.juncaffe.epassport.extension.spaceTrim
import com.juncaffe.epassport.mrtd.lds.AbstractLDSInfo
import com.juncaffe.epassport.smartcard.data.Gender
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer

class MRZInfo(inputStream: InputStream, length: Int): AbstractLDSInfo() {

    val PADDING_BYTE = '<'.code.toByte()
    val SPACE_BYTE = ' '.code.toByte()

    private val td3MRZMap = LinkedHashMap<MRZField, ByteArray>()

    /**®
     * 여권 NFC MRZ 생성
     *
     * @param inputStream 여권 NFC의 DG1
     * @param length
     */
    init {
        try {
            readObject(inputStream, length)
        } catch (ioe: IOException) {
            ioe.printStackTrace()
            throw IllegalArgumentException(ioe)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }


    enum class MRZField(val offset: Int, val length: Int) {
        DOCUMENT_CODE(0, 2), // 문서번호
        ISSUSING_STATE(2, 3), // 여권 상태
        NAMES(5, 39), // 이름
        DOCUMENT_NUMBER(44, 9), // 여권 번호
        DOCUMENT_NUMBER_CHECK_DIGIT(53, 1), // 여권번호 검증 숫자
        NATIONALITY(54, 3), // 국가코드
        DATE_OF_BIRTH(57, 6), // 생년월일
        DATE_OF_BIRTH_CHECK_DIGIT(63, 1), // 생년월일 검증 숫자
        GENDER(64, 1), // 성별
        DATE_OF_EXPRITY(65, 6), // 여권 만료일
        DATE_OF_EXPRITY_CHECK_DIGIT(71, 1), // 여권 만료일 검증 숫자
        PERSONAL_NUMBER(72, 14), // 개인번호
        PERSONAL_NUMBER_CHECK_DIGIT(86, 1), // 개인번호 검증 숫자
        COMPOSITE_CHECK_DIGIT(87, 1)  // 여권번호/생년월일/여권만료일/개인번호의 검증 숫자를 합쳐서 최종 검증
    }

    /**
     * 생년월일
     *
     * @return
     */
    fun getDateOfBirth(): ByteArray? {
        return td3MRZMap[MRZField.DATE_OF_BIRTH]?:byteArrayOf()
    }

    /**
     * 여권 만료일
     *
     * @return
     */
    fun getDateOfExpiry(): ByteArray? {
        return td3MRZMap[MRZField.DATE_OF_EXPRITY]?:byteArrayOf()
    }

    /**
     * 여권 번호
     *
     * @return
     */
    fun getDocumentNumber(): ByteArray? {
        return td3MRZMap[MRZField.DOCUMENT_NUMBER]?:byteArrayOf()
    }

    /**
     * 여권 타입 코드
     *
     * @return
     */
    fun getDocumentCode(): ByteArray? {
        return td3MRZMap[MRZField.DOCUMENT_CODE]?:byteArrayOf()
    }

    /**
     * 여권 발행 3자리 국가코드
     *
     * @return
     */
    fun getIssuingState(): ByteArray? {
        return mrzFormat(td3MRZMap[MRZField.ISSUSING_STATE], 3)
    }

    /**
     * 성
     *
     * @return name
     */
    fun getPrimaryIdentifier(): ByteArray? {
        val (primaryIdentifier, secondaryIdentifier) = readNameIdentifiers(td3MRZMap[MRZField.NAMES]?:byteArrayOf())
        secondaryIdentifier.fill(0)
        return primaryIdentifier
    }

    /**
     * 이름
     *
     * @return
     */
    fun getSecondaryIdentifier(): ByteArray? {
        val (primaryIdentifier, secondaryIdentifier) = readNameIdentifiers(td3MRZMap[MRZField.NAMES]?:byteArrayOf())
        primaryIdentifier.fill(0)
        return secondaryIdentifier
    }

    /**
     * 3자리 국가코드
     *
     * @return
     */
    fun getNationality(): ByteArray? {
        return mrzFormat(td3MRZMap[MRZField.NATIONALITY], 3)
    }

    /**
     * Personal Number
     *
     * @return
     */
    fun getPersonalNumber(): ByteArray? {
        val personalNumber = td3MRZMap[MRZField.PERSONAL_NUMBER]
        return if (personalNumber!!.size > 14) {
            trimTrailingFillerChars(personalNumber.sliceArray(0 until 14))
        } else {
            trimTrailingFillerChars(personalNumber)
        }
    }

    /**
     * 성별 (M:남자, F:여자)
     *
     * @return
     */
    fun getGender(): Gender? {
        val gender = td3MRZMap[MRZField.GENDER]
        return when(gender?.toString(Charsets.UTF_8)) {
            "M" -> Gender.MALE
            "F" -> Gender.FEMALE
            else -> Gender.UNKNOWN
        }
    }

    /**
     * MRZ 정보를 텍스트로 표시
     *
     * @return
     *
     * @see Object.toString
     */
    override fun toString(): String {
        var str = ""
        td3MRZMap.entries.forEachIndexed { idx, (key, value) ->
            if(idx > 0)
                str += ", "
            str += "${key.name}=${String(value, Charsets.UTF_8)}"
        }
        return str
    }

    /**
     * MRZ 정보의 해시코드
     *
     * @return
     */
    override fun hashCode(): Int {
        return 2 * toString().hashCode() + 53
    }

    /**
     * MRZ 비교
     *
     * @param obj
     *
     * @return
     */
    override fun equals(obj: Any?): Boolean {
        if (obj == null) {
            return false
        }
        if (obj.javaClass != this.javaClass) {
            return false
        }
        val other = obj as MRZInfo
        return td3MRZMap.all { (key, mrzField) -> other.td3MRZMap[key]?.contentEquals(mrzField) == true }
    }

    /**
     * TD3 여권 NFC 태깅해서 받은 데이터 처리
     * @param inputStream
     * @param length
     *
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun readObject(inputStream: InputStream, length: Int) {
        td3MRZMap.values.forEach { it.fill(0) }
        td3MRZMap.clear()
        var readSize = 0
        inputStream.use { input ->
            MRZField.entries.forEach {
                val mrzField = ByteArray(it.length)
                readSize += input.read(mrzField, 0, it.length)
                td3MRZMap.put(it, mrzField)
            }
        }

        // TD3 문서는 길이 : 88, P 로 시작함
        require(length == 88 && td3MRZMap[MRZField.DOCUMENT_CODE]?.first() == 'P'.code.toByte()) { "Wrong document code" }
        // 문서 타입과 옵션데이터가 맞지 않을때 예외 발생
        require((td3MRZMap[MRZField.PERSONAL_NUMBER]?.size ?: 0) <= 15) { "Wrong optional data length" }
    }

    /**
     * TD3 MRZ DataOutputStream 에 저장
     *
     * @param outputStream
     */
    @Throws(IOException::class)
    override fun writeObject(outputStream: OutputStream) {
        val dataOut = if (outputStream is DataOutputStream) outputStream else DataOutputStream(outputStream)

        td3MRZMap.forEach { (key, value) ->
            dataOut.write(mrzFormat(value, key.length))
        }
    }

    /**
     * 성과 이름 추출
     * 성과 이름은 << 으로 구분됨 공백은 < 로 채워짐
     * @param mrzName
     */
    private fun readNameIdentifiers(mrzName: ByteArray): Pair<ByteArray, ByteArray> {
        var delimIndex = -1
        for (idx in 0 until mrzName.size - 1) {
            if (mrzName[idx] == PADDING_BYTE && mrzName[idx + 1] == PADDING_BYTE) {
                delimIndex = idx
                break
            }
        }
        if (delimIndex < 0) {
            val primaryIdentifier = trimTrailingFillerChars(mrzName).map {
                if(it == PADDING_BYTE)
                    SPACE_BYTE
                else
                    it
            }.toByteArray()
            val secondaryIdentifier = byteArrayOf()
            return Pair(primaryIdentifier, secondaryIdentifier)
        }else {
            val primary = mrzName.sliceArray(0 until delimIndex)
            val primaryIdentifier = trimTrailingFillerChars(primary).map {
                if(it == PADDING_BYTE)
                    SPACE_BYTE
                else
                    it
            }.toByteArray()

            val rest = mrzName.sliceArray(delimIndex+2 .. mrzName.lastIndex)
            // 이름 추출 (좌우 ' ', '<' 제거)
            val secondaryIdentifier = trimTrailingFillerChars(rest).map {
                if(it == PADDING_BYTE)
                    SPACE_BYTE
                else
                    it
            }.toByteArray()
            return Pair(primaryIdentifier, secondaryIdentifier)
        }
    }

    /**
     * 이름을 MRZ 포맷으로 변환
     * 성과 이름 사이는 << 로 구분, width 보다 길이가 짧을 경우 나머지는 < 로 채움
     *
     * @param primaryIdentifier 성
     * @param secondaryIdentifier 이름
     * @param width MRZ 포맷 길이
     *
     * @return MRZ 포맷 이름의 ByteArray
     */
    private fun nameToByteArray(primaryIdentifier: ByteArray?, secondaryIdentifier: ByteArray?, width: Int): ByteArray {
        val buffer = ByteBuffer.allocate(width*2)
        primaryIdentifier?.let {
            for(idx in it.indices) {
                val b = primaryIdentifier[idx]
                if(idx > 0 && b == SPACE_BYTE || b == PADDING_BYTE)
                    buffer.put(PADDING_BYTE)
                else
                    buffer.put(b)
            }
        }
        if (secondaryIdentifier != null && secondaryIdentifier.isNotEmpty()) {
            buffer.put("<<".toByteArray())
            for (idx in secondaryIdentifier.indices) {
                val b = secondaryIdentifier[idx]
                if (idx > 0 && b == SPACE_BYTE || b == PADDING_BYTE)
                    buffer.put(PADDING_BYTE)
                else
                    buffer.put(b)
            }
        }
        buffer.flip()
        val result = ByteArray(buffer.remaining())
        buffer.get(result)
        buffer.clear()
        while(buffer.hasRemaining()) {
            buffer.put(0)
        }
        return mrzFormat(result, width)
    }

    /**
     * 양끝에 공백을 제거하고 소문자는 대문자로 치환
     * A-Z, 0-9, < 를 제외한 나머지는 < 로 치환
     * byteArray width 보다 작으면 나머지 공백에는 < 로 채움
     *
     * @param byteArray
     * @param width
     *
     * @return
     */
    private fun mrzFormat(bytes: ByteArray?, width: Int): ByteArray {
        if(bytes == null)
            return ByteArray(width) { PADDING_BYTE }
        require(bytes.size <= width) { "Argument too wide (${bytes.size} > $width)" }
        val replaceBytes = bytes.copyOf().map { byte ->
            when {
                byte in 0x61.toByte()..0x7A.toByte() -> (byte - 32).toByte() // a~z 소문자 -> 대문자
                byte in 0x41.toByte()..0x5A.toByte() || byte in 0x30.toByte()..0x39.toByte() -> byte // A~Z, 0~9 는 그대로 반환
                else -> PADDING_BYTE // '<'
            }
        }.toByteArray()
        val result = ByteArray(width) { index ->
            if (index < replaceBytes.size)
                replaceBytes[index]
            else
                PADDING_BYTE
        }
        replaceBytes.fill(0)
        return result
    }

    /**
     * '<'를 ' ' 으로 변환 후 좌우 공백 제거
     *
     * @param bytes
     *
     * @return
     */
    private fun trimTrailingFillerChars(bytes: ByteArray): ByteArray {
        val trimmed = bytes.spaceTrim()
        for (i in trimmed.indices.reversed()) {
            if (trimmed[i] == PADDING_BYTE) {
                trimmed[i] = SPACE_BYTE
            } else {
                break
            }
        }
        val result = trimmed.spaceTrim()
        trimmed.fill(0)
        return result
    }

    fun wipe() {
        td3MRZMap.values.forEach {
            it.fill(0)
        }
        td3MRZMap.clear()
        encoded?.fill(0)
    }
}