package com.juncaffe.epassport.mrtd.utils

internal object MRZUtils {

    /**
     * MRZ 체크디짓 계산
     *
     * @param str
     *
     * @return 체크디짓 (0 ~ 9)
     */
    @JvmStatic
    fun checkDigit(str: ByteArray): Byte {
        return checkDigit(str, false)
    }

    /**
     * MRZ 체크 디지트 계산 (7, 3, 1)
     * `preferFillerOverZero` 가 `true` 이면 0은 '<'으로 반환됨.
     *
     * @param bytes
     * @param preferFillerOverZero 0 을 '<' 로 변환 여부
     *
     * @return
     */
    fun checkDigit(bytes: ByteArray, preferFillerOverZero: Boolean): Byte {
        return try {
            val weights = intArrayOf(7, 3, 1)
            var result = 0
            for(idx in bytes.indices) {
                result = (result + weights[idx % 3] * decodeMRZDigit(bytes[idx])) % 10
            }
            check(result <= 9) { "Error in computing check digit."}
            if(preferFillerOverZero && result == 0) {
                0x3C.toByte() // 0x3C == '<'
            }else {
                (result + 0x30.toByte()).toByte() // 0x30 == '0'
            }
        } catch (e: Exception) {
            throw IllegalArgumentException("Error in computing check digit", e)
        }
    }

    /**
     * 여권 번호를 9자리로 패딩
     *
     * @param documentNumber 여권 번호
     * @return 9자리 '<' 문자로 패딩된 결과
     */
    fun fixDocumentNumber(documentNumber: ByteArray): ByteArray {
        val result = ByteArray(9) { idx ->
            if(idx < documentNumber.size)
                documentNumber[idx]
            else
                0x3C.toByte()
        }
        documentNumber.fill(0)
        return result
    }

    /**
     * 체크 디지트 계산을 이해 MRZ 문자의 숫자 값을 찾음
     *
     * @param chByte
     *
     * @return
     *
     * @throws NumberFormatException 여권에 사용가능한 문자가 아님
     */
    private fun decodeMRZDigit(chByte: Byte): Int {
        return when (chByte) {
            0x3C.toByte(), 0x30.toByte() -> 0 // '<' or '0'
            0x31.toByte() -> 1 // '1'
            0x32.toByte() -> 2 // '2'
            0x33.toByte() -> 3 // '3'
            0x34.toByte() -> 4 // '4'
            0x35.toByte() -> 5 // '5'
            0x36.toByte() -> 6 // '6'
            0x37.toByte() -> 7 // '7'
            0x38.toByte() -> 8 // '8'
            0x39.toByte() -> 9 // '9'
            0x61.toByte(), 0x41.toByte() -> 10 // 'a' or 'A'
            0x62.toByte(), 0x42.toByte() -> 11 // 'b' or 'B'
            0x63.toByte(), 0x43.toByte() -> 12 // 'c' or 'C'
            0x64.toByte(), 0x44.toByte() -> 13 // 'd' or 'D'
            0x65.toByte(), 0x45.toByte() -> 14 // 'e' or 'E'
            0x66.toByte(), 0x46.toByte() -> 15 // 'f' or 'F'
            0x67.toByte(), 0x47.toByte() -> 16 // 'g' or 'G'
            0x68.toByte(), 0x48.toByte() -> 17 // 'h' or 'H'
            0x69.toByte(), 0x49.toByte() -> 18 // 'i' or 'I'
            0x6A.toByte(), 0x4A.toByte() -> 19 // 'j' or 'J'
            0x6B.toByte(), 0x4B.toByte() -> 20 // 'k' or 'K'
            0x6C.toByte(), 0x4C.toByte() -> 21 // 'l' or 'L'
            0x6D.toByte(), 0x4D.toByte() -> 22 // 'm' or 'M'
            0x6E.toByte(), 0x4E.toByte() -> 23 // 'n' or 'N'
            0x6F.toByte(), 0x4F.toByte() -> 24 // 'o' or 'O'
            0x70.toByte(), 0x50.toByte() -> 25 // 'p' or 'P'
            0x71.toByte(), 0x51.toByte() -> 26 // 'q' or 'Q'
            0x72.toByte(), 0x52.toByte() -> 27 // 'r' or 'R'
            0x73.toByte(), 0x53.toByte() -> 28 // 's' or 'S'
            0x74.toByte(), 0x54.toByte() -> 29 // 't' or 'T'
            0x75.toByte(), 0x55.toByte() -> 30 // 'u' or 'U'
            0x76.toByte(), 0x56.toByte() -> 31 // 'v' or 'V'
            0x77.toByte(), 0x57.toByte() -> 32 // 'w' or 'W'
            0x78.toByte(), 0x58.toByte() -> 33 // 'x' or 'X'
            0x79.toByte(), 0x59.toByte() -> 34 // 'y' or 'Y'
            0x7A.toByte(), 0x5A.toByte() -> 35 // 'z' or 'Z'
            else -> throw NumberFormatException("Could not decode MRZ character " + chByte + " ('" + Char(chByte.toUShort()).toString() + "')")
        }
    }
}