package com.juncaffe.extension

import java.io.ByteArrayOutputStream
import java.io.InputStream

/*****************************************************************************
 * 업 무 명    :
 ************************** 변 경 이 력 ****************************************
 * 번호  작 업 자    작  업  일                       변경내용
 *******************************************************************************
 *   1  조현준     2025.08.07              최초생성.
 ******************************************************************************/
internal fun InputStream.getBytes(): ByteArray {
    val byteBuffer = ByteArrayOutputStream()
    val bufferSize = 1024
    val buffer = ByteArray(bufferSize)
    var len = 0
    while (read(buffer).also { len = it } != -1) {
        byteBuffer.write(buffer, 0, len)
    }
    return byteBuffer.toByteArray()
}