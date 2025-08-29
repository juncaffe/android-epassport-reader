package com.juncaffe.epassport.extension

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * 양 끝의 문자 제거 기본값 0x20 (space)
 */
internal fun ByteArray.trim(chByte: Byte = 0x20.toByte()): ByteArray {
    return this.dropWhile { it == chByte }
        .dropLastWhile { it == chByte }
        .toByteArray()
}

/**
 * 공백 문자 제거 0x00 ~ 0x20 (null ~ space)
 */
internal fun ByteArray.spaceTrim(): ByteArray {
    return this.dropWhile { it <= 0x20.toByte() }
        .dropLastWhile { it <= 0x20.toByte() }
        .toByteArray()
}

/**
 * ByteArrayOutputStream 사용한 메모리 0으로 덮어쓰기 (클리어)
 */
internal fun ByteArrayOutputStream.wipe() {
    // 메모리 덮어쓰기 (클리어)
    val bufferField = ByteArrayOutputStream::class.java.getDeclaredField("buf")
    bufferField.isAccessible = true
    val internalBuffer = bufferField.get(this) as ByteArray
    synchronized(this) {
        internalBuffer.fill(0)
        this.reset()
    }
}

/**
 * ByteArrayOutputStream 사용한 메모리 0으로 덮어쓰기 (클리어)
 */
internal fun ByteArrayInputStream.wipe() {
    // 메모리 덮어쓰기 (클리어)
    val bufferField = ByteArrayInputStream::class.java.getDeclaredField("buf")
    bufferField.isAccessible = true
    val internalBuffer = bufferField.get(this) as ByteArray
    synchronized(this) {
        internalBuffer.fill(0)
        this.reset()
    }
}