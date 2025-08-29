/**
 * This class implements an output stream in which the data is
 * written into a byte array. The buffer automatically grows as data
 * is written to it.
 * The data can be retrieved using {@code toByteArray()} and
 * {@code toString()}.
 * <p>
 * Closing a {@code ByteArrayOutputStream} has no effect. The methods in
 * this class can be called after the stream has been closed without
 * generating an {@code IOException}.
 *
 * @author  Arthur van Hoff
 * @since   1.0
 */

package com.juncaffe.epassport.io

import java.io.IOException
import java.io.OutputStream
import java.util.Arrays
import java.util.Objects

/**
 * 보안이 필요한 데이터를 메모리 임시 저장 사용이 끝난 후 즉시 0으로 덮어써서 힙 메모리에 흔적이 남지 않도록 하는 OutputStream 구현체
 * - 가변 용량 자동 확장
 * - {@code #toByteArray()}로 변환된 배열은 호출자가 직접 fill(0) 를 이용해 사용 후 즉시 덮어쓰기 해야 함
 *
 * @author JunCaffe
 */
class SecureByteArrayOutputStream: OutputStream {
    private val MAX_CAPACITY: Int = Int.MAX_VALUE - 8
    protected var count = 0
    protected var buf: ByteArray
    private var secureWipe: Boolean = false

    constructor(): this(size = 32, secureWipe = false)

    constructor(secureWipe: Boolean): this(size = 32, secureWipe = secureWipe)

    constructor(size: Int = 32): this(size = size, secureWipe = false)

    constructor(size: Int = 32, secureWipe: Boolean = false) {
        require(this@SecureByteArrayOutputStream.size >= 0) {"Negative initial size: $size" }
        buf = ByteArray(size)
        this.secureWipe = secureWipe
    }

    fun setWipe(secureWipe: Boolean) {
        this.secureWipe = secureWipe
    }

    @Synchronized
    override fun write(b: Int) {
        if (this.count >= buf.size)
            expandCapacity(this.count + 1)
        buf[count] = b.toByte()
        count += 1
    }

    fun writeBytes(b: ByteArray) {
        this.write(b, 0, b.size)
    }

    @Synchronized
    override fun write(b: ByteArray, off: Int, len: Int) {
        Objects.checkFromIndexSize(off, len, b.size)
        if (count + len > buf.size)
            expandCapacity(this.count + len)
        System.arraycopy(b, off, buf, count, len)
        count += len
        if(secureWipe)
            Arrays.fill(b, off, off + len, 0)
    }

    @Synchronized
    @Throws(IOException::class)
    fun writeTo(out: OutputStream) {
        out.write(buf, 0, count)
    }

    fun reset() {
        this.count = 0
    }

    val size: Int get() = this.count

    fun size(): Int = this.count

    fun wipe() {
        this.buf.fill(0)
        this.count = 0
    }

    @Synchronized
    fun toByteArray(): ByteArray = this.buf.copyOf(count)

    @Synchronized
    fun toByteArrayAndWipe(): ByteArray {
        val out = this.buf.copyOf(count)
        this.wipe()
        return out
    }

    private fun expandCapacity(requiredCapacity: Int) {
        if (requiredCapacity <= this.buf.size)
            return

        var proposedCapacity = this.buf.size shl 1
        // overflow 방지 및 최소 필요 용량 보장
        if(proposedCapacity < 0 || proposedCapacity < requiredCapacity)
            proposedCapacity = requiredCapacity

        val allocateCapacity = computeSafeCapacity(proposedCapacity, requiredCapacity)
        val newBuf = this.buf.copyOf(allocateCapacity)
        this.buf.fill(0)
        this.buf = newBuf
    }

    private fun computeSafeCapacity(proposedCapacity: Int, requiredCapacity: Int): Int {
        if (proposedCapacity < 0) throw OutOfMemoryError()
        return when {
            proposedCapacity <= MAX_CAPACITY -> proposedCapacity
            requiredCapacity <= MAX_CAPACITY -> requiredCapacity
            else -> throw OutOfMemoryError()
        }
    }
}