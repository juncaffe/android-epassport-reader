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
 * $Id: AbstractImageInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds;

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.PassportService
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_FINGER
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_IRIS
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_PORTRAIT
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_SIGNATURE_OR_MARK
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_UNKNOWN
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.Arrays
import java.util.logging.Level
import java.util.logging.Logger

/**
 * Base class for image infos.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
abstract class AbstractImageInfo: ImageInfo {

  private var type: Int
  private var mimeType: String? = null
  private var imageBytes: ByteArray? = null

  private var imageLength: Int

  private var width: Int
  private var height: Int

  /* PACKAGE ONLY VISIBLE CONSTRUCTORS BELOW */

  /**
   * Constructs a default abstract image info.
   */
  constructor(): this(TYPE_UNKNOWN, 0, 0, null)

  /**
   * Constructs an abstract image info with a type.
   *
   * @param type the type of image
   */
  constructor(type: Int): this (type, 0, 0, null)

  /**
   * Constructs an abstract image info with a type and a mime-type.
   *
   * @param type the type
   * @param mimeType the mime-type string
   */
  constructor(type: Int, mimeType: String): this(type, 0, 0, mimeType)

  /**
   * Constructs an abstract image info with full parameters.
   *
   * @param type the type of image
   * @param width the width
   * @param height the height
   * @param mimeType the mime-type string
   */
  private constructor(type: Int, width: Int, height: Int, mimeType: String?) {
    this.type = type
    this.mimeType = mimeType
    this.width = width
    this.height = height
    this.imageLength = 0
  }

  /* public CONSRTUCTOR BELOW */

  /**
   * Constructs an abstract image info.
   *
   * @param type type of image info
   * @param width width of image
   * @param height height of image
   * @param inputStream encoded image
   * @param imageLength length of encoded image
   * @param mimeType mime-type of encoded image
   *
   * @throws IOException if reading fails
   */
  @Throws(IOException::class)
  constructor(type: Int, width: Int, height: Int, inputStream: InputStream, imageLength: Int, mimeType: String?) {
    this.type = type
    this.mimeType = mimeType
    this.width = width
    this.height = height
    this.imageLength = imageLength
    readImage(inputStream, imageLength)
  }


  /* public METHODS BELOW */

  /**
   * Returns the content-type,
   * where content-type is one of
   * {@link ImageInfo#TYPE_PORTRAIT},
   * {@link ImageInfo#TYPE_FINGER},
   * {@link ImageInfo#TYPE_IRIS},
   * {@link ImageInfo#TYPE_SIGNATURE_OR_MARK}.
   *
   * @return content type
   */
  override fun getType(): Int {
    return type
  }

  /**
   * Returns the mime-type of the encoded image.
   *
   * @return the mime-type of the encoded image
   */
  override fun getMimeType(): String? {
    return mimeType
  }

  /**
   * Returns the width of the image.
   *
   * @return the width of the image
   */
  override fun getWidth(): Int {
    return width
  }

  /**
   * Returns the height of the image.
   *
   * @return the height of the image
   */
  override fun getHeight(): Int {
    return height
  }

  /**
   * Returns the length of the encoded image.
   *
   * @return the length of the encoded image
   */
  override fun getImageLength(): Int {
    if (imageBytes == null) {
      throw IllegalStateException("Cannot get length of null");
    }

    return imageBytes!!.size
  }

  /**
   * Returns a textual representation of this image info.
   *
   * @return a textual representation of this image info
   */
  override fun toString(): String {
    return StringBuilder()
        .append(this.javaClass.getSimpleName())
        .append(" [")
        .append("type: ").append(typeToString(type) + ", ")
        .append("size: ").append(getImageLength())
        .append("]")
        .toString();
  }

  override fun hashCode(): Int {
    var result = 1234567891
    result = 3 * result + 5 * type
    result += 5 * (if(mimeType == null) 1337 else mimeType.hashCode()) + 7
    result += 7 * getImageLength() + 11
    return result
  }

  override fun equals(other: Any?): Boolean {
    try {
      if (other == null) {
        return false
      }
      if (other == this) {
        return true
      }
      if (!other.javaClass.equals(this.javaClass)) {
        return false
      }

      val otherImageInfo = other as AbstractImageInfo
      return (Arrays.equals(getImageBytes(), otherImageInfo.getImageBytes()))
          // && getImageLength() == otherImageInfo.getImageLength()
          && (mimeType == null && otherImageInfo.mimeType == null || mimeType != null && mimeType.equals(otherImageInfo.mimeType))
          && type == otherImageInfo.type;
    } catch (e: Exception) {
      LOGGER.log(Level.WARNING, "Exception" + e);
      return false
    }
  }

  /**
   * Encodes this image info.
   *
   * @return a byte array containing the encoded image info
   */
  override fun getEncoded(): ByteArray? {
    return SecureByteArrayOutputStream(true).use {
      try {
        writeObject(it)
      } catch (ioe: IOException) {
        LOGGER.log(Level.WARNING, "Exception", ioe)
        null
      }
      it.toByteArrayAndWipe()
    }
  }

  /**
   * Returns the encoded image as an input stream.
   *
   * @return an input stream containing the encoded image
   */
  override fun getImageInputStream(): InputStream {
    return imageBytes?.let {
      ByteArrayInputStream(it)
    }?:throw IllegalStateException("Both the byte buffer and the stream are null")
  }

  fun getImageByteArray(): ByteArray? {
    return imageBytes
  }

  /**
   * Clients should call this method after positioning the input stream to the
   * image bytes.
   *
   * @param inputStream input stream
   * @param imageLength image length
   *
   * @throws IOException on error reading the input stream, for example at EOF
   */
  @Throws(IOException::class)
  protected fun readImage(inputStream: InputStream, imageLength: Int) {
    this.imageBytes = ByteArray(imageLength)
    val dataIn = DataInputStream(inputStream)
    var read = 0
    while(read < imageLength) {
      val toRead = minOf(imageLength-read, PassportService.DEFAULT_MAX_BLOCKSIZE)
      read += dataIn.read(this.imageBytes!!, read, toRead)
    }
  }

  /**
   * Writes this image to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  @Throws(IOException::class)
  protected fun writeImage(outputStream: OutputStream) {
    outputStream.write(getImageBytes())
  }

  /**
   * Sets the mime-type.
   *
   * @param mimeType the new mime-type
   */
  protected fun setMimeType(mimeType: String) {
    this.mimeType = mimeType
  }

  /**
   * Sets the type.
   *
   * @param type the new type
   */
  protected fun setType(type: Int) {
    this.type = type
  }

  /**
   * Sets the width of this image.
   *
   * @param width the new width
   */
  protected fun setWidth(width: Int) {
    this.width = width
  }

  /**
   * Sets the height of this image.
   *
   * @param height the new height
   */
  protected fun setHeight(height: Int) {
    this.height = height
  }

  /**
   * Sets the encoded image bytes of this image.
   *
   * @param imageBytes the image bytes
   */
  protected fun setImageBytes(imageBytes: ByteArray?) {
    requireNotNull(imageBytes) { "Cannot set null image bytes" }
    try {
      readImage(ByteArrayInputStream(imageBytes), imageBytes.size)
    } catch (e: IOException) {
      LOGGER.log(Level.WARNING, "Exception", e)
    }
  }

  /**
   * Reads this object from a stream.
   *
   * @param inputStream the stream to read from
   *
   * @throws IOException on error reading from the stream
   */
  @Throws(IOException::class)
  protected abstract fun readObject(inputStream: InputStream)

  /**
   * Writes this object to a stream.
   *
   * @param outputStream the stream to write to
   *
   * @throws IOException on error writing to the stream
   */
  @Throws(IOException::class)
  protected abstract fun writeObject(outputStream: OutputStream)

  /* ONLY PRIVATE METHODS BELOW */

  /**
   * Reads the image bytes from the stream.
   *
   * @return the image bytes
   *
   * @throws IOException on error reading from the stream
   */
  @Throws(IOException::class)
  private fun getImageBytes(): ByteArray {
    val length = getImageLength()
    return getImageInputStream().use {
      val imageBytes = ByteArray(length)
      val imageInputStream = DataInputStream(it)
      imageInputStream.readFully(imageBytes)
      imageBytes
    }
  }

  /**
   * Returns a human readable string from the image type.
   *
   * @param type the image type
   *
   * @return a human readable string
   */
  private fun typeToString(type: Int): String {
    return when (type) {
      TYPE_PORTRAIT -> "Portrait"
      TYPE_SIGNATURE_OR_MARK -> "Signature or usual mark"
      TYPE_FINGER -> "Finger"
      TYPE_IRIS -> "Iris"
      TYPE_UNKNOWN -> "Unknown"
      else -> throw NumberFormatException("Unknown type: " + Integer.toHexString(type))
    }
  }

  fun wipe() {
    this.type = 0
    this.imageBytes?.fill(0)
    this.imageLength = 0
    this.width = 0
    this.height = 0
    this.imageBytes = null
  }

  companion object {
    private const val serialVersionUID = 2870092217269116309L
    val LOGGER = Logger.getLogger("org.jmrtd")
  }
}
