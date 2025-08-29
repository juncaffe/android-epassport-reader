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
 * $Id: FaceImageInfo.java 1808 2019-03-07 21:32:19Z martijno $
 */
package com.juncaffe.epassport.mrtd.lds.iso19794

import com.juncaffe.epassport.io.SecureByteArrayOutputStream
import com.juncaffe.epassport.mrtd.lds.AbstractImageInfo
import com.juncaffe.epassport.mrtd.lds.ImageInfo.JPEG2000_MIME_TYPE
import com.juncaffe.epassport.mrtd.lds.ImageInfo.JPEG_MIME_TYPE
import com.juncaffe.epassport.mrtd.lds.ImageInfo.TYPE_PORTRAIT
import com.juncaffe.epassport.smartcard.data.Gender
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.Serializable
import java.util.logging.Logger

/**
 * Data structure for storing facial image data. This represents
 * a facial record data block as specified in Section 5.5, 5.6,
 * and 5.7 of ISO/IEC FCD 19794-5 (2004-03-22, AKA Annex D).
 *
 * A facial record data block contains a single facial image.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1808 $
 */
class FaceImageInfo : AbstractImageInfo {
    /**
     * Eye color code based on Section 5.5.4 of ISO 19794-5.
     * Creates an eye color.
     *
     * @param code the ISO19794-5 integer code for the color
     */
    enum class EyeColor(private val code: Int) {
        UNSPECIFIED(EYE_COLOR_UNSPECIFIED),
        BLACK(EYE_COLOR_BLACK),
        BLUE(EYE_COLOR_BLUE),
        BROWN(EYE_COLOR_BROWN),
        GRAY(EYE_COLOR_GRAY),
        GREEN(EYE_COLOR_GREEN),
        MULTI_COLORED(EYE_COLOR_MULTI_COLORED),
        PINK(EYE_COLOR_PINK),
        UNKNOWN(EYE_COLOR_UNKNOWN);

        /**
         * Returns the integer code to use in ISO19794-5 encoding for this color.
         *
         * @return the integer code
         */
        fun toInt(): Int {
            return code
        }

        companion object {
            /**
             * Returns an eye color value for the given code.
             *
             * @param i the integer code for a color
             *
             * @return the color value
             */
            fun toEyeColor(i: Int): EyeColor {
                for (c in entries) {
                    if (c.toInt() == i) {
                        return c
                    }
                }
                return EyeColor.UNKNOWN
            }
        }
    }

    /**
     * Hair color code based on Section 5.5.5 of ISO 19794-5.
     * Creates a hair color.
     *
     * @param code the integer code for a color
     */
    enum class HairColor(private val code: Int) {
        UNSPECIFIED(HAIR_COLOR_UNSPECIFIED),
        BALD(HAIR_COLOR_BALD),
        BLACK(HAIR_COLOR_BLACK),
        BLONDE(HAIR_COLOR_BLONDE),
        BROWN(HAIR_COLOR_BROWN),
        GRAY(HAIR_COLOR_GRAY),
        WHITE(HAIR_COLOR_WHITE),
        RED(HAIR_COLOR_RED),
        GREEN(HAIR_COLOR_GREEN),
        BLUE(HAIR_COLOR_BLUE),
        UNKNOWN(HAIR_COLOR_UNKNOWN);

        /**
         * Returns the code for this hair color.
         *
         * @return the code
         */
        fun toInt(): Int {
            return code
        }

        companion object {
            /**
             * Returns a hair color value for the given code.
             *
             * @param i the integer code for a color
             *
             * @return the color value
             */
            fun toHairColor(i: Int): HairColor {
                for (c in entries) {
                    if (c.toInt() == i) {
                        return c
                    }
                }

                return HairColor.UNKNOWN
            }
        }
    }

    /** Feature flags meaning based on Section 5.5.6 of ISO 19794-5.  */
    enum class Features {
        FEATURES_ARE_SPECIFIED,
        GLASSES,
        MOUSTACHE,
        BEARD,
        TEETH_VISIBLE,
        BLINK,
        MOUTH_OPEN,
        LEFT_EYE_PATCH,
        RIGHT_EYE_PATCH,
        DARK_GLASSES,
        DISTORTING_MEDICAL_CONDITION
    }

    /** Expression code based on Section 5.5.7 of ISO 19794-5.  */
    enum class Expression {
        UNSPECIFIED,
        NEUTRAL,
        SMILE_CLOSED,
        SMILE_OPEN,
        RAISED_EYEBROWS,
        EYES_LOOKING_AWAY,
        SQUINTING,
        FROWNING
    }

    /** Face image type code based on Section 5.7.1 of ISO 19794-5.  */
    enum class FaceImageType {
        BASIC,
        FULL_FRONTAL,
        TOKEN_FRONTAL
    }

    /** Image data type code based on Section 5.7.2 of ISO 19794-5.  */
    enum class ImageDataType {
        TYPE_JPEG,
        TYPE_JPEG2000
    }

    /** Color space code based on Section 5.7.4 of ISO 19794-5.  */
    enum class ImageColorSpace {
        UNSPECIFIED,
        RGB24,
        YUV422,
        GRAY8,
        OTHER
    }

    /** Source type based on Section 5.7.6 of ISO 19794-5.  */
    enum class SourceType {
        UNSPECIFIED,
        STATIC_PHOTO_UNKNOWN_SOURCE,
        STATIC_PHOTO_DIGITAL_CAM,
        STATIC_PHOTO_SCANNER,
        VIDEO_FRAME_UNKNOWN_SOURCE,
        VIDEO_FRAME_ANALOG_CAM,
        VIDEO_FRAME_DIGITAL_CAM,
        UNKNOWN
    }

    private var recordLength: Long = 0

    /**
     * Returns the gender
     * (male, female, etc).
     *
     * @return gender
     */
    var gender: Gender? = null
        private set

    /**
     * Returns the eye color
     * (black, blue, brown, etc).
     *
     * @return eye color
     */
    var eyeColor: EyeColor? = null
        private set

    /**
     * Returns the hair color
     * (bald, black, blonde, etc).
     *
     * @return hair color
     */
    var hairColor: Int = 0
        private set

    /**
     * Returns the feature mask.
     *
     * @return feature mask
     */
    var featureMask: Int = 0
        private set

    /**
     * Returns the expression
     * (neutral, smiling, eyebrow raised, etc).
     *
     * @return expression
     */
    var expression: Int = 0
        private set
    private lateinit var poseAngle: IntArray
    private lateinit var poseAngleUncertainty: IntArray

    /**
     * Returns the available feature points of this face.
     *
     * @return feature points
     */
    var featurePoints: Array<FeaturePoint>? = null

    /**
     * Returns the face image type
     * (full frontal, token frontal, etc).
     *
     * @return face image type
     */
    var faceImageType: Int = 0
        private set

    /**
     * Returns the image data type.
     *
     * @return image data type
     */
    var imageDataType: Int = 0
        private set

    /**
     * Returns the image color space
     * (rgb, grayscale, etc).
     *
     * @return image color space
     */
    var colorSpace: Int = 0
        private set

    /**
     * Returns the source type
     * (camera, scanner, etc).
     *
     * @return source type
     */
    var sourceType: Int = 0
        private set

    /**
     * Returns the device type.
     *
     * @return device type
     */
    var deviceType: Int = 0
        private set

    /**
     * Returns the quality as unsigned integer.
     *
     * @return quality
     */
    var quality: Int = 0
        private set

    /**
     * Constructs a new face information data structure instance.
     *
     * @param gender gender
     * @param eyeColor eye color
     * @param featureMask feature mask (least significant 3 bytes)
     * @param hairColor hair color
     * @param expression expression
     * @param poseAngle (encoded) pose angle
     * @param poseAngleUncertainty pose angle uncertainty
     * @param faceImageType face image type
     * @param colorSpace color space
     * @param sourceType source type
     * @param deviceType capture device type (unspecified is `0x00`)
     * @param quality quality
     * @param featurePoints feature points
     * @param width width
     * @param height height
     * @param imageInputStream encoded image bytes
     * @param imageLength length of encoded image
     * @param imageDataType either IMAGE_DATA_TYPE_JPEG or IMAGE_DATA_TYPE_JPEG2000
     *
     * @throws IOException on error reading input
     */
    constructor(
        gender: Gender?, eyeColor: EyeColor?,
        featureMask: Int,
        hairColor: Int,
        expression: Int,
        poseAngle: IntArray, poseAngleUncertainty: IntArray,
        faceImageType: Int,
        colorSpace: Int,
        sourceType: Int,
        deviceType: Int,
        quality: Int,
        featurePoints: Array<FeaturePoint>?,
        width: Int, height: Int,
        imageInputStream: InputStream, imageLength: Int, imageDataType: Int
    ) : super(TYPE_PORTRAIT, width, height, imageInputStream, imageLength, toMimeType(imageDataType)) {
        requireNotNull(imageInputStream) { "Null image" }
        this.gender = if (gender == null) Gender.UNSPECIFIED else gender
        this.eyeColor = if (eyeColor == null) EyeColor.UNSPECIFIED else eyeColor
        this.featureMask = featureMask
        this.hairColor = hairColor
        this.expression = expression
        this.colorSpace = colorSpace
        this.sourceType = sourceType
        this.deviceType = deviceType
        val featurePointCount = if (featurePoints == null) 0 else featurePoints.size
        this.featurePoints = arrayOfNulls<FeaturePoint>(featurePointCount) as Array<FeaturePoint>?
        if (featurePointCount > 0) {
            System.arraycopy(featurePoints, 0, this.featurePoints, 0, featurePointCount)
        }

        this.poseAngle = IntArray(3)
        System.arraycopy(poseAngle, 0, this.poseAngle, 0, 3)
        this.poseAngleUncertainty = IntArray(3)
        System.arraycopy(poseAngleUncertainty, 0, this.poseAngleUncertainty, 0, 3)
        this.imageDataType = imageDataType
        this.recordLength = 20L + 8 * featurePointCount + 12L + imageLength

        this.faceImageType = faceImageType
        this.colorSpace = colorSpace
        this.sourceType = sourceType
        this.deviceType = deviceType
        this.quality = quality
    }

    /**
     * Constructs a new face information structure from binary encoding.
     *
     * @param inputStream an input stream
     *
     * @throws IOException if input cannot be read
     */
    constructor(inputStream: InputStream) : super(TYPE_PORTRAIT) {
        readObject(inputStream)
    }

    @Throws(IOException::class)
    override fun readObject(inputStream: InputStream) {
        val dataIn = DataInputStream(inputStream)

        /* Facial Information Block (20), see ISO 19794-5 5.5 */
        recordLength = dataIn.readInt().toLong() and 0xFFFFFFFFL /* 4 */
        val featurePointCount = dataIn.readUnsignedShort() /* +2 = 6 */
        gender = Gender.getInstance(dataIn.readUnsignedByte()) /* +1 = 7 */
        eyeColor = EyeColor.Companion.toEyeColor(dataIn.readUnsignedByte()) /* +1 = 8 */
        hairColor = dataIn.readUnsignedByte() /* +1 = 9 */
        featureMask = dataIn.readUnsignedByte() /* +1 = 10 */
        featureMask = (featureMask shl 16) or dataIn.readUnsignedShort() /* +2 = 12 */
        expression = dataIn.readShort().toInt() /* +2 = 14 */
        poseAngle = IntArray(3)
        val by = dataIn.readUnsignedByte() /* +1 = 15 */
        poseAngle[YAW] = by
        val bp = dataIn.readUnsignedByte() /* +1 = 16 */
        poseAngle[PITCH] = bp
        val br = dataIn.readUnsignedByte() /* +1 = 17 */
        poseAngle[ROLL] = br
        poseAngleUncertainty = IntArray(3)
        poseAngleUncertainty[YAW] = dataIn.readUnsignedByte() /* +1 = 18 */
        poseAngleUncertainty[PITCH] = dataIn.readUnsignedByte() /* +1 = 19 */
        poseAngleUncertainty[ROLL] = dataIn.readUnsignedByte() /* +1 = 20 */

        /* Feature Point(s) (optional) (8 * featurePointCount), see ISO 19794-5 5.8 */
        featurePoints = arrayOfNulls<FeaturePoint>(featurePointCount) as Array<FeaturePoint>?
        for (i in 0..<featurePointCount) {
            val featureType = dataIn.readUnsignedByte() /* 1 */
            val featurePoint = dataIn.readByte() /* +1 = 2 */
            val x = dataIn.readUnsignedShort() /* +2 = 4 */
            val y = dataIn.readUnsignedShort() /* +2 = 6 */
            var skippedBytes: Long = 0
            while (skippedBytes < 2) {
                skippedBytes += dataIn.skip(2)
            } /* +2 = 8, NOTE: 2 bytes reserved */
            featurePoints!![i] = FeaturePoint(featureType, featurePoint, x, y)
        }

        /* Image Information */
        faceImageType = dataIn.readUnsignedByte() /* 1 */
        imageDataType = dataIn.readUnsignedByte() /* +1 = 2 */
        setWidth(dataIn.readUnsignedShort()) /* +2 = 4 */
        setHeight(dataIn.readUnsignedShort()) /* +2 = 6 */
        colorSpace = dataIn.readUnsignedByte() /* +1 = 7 */
        sourceType = dataIn.readUnsignedByte() /* +1 = 8 */
        deviceType = dataIn.readUnsignedShort() /* +2 = 10 */
        quality = dataIn.readUnsignedShort() /* +2 = 12 */

        /* Temporarily fix width and height if 0. */
        if (getWidth() <= 0) {
            setWidth(800)
        }
        if (getHeight() <= 0) {
            setHeight(600)
        }

        /*
         * Read image data, image data type code based on Section 5.8.1
         * ISO 19794-5.
         */
        toMimeType(imageDataType)?.let { setMimeType(it) }
        val imageLength = recordLength - 20 - 8 * featurePointCount - 12

        readImage(inputStream, imageLength.toInt())
    }

    /**
     * Writes this face image info to output stream.
     *
     * @param outputStream an output stream
     *
     * @throws IOException if writing fails
     */
    @Throws(IOException::class)
    public override fun writeObject(outputStream: OutputStream) {
        SecureByteArrayOutputStream(true).use {
            writeFacialRecordData(it)
            val facialRecordData = it.toByteArray()
            val faceImageBlockLength = facialRecordData.size + 4L
            val dataOut = DataOutputStream(outputStream)
            dataOut.writeInt(faceImageBlockLength.toInt())
            dataOut.write(facialRecordData)
            dataOut.flush()
        }
    }

    /**
     * Returns the record length.
     *
     * @return the record length
     */
    override fun getRecordLength(): Long {
        /* Should be equal to (20 + 8 * featurePoints.length + 12 + getImageLength()). */
        return recordLength
    }

    /**
     * Returns the pose angle as an integer array of length 3,
     * containing yaw, pitch, and roll angle in encoded form.
     *
     * @return an integer array of length 3
     */
    fun getPoseAngle(): IntArray {
        val result = IntArray(3)
        System.arraycopy(poseAngle, 0, result, 0, result.size)
        return result
    }

    /**
     * Returns the pose angle uncertainty as an integer array of length 3,
     * containing yaw, pitch, and roll angle uncertainty.
     *
     * @return an integer array of length 3
     */
    fun getPoseAngleUncertainty(): IntArray {
        val result = IntArray(3)
        System.arraycopy(poseAngleUncertainty, 0, result, 0, result.size)
        return result
    }

    /**
     * Generates a textual representation of this object.
     *
     * @return a textual representation of this object
     *
     * @see Object.toString
     */
    override fun toString(): String {
        val out = StringBuilder()
        out.append("FaceImageInfo [")
        out.append("Image size: ").append(getWidth()).append(" x ").append(getHeight()).append(", ")
        out.append("Gender: ").append(if (gender == null) Gender.UNSPECIFIED else gender).append(", ")
        out.append("Eye color: ").append(if (eyeColor == null) EyeColor.UNSPECIFIED else eyeColor).append(", ")
        out.append("Hair color: ").append(hairColorToString()).append(", ")
        out.append("Feature mask: ").append(featureMaskToString()).append(", ")
        out.append("Expression: ").append(expressionToString()).append(", ")
        out.append("Pose angle: ").append(poseAngleToString()).append(", ")
        out.append("Face image type: ").append(faceImageTypeToString()).append(", ")
        out.append("Source type: ").append(sourceTypeToString()).append(", ")
        out.append("FeaturePoints [")
        if (featurePoints != null && featurePoints!!.size > 0) {
            var isFirstFeaturePoint = true
            for (featurePoint in featurePoints) {
                if (isFirstFeaturePoint) {
                    isFirstFeaturePoint = false
                } else {
                    out.append(", ")
                }
                out.append(featurePoint.toString())
            }
        }
        out.append("]") /* FeaturePoints. */
        out.append("]") /* FaceImageInfo. */
        return out.toString()
    }

    override fun hashCode(): Int {
        val prime = 31
        var result = super.hashCode()
        result = prime * result + colorSpace
        result = prime * result + deviceType
        result = prime * result + expression
        result = prime * result + (if (eyeColor == null) 0 else eyeColor.hashCode())
        result = prime * result + faceImageType
        result = prime * result + featureMask
        result = prime * result + featurePoints.contentHashCode()
        result = prime * result + (if (gender == null) 0 else gender.hashCode())
        result = prime * result + hairColor
        result = prime * result + imageDataType
        result = prime * result + poseAngle.contentHashCode()
        result = prime * result + poseAngleUncertainty.contentHashCode()
        result = prime * result + quality
        result = prime * result + (recordLength xor (recordLength ushr 32)).toInt()
        result = prime * result + sourceType
        return result
    }

    override fun equals(obj: Any?): Boolean {
        if (this === obj) {
            return true
        }
        if (!super.equals(obj)) {
            return false
        }
        if (javaClass != obj!!.javaClass) {
            return false
        }

        val other = obj as FaceImageInfo
        return colorSpace == other.colorSpace && deviceType == other.deviceType && expression == other.expression && eyeColor == other.eyeColor && faceImageType == other.faceImageType && featureMask == other.featureMask && featurePoints.contentEquals(
            other.featurePoints
        ) && gender === other.gender && hairColor == other.hairColor && imageDataType == other.imageDataType && poseAngle.contentEquals(other.poseAngle) && poseAngleUncertainty.contentEquals(other.poseAngleUncertainty) && quality == other.quality && recordLength == other.recordLength && sourceType == other.sourceType
    }

    /**
     * Writes the record data to a stream.
     *
     * @param outputStream the stream to write to
     *
     * @throws IOException on error
     */
    @Throws(IOException::class)
    private fun writeFacialRecordData(outputStream: OutputStream?) {
        val dataOut = DataOutputStream(outputStream)

        /* Facial Information (16) */
        dataOut.writeShort(featurePoints!!.size) /* 2 */
        dataOut.writeByte(if (gender == null) Gender.UNSPECIFIED.toInt() else gender!!.toInt()) /* 1 */
        dataOut.writeByte(if (eyeColor == null) EyeColor.UNSPECIFIED.toInt() else eyeColor!!.toInt()) /* 1 */
        dataOut.writeByte(hairColor) /* 1 */
        dataOut.writeByte(((featureMask.toLong() and 0xFF0000L) shr 16).toByte().toInt()) /* 1 */
        dataOut.writeByte(((featureMask.toLong() and 0x00FF00L) shr 8).toByte().toInt()) /* 1 */
        dataOut.writeByte((featureMask.toLong() and 0x0000FFL).toByte().toInt()) /* 1 */
        dataOut.writeShort(expression) /* 2 */
        for (i in 0..2) {                                                          /* 3 */
            val b = poseAngle[i]
            dataOut.writeByte(b)
        }
        for (i in 0..2) {                                                          /* 3 */
            dataOut.writeByte(poseAngleUncertainty[i])
        }

        /* Feature Point(s) (optional) (8 * featurePointCount) */
        for (fp in featurePoints!!) {
            dataOut.writeByte(fp.type)
            dataOut.writeByte((fp.majorCode shl 4) or fp.minorCode)
            dataOut.writeShort(fp.x)
            dataOut.writeShort(fp.y)
            dataOut.writeShort(0x00) /* 2 bytes RFU */
        }

        /* Image Information (12) */
        dataOut.writeByte(faceImageType) /* 1 */
        dataOut.writeByte(imageDataType) /* 1 */
        dataOut.writeShort(getWidth()) /* 2 */
        dataOut.writeShort(getHeight()) /* 2 */
        dataOut.writeByte(colorSpace) /* 1 */
        dataOut.writeByte(sourceType) /* 1 */
        dataOut.writeShort(deviceType) /* 2 */
        dataOut.writeShort(quality) /* 2 */

        /*
     * Image data type code based on Section 5.8.1
     * ISO 19794-5
     */
        writeImage(dataOut)
        dataOut.flush()
        dataOut.close()
    }

    /**
     * Converts a hair color value to a human readable string.
     *
     * @return a human readable string for the current hair color value
     */
    private fun hairColorToString(): String {
        when (hairColor) {
            HAIR_COLOR_UNSPECIFIED -> return "unspecified"
            HAIR_COLOR_BALD -> return "bald"
            HAIR_COLOR_BLACK -> return "black"
            HAIR_COLOR_BLONDE -> return "blonde"
            HAIR_COLOR_BROWN -> return "brown"
            HAIR_COLOR_GRAY -> return "gray"
            HAIR_COLOR_WHITE -> return "white"
            HAIR_COLOR_RED -> return "red"
            HAIR_COLOR_GREEN -> return "green"
            HAIR_COLOR_BLUE -> return "blue"
            else -> return "unknown"
        }
    }

    /**
     * Returns a human readable string for the current feature mask.
     *
     * @return a human readable string
     */
    private fun featureMaskToString(): String {
        if ((featureMask and FEATURE_FEATURES_ARE_SPECIFIED_FLAG) == 0) {
            return ""
        }
        val features: MutableCollection<String?> = ArrayList<String?>()
        if ((featureMask and FEATURE_GLASSES_FLAG) != 0) {
            features.add("glasses")
        }
        if ((featureMask and FEATURE_MOUSTACHE_FLAG) != 0) {
            features.add("moustache")
        }
        if ((featureMask and FEATURE_BEARD_FLAG) != 0) {
            features.add("beard")
        }
        if ((featureMask and FEATURE_TEETH_VISIBLE_FLAG) != 0) {
            features.add("teeth visible")
        }
        if ((featureMask and FEATURE_BLINK_FLAG) != 0) {
            features.add("blink")
        }
        if ((featureMask and FEATURE_MOUTH_OPEN_FLAG) != 0) {
            features.add("mouth open")
        }
        if ((featureMask and FEATURE_LEFT_EYE_PATCH_FLAG) != 0) {
            features.add("left eye patch")
        }
        if ((featureMask and FEATURE_RIGHT_EYE_PATCH) != 0) {
            features.add("right eye patch")
        }
        if ((featureMask and FEATURE_DARK_GLASSES) != 0) {
            features.add("dark glasses")
        }
        if ((featureMask and FEATURE_DISTORTING_MEDICAL_CONDITION) != 0) {
            features.add("distorting medical condition (which could impact feature point detection)")
        }
        val out = StringBuilder()
        val it = features.iterator()
        while (it.hasNext()) {
            out.append(it.next())
            if (it.hasNext()) {
                out.append(", ")
            }
        }

        return out.toString()
    }

    /**
     * Converts the current expression to a human readable string.
     *
     * @return a human readable string
     */
    private fun expressionToString(): String {
        when (expression.toShort()) {
            EXPRESSION_UNSPECIFIED -> return "unspecified"
            EXPRESSION_NEUTRAL -> return "neutral (non-smiling) with both eyes open and mouth closed"
            EXPRESSION_SMILE_CLOSED -> return "a smile where the inside of the mouth and/or teeth is not exposed (closed jaw)"
            EXPRESSION_SMILE_OPEN -> return "a smile where the inside of the mouth and/or teeth is exposed"
            EXPRESSION_RAISED_EYEBROWS -> return "raised eyebrows"
            EXPRESSION_EYES_LOOKING_AWAY -> return "eyes looking away from the camera"
            EXPRESSION_SQUINTING -> return "squinting"
            EXPRESSION_FROWNING -> return "frowning"
            else -> return "unknown"
        }
    }

    /**
     * Converts the current pose angle to a human readable string.
     *
     * @return a human readable string
     */
    private fun poseAngleToString(): String {
        val out = StringBuilder()
        out.append("(")
        out.append("y: ").append(poseAngle[YAW])
        if (poseAngleUncertainty[YAW] != 0) {
            out.append(" (").append(poseAngleUncertainty[YAW]).append(")")
        }
        out.append(", ")
        out.append("p:").append(poseAngle[PITCH])
        if (poseAngleUncertainty[PITCH] != 0) {
            out.append(" (").append(poseAngleUncertainty[PITCH]).append(")")
        }
        out.append(", ")
        out.append("r: ").append(poseAngle[ROLL])
        if (poseAngleUncertainty[ROLL] != 0) {
            out.append(" (").append(poseAngleUncertainty[ROLL]).append(")")
        }
        out.append(")")
        return out.toString()
    }

    /**
     * Returns a textual representation of the face image type
     * (`"basic"`, `"full frontal"`, `"token frontal"`,
     * or `"unknown"`).
     *
     * @return a textual representation of the face image type
     */
    private fun faceImageTypeToString(): String {
        when (faceImageType) {
            FACE_IMAGE_TYPE_BASIC -> return "basic"
            FACE_IMAGE_TYPE_FULL_FRONTAL -> return "full frontal"
            FACE_IMAGE_TYPE_TOKEN_FRONTAL -> return "token frontal"
            else -> return "unknown"
        }
    }

    /**
     * Returns a textual representation of the source type.
     *
     * @return a textual representation of the source type
     */
    private fun sourceTypeToString(): String {
        when (sourceType) {
            SOURCE_TYPE_UNSPECIFIED -> return "unspecified"
            SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE -> return "static photograph from an unknown source"
            SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM -> return "static photograph from a digital still-image camera"
            SOURCE_TYPE_STATIC_PHOTO_SCANNER -> return "static photograph from a scanner"
            SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE -> return "single video frame from an unknown source"
            SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM -> return "single video frame from an analogue camera"
            SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM -> return "single video frame from a digital camera"
            else -> return "unknown"
        }
    }

    /**
     * Feature points as described in Section 5.6.3 of ISO/IEC FCD 19794-5.
     *
     * @author The JMRTD team (info@jmrtd.org)
     *
     * @version $Revision: 1808 $
     */
    class FeaturePoint: Serializable {

        var type: Int
        var majorCode: Int
        var minorCode: Int
        var x: Int
        var y: Int

        /**
         * Constructs a new feature point.
         *
         * @param type feature point type
         * @param code combined major and minor code
         * @param x X-coordinate
         * @param y Y-coordinate
         */
        constructor(type: Int, code: Byte, x: Int, y: Int) : this(type, (code.toInt() and 0xF0) shr 4, code.toInt() and 0x0F, x, y)

        /**
         * Constructs a new feature point.
         *
         * @param type feature point type
         * @param majorCode major code
         * @param minorCode minor code
         * @param x X-coordinate
         * @param y Y-coordinate
         */
        constructor(type: Int, majorCode: Int, minorCode: Int, x: Int, y: Int) {
            this.type = type
            this.majorCode = majorCode
            this.minorCode = minorCode
            this.x = x
            this.y = y
        }

        /**
         * Generates a textual representation of this point.
         *
         * @return a textual representation of this point
         *
         * @see Object.toString
         */
        override fun toString(): String {
            return StringBuilder()
                .append("( point: ").append(this.majorCode).append(".").append(this.minorCode)
                .append(", ")
                .append("type: ").append(Integer.toHexString(type)).append(", ")
                .append("(").append(x).append(", ")
                .append(y).append(")")
                .append(")").toString()
        }

        companion object {
            private val serialVersionUID = -4209679423938065215L
        }
    }

    companion object {
        private val serialVersionUID = -1751069410327594067L

        private val LOGGER: Logger = Logger.getLogger("org.jmrtd")

        /* These correspond to values in Table 4 in 5.5.4 in ISO/IEC 19794-5:2005(E). */
        const val EYE_COLOR_UNSPECIFIED: Int = 0x00
        const val EYE_COLOR_BLACK: Int = 0x01
        const val EYE_COLOR_BLUE: Int = 0x02
        const val EYE_COLOR_BROWN: Int = 0x03
        const val EYE_COLOR_GRAY: Int = 0x04
        const val EYE_COLOR_GREEN: Int = 0x05
        const val EYE_COLOR_MULTI_COLORED: Int = 0x06
        const val EYE_COLOR_PINK: Int = 0x07
        const val EYE_COLOR_UNKNOWN: Int = 0xFF

        const val HAIR_COLOR_UNSPECIFIED: Int = 0x00
        const val HAIR_COLOR_BALD: Int = 0x01
        const val HAIR_COLOR_BLACK: Int = 0x02
        const val HAIR_COLOR_BLONDE: Int = 0x03
        const val HAIR_COLOR_BROWN: Int = 0x04
        const val HAIR_COLOR_GRAY: Int = 0x05
        const val HAIR_COLOR_WHITE: Int = 0x06
        const val HAIR_COLOR_RED: Int = 0x07
        const val HAIR_COLOR_GREEN: Int = 0x08
        const val HAIR_COLOR_BLUE: Int = 0x09
        const val HAIR_COLOR_UNKNOWN: Int = 0xFF

        private const val FEATURE_FEATURES_ARE_SPECIFIED_FLAG = 0x000001
        private const val FEATURE_GLASSES_FLAG = 0x000002
        private const val FEATURE_MOUSTACHE_FLAG = 0x000004
        private const val FEATURE_BEARD_FLAG = 0x000008
        private const val FEATURE_TEETH_VISIBLE_FLAG = 0x000010
        private const val FEATURE_BLINK_FLAG = 0x000020
        private const val FEATURE_MOUTH_OPEN_FLAG = 0x000040
        private const val FEATURE_LEFT_EYE_PATCH_FLAG = 0x000080
        private const val FEATURE_RIGHT_EYE_PATCH = 0x000100
        private const val FEATURE_DARK_GLASSES = 0x000200
        private const val FEATURE_DISTORTING_MEDICAL_CONDITION = 0x000400

        const val EXPRESSION_UNSPECIFIED: Short = 0x0000
        const val EXPRESSION_NEUTRAL: Short = 0x0001
        const val EXPRESSION_SMILE_CLOSED: Short = 0x0002
        const val EXPRESSION_SMILE_OPEN: Short = 0x0003
        const val EXPRESSION_RAISED_EYEBROWS: Short = 0x0004
        const val EXPRESSION_EYES_LOOKING_AWAY: Short = 0x0005
        const val EXPRESSION_SQUINTING: Short = 0x0006
        const val EXPRESSION_FROWNING: Short = 0x0007

        const val FACE_IMAGE_TYPE_BASIC: Int = 0x00
        const val FACE_IMAGE_TYPE_FULL_FRONTAL: Int = 0x01
        const val FACE_IMAGE_TYPE_TOKEN_FRONTAL: Int = 0x02

        const val IMAGE_DATA_TYPE_JPEG: Int = 0x00
        const val IMAGE_DATA_TYPE_JPEG2000: Int = 0x01

        const val IMAGE_COLOR_SPACE_UNSPECIFIED: Int = 0x00
        const val IMAGE_COLOR_SPACE_RGB24: Int = 0x01
        const val IMAGE_COLOR_SPACE_YUV422: Int = 0x02
        const val IMAGE_COLOR_SPACE_GRAY8: Int = 0x03
        const val IMAGE_COLOR_SPACE_OTHER: Int = 0x04

        const val SOURCE_TYPE_UNSPECIFIED: Int = 0x00
        const val SOURCE_TYPE_STATIC_PHOTO_UNKNOWN_SOURCE: Int = 0x01
        const val SOURCE_TYPE_STATIC_PHOTO_DIGITAL_CAM: Int = 0x02
        const val SOURCE_TYPE_STATIC_PHOTO_SCANNER: Int = 0x03
        const val SOURCE_TYPE_VIDEO_FRAME_UNKNOWN_SOURCE: Int = 0x04
        const val SOURCE_TYPE_VIDEO_FRAME_ANALOG_CAM: Int = 0x05
        const val SOURCE_TYPE_VIDEO_FRAME_DIGITAL_CAM: Int = 0x06
        const val SOURCE_TYPE_UNKNOWN: Int = 0x07

        /** Indexes into poseAngle array.  */
        private const val YAW = 0

        /** Indexes into poseAngle array.  */
        private const val PITCH = 1

        /** Indexes into poseAngle array.  */
        private const val ROLL = 2

        /**
         * Returns a mime-type string for the compression algorithm code.
         *
         * @param compressionAlg the compression algorithm code as it occurs in the header
         *
         * @return a mime-type string,
         * typically `JPEG_MIME_TYPE` or `JPEG2000_MIME_TYPE`
         */
        private fun toMimeType(compressionAlg: Int): String? {
            when (compressionAlg) {
                IMAGE_DATA_TYPE_JPEG -> return JPEG_MIME_TYPE
                IMAGE_DATA_TYPE_JPEG2000 -> return JPEG2000_MIME_TYPE
                else -> {
                    LOGGER.warning("Unknown image type: " + compressionAlg)
                    return null
                }
            }
        }
    }
}
