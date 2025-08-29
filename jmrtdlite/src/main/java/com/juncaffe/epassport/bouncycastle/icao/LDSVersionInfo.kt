/**
 * Originally from The Bouncy Castle Library
 * Source: https://github.com/bcgit/bc-java
 *
 * Copyright (c) 2000-2023 The Legion of the Bouncy Castle Inc.
 * Licensed under the Bouncy Castle License (MIT License)
 * https://www.bouncycastle.org/licence.html
 *
 * Modified and converted to kotlin for use in JMRTD-Light by JunCaffe
 * https://github.com/juncaffe/jmrtd-light
 */

package com.juncaffe.epassport.bouncycastle.icao

import org.bouncycastle.asn1.ASN1EncodableVector
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1PrintableString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERPrintableString
import org.bouncycastle.asn1.DERSequence

class LDSVersionInfo

    : ASN1Object {
    private val ldsVersion: ASN1PrintableString
    private val unicodeVersion: ASN1PrintableString

    constructor(ldsVersion: String, unicodeVersion: String) {
        this.ldsVersion = DERPrintableString(ldsVersion)
        this.unicodeVersion = DERPrintableString(unicodeVersion)
    }

    private constructor(seq: ASN1Sequence) {
        require(seq.size() == 2) { "sequence wrong size for LDSVersionInfo" }

        this.ldsVersion = ASN1PrintableString.getInstance(seq.getObjectAt(0))
        this.unicodeVersion = ASN1PrintableString.getInstance(seq.getObjectAt(1))
    }

    fun getLdsVersion(): String {
        return ldsVersion.getString()
    }

    fun getUnicodeVersion(): String {
        return unicodeVersion.getString()
    }

    /**
     * <pre>
     * LDSVersionInfo ::= SEQUENCE {
     * ldsVersion PRINTABLE STRING
     * unicodeVersion PRINTABLE STRING
     * }
    </pre> *
     * @return  an ASN.1 primitive composition of this LDSVersionInfo.
     */
    override fun toASN1Primitive(): ASN1Primitive {
        val v = ASN1EncodableVector(2)

        v.add(ldsVersion)
        v.add(unicodeVersion)

        return DERSequence(v)
    }

    companion object {
        fun getInstance(obj: Any?): LDSVersionInfo? {
            if (obj is LDSVersionInfo) {
                return obj
            } else if (obj != null) {
                return LDSVersionInfo(ASN1Sequence.getInstance(obj))
            }

            return null
        }
    }
}