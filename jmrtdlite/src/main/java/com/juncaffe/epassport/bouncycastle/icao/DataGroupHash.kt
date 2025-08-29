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
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence

/**
 * The DataGroupHash object.
 * <pre>
 * DataGroupHash  ::=  SEQUENCE {
 *      dataGroupNumber         DataGroupNumber,
 *      dataGroupHashValue     OCTET STRING }
 *
 * DataGroupNumber ::= INTEGER {
 *         dataGroup1    (1),
 *         dataGroup1    (2),
 *         dataGroup1    (3),
 *         dataGroup1    (4),
 *         dataGroup1    (5),
 *         dataGroup1    (6),
 *         dataGroup1    (7),
 *         dataGroup1    (8),
 *         dataGroup1    (9),
 *         dataGroup1    (10),
 *         dataGroup1    (11),
 *         dataGroup1    (12),
 *         dataGroup1    (13),
 *         dataGroup1    (14),
 *         dataGroup1    (15),
 *         dataGroup1    (16) }
 *
 * </pre>
 */
class DataGroupHash: ASN1Object {
    private var dataGroupNumber: ASN1Integer
    private var dataGroupHashValue: ASN1OctetString?

    constructor(seq: ASN1Sequence) {
        val e = seq.getObjects()

        // dataGroupNumber
        dataGroupNumber = ASN1Integer.getInstance(e.nextElement())
        // dataGroupHashValue
        dataGroupHashValue = ASN1OctetString.getInstance(e.nextElement())
    }

    constructor(dataGroupNumber: Int, dataGroupHashValue: ASN1OctetString?) {
        this.dataGroupNumber = ASN1Integer(dataGroupNumber.toLong())
        this.dataGroupHashValue = dataGroupHashValue
    }

    fun getDataGroupNumber(): Int {
        return dataGroupNumber.intValueExact()
    }

    fun getDataGroupHashValue(): ASN1OctetString? {
        return dataGroupHashValue
    }

    override fun toASN1Primitive(): ASN1Primitive {
        val seq = ASN1EncodableVector(2)
        seq.add(dataGroupNumber)
        seq.add(dataGroupHashValue)

        return DERSequence(seq)
    }

    companion object {
        fun getInstance(obj: Any?): DataGroupHash? {
            if (obj is DataGroupHash) {
                return obj
            } else if (obj != null) {
                return DataGroupHash(ASN1Sequence.getInstance(obj))
            }

            return null
        }
    }
}