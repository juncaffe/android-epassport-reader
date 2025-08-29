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
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.x509.AlgorithmIdentifier

/**
 * The LDSSecurityObject object (V1.8).
 * <pre>
 * LDSSecurityObject ::= SEQUENCE {
 * version                LDSSecurityObjectVersion,
 * hashAlgorithm          DigestAlgorithmIdentifier,
 * dataGroupHashValues    SEQUENCE SIZE (2..ub-DataGroups) OF DataHashGroup,
 * ldsVersionInfo         LDSVersionInfo OPTIONAL
 * -- if present, version MUST be v1 }
 *
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier,
 *
 * LDSSecurityObjectVersion :: INTEGER {V0(0)}
</pre> *
 */
class LDSSecurityObject: ASN1Object {
    private var version = ASN1Integer(0)
    private var digestAlgorithmIdentifier: AlgorithmIdentifier
    private var datagroupHash: Array<DataGroupHash?>
    private var versionInfo: LDSVersionInfo? = null

    private constructor(seq: ASN1Sequence) {
        val e = seq.getObjects()

        // version
        version = ASN1Integer.getInstance(e.nextElement())
        // digestAlgorithmIdentifier
        digestAlgorithmIdentifier = AlgorithmIdentifier.getInstance(e.nextElement())

        val datagroupHashSeq = ASN1Sequence.getInstance(e.nextElement())

        if (version.hasValue(1)) {
            versionInfo = LDSVersionInfo.getInstance(e.nextElement())
        }

        checkDatagroupHashSeqSize(datagroupHashSeq.size())

        datagroupHash = Array(datagroupHashSeq.size()) { null }
        for (i in 0..<datagroupHashSeq.size()) {
            datagroupHash[i] = DataGroupHash.getInstance(datagroupHashSeq.getObjectAt(i))
        }
    }

    constructor(
        digestAlgorithmIdentifier: AlgorithmIdentifier,
        datagroupHash: Array<DataGroupHash?>
    ) {
        this.version = ASN1Integer(0)
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier
        this.datagroupHash = copy(datagroupHash)

        checkDatagroupHashSeqSize(datagroupHash.size)
    }

    constructor(
        digestAlgorithmIdentifier: AlgorithmIdentifier,
        datagroupHash: Array<DataGroupHash?>,
        versionInfo: LDSVersionInfo?
    ) {
        this.version = ASN1Integer(1)
        this.digestAlgorithmIdentifier = digestAlgorithmIdentifier
        this.datagroupHash = copy(datagroupHash)
        this.versionInfo = versionInfo

        checkDatagroupHashSeqSize(datagroupHash.size)
    }

    fun getDigestAlgorithmIdentifier(): AlgorithmIdentifier? {
        return digestAlgorithmIdentifier
    }

    private fun checkDatagroupHashSeqSize(size: Int) {
        require(!((size < 2) || (size > ub_DataGroups))) { "wrong size in DataGroupHashValues : not in (2.." + ub_DataGroups + ")" }
    }

    fun getVersion(): Int {
        return version.intValueExact()
    }

    fun getDatagroupHash(): Array<DataGroupHash?> {
        return copy(datagroupHash)
    }

    fun getVersionInfo(): LDSVersionInfo? {
        return versionInfo
    }

    override fun toASN1Primitive(): ASN1Primitive {
        val seq = ASN1EncodableVector(4)

        seq.add(version)
        seq.add(digestAlgorithmIdentifier)
        seq.add(DERSequence(datagroupHash))

        if (versionInfo != null) {
            seq.add(versionInfo)
        }

        return DERSequence(seq)
    }

    private fun copy(dgHash: Array<DataGroupHash?>): Array<DataGroupHash?> {
        val rv: Array<DataGroupHash?> = arrayOfNulls<DataGroupHash?>(dgHash.size)

        System.arraycopy(dgHash, 0, rv, 0, rv.size)

        return rv
    }

    companion object {
        const val ub_DataGroups: Int = 16

        @JvmStatic
        fun getInstance(
            obj: Any
        ): LDSSecurityObject {
            return if (obj is LDSSecurityObject) {
                obj
            }else {
                LDSSecurityObject(ASN1Sequence.getInstance(obj))
            }
        }
    }
}
