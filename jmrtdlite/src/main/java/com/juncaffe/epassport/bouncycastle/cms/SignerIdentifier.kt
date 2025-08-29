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

package com.juncaffe.epassport.bouncycastle.cms

import org.bouncycastle.asn1.ASN1Choice
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1TaggedObject
import org.bouncycastle.asn1.DERTaggedObject

/**
 * [RFC 5652](https://tools.ietf.org/html/rfc5652#section-5.3):
 * Identify who signed the containing [SignerInfo] object.
 *
 *
 * The certificates referred to by this are at containing [SignedData] structure.
 *
 *
 * <pre>
 * SignerIdentifier ::= CHOICE {
 * issuerAndSerialNumber IssuerAndSerialNumber,
 * subjectKeyIdentifier [0] SubjectKeyIdentifier
 * }
 *
 * SubjectKeyIdentifier ::= OCTET STRING
</pre> *
 */
class SignerIdentifier

    : ASN1Object, ASN1Choice {
    private val id: ASN1Encodable

    constructor(id: IssuerAndSerialNumber) {
        this.id = id
    }

    constructor(id: ASN1OctetString) {
        this.id = DERTaggedObject(false, 0, id)
    }

    constructor(id: ASN1Primitive) {
        this.id = id
    }

    val isTagged: Boolean
        get() = (id is ASN1TaggedObject)

    fun getId(): ASN1Encodable {
        if (id is ASN1TaggedObject) {
            return ASN1OctetString.getInstance(id, false)
        }

        return id
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    override fun toASN1Primitive(): ASN1Primitive? {
        return id.toASN1Primitive()
    }

    companion object {
        /**
         * Return a SignerIdentifier object from the given object.
         *
         *
         * Accepted inputs:
         *
         *  *  null  null
         *  *  [SignerIdentifier] object
         *  *  [IssuerAndSerialNumber] object
         *  *  [ASN1OctetString][ASN1OctetString.getInstance] input formats with SignerIdentifier structure inside
         *  *  [ASN1Primitive][ASN1Primitive] for SignerIdentifier constructor.
         *
         *
         * @param o the object we want converted.
         * @exception IllegalArgumentException if the object cannot be converted.
         */
        fun getInstance(
            o: Any?
        ): SignerIdentifier? {
            if (o == null || o is SignerIdentifier) {
                return o
            }
            return when(o) {
                is IssuerAndSerialNumber -> {
                    SignerIdentifier(o)
                }

                is ASN1OctetString -> {
                    SignerIdentifier(o)
                }

                is ASN1Primitive -> {
                    SignerIdentifier(o)
                }

                else -> throw IllegalArgumentException("Illegal object in SignerIdentifier: " + o.javaClass.getName())
            }
        }
    }
}