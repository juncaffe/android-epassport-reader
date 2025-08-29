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
 * $Id: SecurityInfo.java 1894 2025-03-19 20:00:46Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds;

import com.juncaffe.epassport.mrtd.utils.Util;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/* FIXME: dependency on BC in interface? */

/**
 * Abstract base class for security info structure.
 * See the BSI EAC 1.11 specification.
 * See the ICAO TR - SAC v1.1 specification.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1894 $
 */
public abstract class SecurityInfo extends AbstractLDSInfo {

  private static final long serialVersionUID = -7919854443619069808L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /**
   * Used in ECDSA based Active Authentication.
   * <code>{joint-iso-itu-t(2) international-organizations(23) 136 mrtd(1) security(1) aaProtocolObject(5)}</code>.
   */
  public static final String ID_AA = "2.23.136.1.1.5";

  public static final String ID_PK_DH = "0.4.0.127.0.7.2.2.1.1";
  public static final String ID_PK_ECDH = "0.4.0.127.0.7.2.2.1.2";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_DH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.1.1";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_ECDH_3DES_CBC_CBC = "0.4.0.127.0.7.2.2.3.2.1";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_DH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.1.2";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_DH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.1.3";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_DH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.1.4";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_ECDH_AES_CBC_CMAC_128 = "0.4.0.127.0.7.2.2.3.2.2";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_ECDH_AES_CBC_CMAC_192 = "0.4.0.127.0.7.2.2.3.2.3";

  /** Used in Chip Authentication 1 and 2. */
  public static final String ID_CA_ECDH_AES_CBC_CMAC_256 = "0.4.0.127.0.7.2.2.3.2.4";

  public static final String ID_EC_PUBLIC_KEY_TYPE = "1.2.840.10045.2";

  public static final String ID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

  private static final String ID_BSI = "0.4.0.127.0.7";

  /* protocols (2), smartcard (2), PACE (4) */
  public static final String ID_PACE = ID_BSI + ".2.2.4";

  public static final String ID_PACE_DH_GM = ID_PACE + ".1";
  public static final String ID_PACE_DH_GM_3DES_CBC_CBC = ID_PACE_DH_GM + ".1"; /* 0.4.0.127.0.7.2.2.4.1.1, id-PACE-DH-GM-3DES-CBC-CBC */
  public static final String ID_PACE_DH_GM_AES_CBC_CMAC_128 = ID_PACE_DH_GM + ".2"; /* 0.4.0.127.0.7.2.2.4.1.2, id-PACE-DH-GM-AES-CBC-CMAC-128 */
  public static final String ID_PACE_DH_GM_AES_CBC_CMAC_192 = ID_PACE_DH_GM + ".3"; /* 0.4.0.127.0.7.2.2.4.1.3, id-PACE-DH-GM-AES-CBC-CMAC-192 */
  public static final String ID_PACE_DH_GM_AES_CBC_CMAC_256 = ID_PACE_DH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.1.4, id-PACE-DH-GM-AES-CBC-CMAC-256 */

  public static final String ID_PACE_ECDH_GM = ID_PACE + ".2";
  public static final String ID_PACE_ECDH_GM_3DES_CBC_CBC = ID_PACE_ECDH_GM + ".1"; /* 0.4.0.127.0.7.2.2.4.2.1, id-PACE-ECDH-GM-3DES-CBC-CBC */
  public static final String ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2"; /* 0.4.0.127.0.7.2.2.4.2.2, id-PACE-ECDH-GM-AES-CBC-CMAC-128 */
  public static final String ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3"; /* 0.4.0.127.0.7.2.2.4.2.3, id-PACE-ECDH-GM-AES-CBC-CMAC-192 */
  public static final String ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4"; /* 0.4.0.127.0.7.2.2.4.2.4, id-PACE-ECDH-GM-AES-CBC-CMAC-256 */

  public static final String ID_PACE_DH_IM = ID_PACE + ".3";
  public static final String ID_PACE_DH_IM_3DES_CBC_CBC = ID_PACE_DH_IM + ".1"; /* 0.4.0.127.0.7.2.2.4.3.1, id-PACE-DH-IM-3DES-CBC-CBC */
  public static final String ID_PACE_DH_IM_AES_CBC_CMAC_128 = ID_PACE_DH_IM + ".2"; /* 0.4.0.127.0.7.2.2.4.3.2, id-PACE-DH-IM-AES-CBC-CMAC-128 */
  public static final String ID_PACE_DH_IM_AES_CBC_CMAC_192 = ID_PACE_DH_IM + ".3"; /* 0.4.0.127.0.7.2.2.4.3.3, id-PACE-DH-IM-AES-CBC-CMAC-192 */
  public static final String ID_PACE_DH_IM_AES_CBC_CMAC_256 = ID_PACE_DH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.3.4, id-PACE-DH-IM-AES-CBC-CMAC-256 */

  public static final String ID_PACE_ECDH_IM = ID_PACE + ".4";
  public static final String ID_PACE_ECDH_IM_3DES_CBC_CBC = ID_PACE_ECDH_IM + ".1"; /* 0.4.0.127.0.7.2.2.4.4.1, id-PACE-ECDH-IM-3DES-CBC-CBC */
  public static final String ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2"; /* 0.4.0.127.0.7.2.2.4.4.2, id-PACE-ECDH-IM-AES-CBC-CMAC-128 */
  public static final String ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3"; /* 0.4.0.127.0.7.2.2.4.4.3, id-PACE-ECDH-IM-AES-CBC-CMAC-192 */
  public static final String ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4"; /* 0.4.0.127.0.7.2.2.4.4.4, id-PACE-ECDH-IM-AES-CBC-CMAC-256 */

  public static final String ID_PACE_ECDH_CAM = ID_PACE + ".6";
  public static final String ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2"; /* 0.4.0.127.0.7.2.2.4.6.2, id-PACE-ECDH-CAM-AES-CBC-CMAC-128 */
  public static final String ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3"; /* 0.4.0.127.0.7.2.2.4.6.3, id-PACE-ECDH-CAM-AES-CBC-CMAC-192 */
  public static final String ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4"; /* 0.4.0.127.0.7.2.2.4.6.4, id-PACE-ECDH-CAM-AES-CBC-CMAC-256 */

  /**
   * Returns a DER object with this SecurityInfo data (DER sequence).
   *
   * @return a DER object with this SecurityInfo data
   *
   * @deprecated this method will be removed from visible interface (because of dependency on BC API)
   */
  @Deprecated
  public abstract ASN1Primitive getDERObject();

  /**
   * Writes this SecurityInfo to output stream.
   *
   * @param outputStream an ouput stream
   *
   * @throws IOException if writing fails
   */
  @Override
  public void writeObject(OutputStream outputStream) throws IOException {
    ASN1Primitive derEncoded = getDERObject();
    if (derEncoded == null) {
      throw new IOException("Could not decode from DER.");
    }

    byte[] derEncodedBytes = derEncoded.getEncoded(ASN1Encoding.DER);
    if (derEncodedBytes == null) {
      throw new IOException("Could not decode from DER.");
    }

    outputStream.write(derEncodedBytes);
  }

  /**
   * Returns the protocol object identifier of this SecurityInfo.
   *
   * @return this protocol object identifier
   */
  public abstract String getObjectIdentifier();

  /**
   * Returns the protocol object identifier as a human readable string.
   *
   * @return a human readable string representing the protocol object identifier
   */
  public abstract String getProtocolOIDString();

  /**
   * Factory method for creating security info objects given an input.
   *
   * @param obj the input
   *
   * @return a concrete security info object
   */
  public static SecurityInfo getInstance(ASN1Encodable obj) {
    try {
      List<ASN1Encodable> sequence = list(obj);
      String oid = ASN1ObjectIdentifier.getInstance(sequence.get(0)).getId();
      ASN1Encodable requiredData = sequence.get(1);
      ASN1Encodable optionalData = sequence.size() <= 2 ? null : sequence.get(2);

      if (ActiveAuthenticationInfo.checkRequiredIdentifier(oid)) {
        int version = ASN1Integer.getInstance(requiredData).getValue().intValue();
        if (optionalData == null) {
          return new ActiveAuthenticationInfo(oid, version, null);
        } else {
          String signatureAlgorithmOID = ASN1ObjectIdentifier.getInstance(optionalData).getId();
          return new ActiveAuthenticationInfo(oid, version, signatureAlgorithmOID);
        }
      } else if (ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid)) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(requiredData);
        if (optionalData == null) {
          return new ChipAuthenticationPublicKeyInfo(oid, Util.toPublicKey(subjectPublicKeyInfo));
        } else {
          ASN1Integer optionalDataAsASN1Integer = ASN1Integer.getInstance(optionalData);
          BigInteger keyId = optionalDataAsASN1Integer.getValue();
          return new ChipAuthenticationPublicKeyInfo(oid, Util.toPublicKey(subjectPublicKeyInfo), keyId);
        }
      } else if (ChipAuthenticationInfo.checkRequiredIdentifier(oid)) {
        int version = ASN1Integer.getInstance(requiredData).getValue().intValue();
        if (optionalData == null) {
          return new ChipAuthenticationInfo(oid, version);
        } else {
          ASN1Integer optionalDataAsASN1Integer = ASN1Integer.getInstance(optionalData);
          BigInteger keyId = optionalDataAsASN1Integer.getValue();
          return new ChipAuthenticationInfo(oid, version, keyId);
        }
      } else if (PACEInfo.checkRequiredIdentifier(oid)) {
        int version = ASN1Integer.getInstance(requiredData).getValue().intValue();
        int parameterId = -1;
        if (optionalData != null) {
          parameterId = ASN1Integer.getInstance(optionalData).getValue().intValue();
        }
        return new PACEInfo(oid, version, parameterId);
      } else if (PACEDomainParameterInfo.checkRequiredIdentifier(oid)) {
        AlgorithmIdentifier domainParameters = AlgorithmIdentifier.getInstance(requiredData);
        if (optionalData != null) {
          BigInteger parameterId = ASN1Integer.getInstance(optionalData).getValue();
          return new PACEDomainParameterInfo(oid, domainParameters, parameterId);
        }
        return new PACEDomainParameterInfo(oid, domainParameters);
      }
      LOGGER.warning("Unsupported SecurityInfo, oid = " + oid);
      return null;
    } catch (Exception e) {
      LOGGER.log(Level.WARNING, "Unexpected exception", e);
      throw new IllegalArgumentException("Malformed input stream.");
    }
  }

  /**
   * Converts an ASN1 sequence to a list.
   *
   * @param asn1Encodable the ASN1 sequence
   *
   * @return a list with element ASN1 objects
   */
  public static List<ASN1Encodable> list(ASN1Encodable asn1Encodable) {
    if (asn1Encodable == null) {
      return null;
    }

    if (asn1Encodable instanceof ASN1Sequence) {
      ASN1Sequence asn1Sequence = (ASN1Sequence)asn1Encodable;
      int count = asn1Sequence.size();
      List<ASN1Encodable> result = new ArrayList<ASN1Encodable>(count);
      for (int i = 0; i < count; i++) {
        ASN1Encodable subObject = asn1Sequence.getObjectAt(i);
        result.add(subObject);
      }
      return result;
    }

    return Collections.singletonList(asn1Encodable);
  }
}
