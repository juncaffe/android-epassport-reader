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
 * $Id: DG14File.java 1885 2024-11-07 09:17:29Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds.icao;

import com.juncaffe.epassport.mrtd.PassportService;
import com.juncaffe.epassport.mrtd.lds.DataGroup;
import com.juncaffe.epassport.mrtd.lds.SecurityInfo;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DLSet;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Data Group 14 stores a set of SecurityInfos for EAC and PACE, see
 * BSI EAC 1.11 and ICAO TR-SAC-1.01.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1885 $
 */
public class DG14File extends DataGroup {

  private static final long serialVersionUID = -3536507558193769953L;

  private static final Logger LOGGER = Logger.getLogger("org.jmrtd");

  /** The security infos that make up this file. */
  private Set<SecurityInfo> securityInfos;

  /**
   * Constructs a new DG14 file from the data in an input stream.
   *
   * @param inputStream the input stream to parse the data from
   *
   * @throws IOException on error reading from input stream
   */
  public DG14File(InputStream inputStream) throws IOException {
    super(EF_DG14_TAG, inputStream);
  }

  public DG14File(InputStream inputStream, PassportService.ProgressListener listener) throws IOException {
    super(EF_DG14_TAG, inputStream, listener);
  }

  @Override
  protected void readContent(InputStream inputStream) throws IOException {
    ASN1InputStream asn1In = new ASN1InputStream(inputStream, true);
    ASN1Primitive asn1Primitive = asn1In.readObject();
    ASN1Set set = ASN1Set.getInstance(asn1Primitive);
    securityInfos = new HashSet<SecurityInfo>(set.size());
    for (int i = 0; i < set.size(); i++) {
      ASN1Primitive object = set.getObjectAt(i).toASN1Primitive();
      try {
        SecurityInfo securityInfo = SecurityInfo.getInstance(object);
        if (securityInfo == null) {
          LOGGER.warning("Skipping this unsupported SecurityInfo");
          continue;
        }
        securityInfos.add(securityInfo);
      } catch (Exception e) {
        LOGGER.log(Level.WARNING, "Skipping Security Info", e);
      }
    }
  }

  /* FIXME: rewrite (using writeObject instead of getDERObject) to remove interface dependency on BC. */
  @Override
  protected void writeContent(OutputStream outputStream) throws IOException {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    for (SecurityInfo securityInfo: securityInfos) {
      if (securityInfo == null) {
        continue;
      }

      ASN1Primitive derObject = securityInfo.getDERObject();
      vector.add(derObject);
    }
    ASN1Set derSet = new DLSet(vector);
    outputStream.write(derSet.getEncoded(ASN1Encoding.DER));
  }

  /**
   * Returns the security infos as an unordered collection.
   *
   * @return security infos
   */
  public Collection<SecurityInfo> getSecurityInfos() {
    return securityInfos;
  }

  @Override
  public void wipe() {

  }

  @Override
  public String toString() {
    return "DG14File [" + securityInfos.toString() + "]";
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (!(obj.getClass().equals(this.getClass()))) {
      return false;
    }

    DG14File other = (DG14File)obj;
    if (securityInfos == null) {
      return  other.securityInfos == null;
    }
    if (other.securityInfos == null) {
      return securityInfos == null;
    }

    return securityInfos.equals(other.securityInfos);
  }

  @Override
  public int hashCode() {
    return 5 * securityInfos.hashCode() + 41;
  }
}
