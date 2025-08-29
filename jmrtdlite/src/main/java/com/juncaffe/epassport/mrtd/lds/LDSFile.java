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
 * $Id: LDSFile.java 1751 2018-01-15 15:35:45Z martijno $
 */

package com.juncaffe.epassport.mrtd.lds;

/**
 * LDS element at file level.
 *
 * @author The JMRTD team (info@jmrtd.org)
 *
 * @version $Revision: 1751 $
 */
public interface LDSFile extends LDSElement {

  /** ICAO tag for document index (COM). */
  int EF_COM_TAG = 0x60;

  /** ICAO data group tag for DG1. */
  int EF_DG1_TAG = 0x61;

  /** ICAO data group tag for DG2. */
  int EF_DG2_TAG = 0x75;

  /* ICAO data group tag for DG3. */
  int EF_DG3_TAG = 0x63;

  /** ICAO data group tag for DG14. */
  int EF_DG14_TAG = 0x6E;

  /** ICAO tag for document security index (SOd). */
  int EF_SOD_TAG = 0x77;

  /**
   * Returns the length of this file.
   *
   * @return the length of this file
   */
  int getLength();
}
