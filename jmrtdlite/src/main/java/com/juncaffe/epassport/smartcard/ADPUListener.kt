/*
 * This file is part of the SCUBA smart card framework.
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
 * Copyright (C) 2009 - 2023  The SCUBA team.
 *
 * $Id: APDUListener.java 321 2023-03-09 15:35:49Z martijno $
 */
package com.juncaffe.epassport.smartcard

import java.util.EventListener

/**
 * Specifies an event handler type to react to APDU events.
 *
 * @author Engelbert Hubbers (hubbers@cs.ru.nl)
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 *
 * @version $Revision: 321 $
 */
interface APDUListener : EventListener {
    /**
     * Is called after an apdu was exchanged.
     *
     * @param e an APDU event containing the exchanged APDUs
     */
    fun exchangedAPDU(e: APDUEvent?)
}