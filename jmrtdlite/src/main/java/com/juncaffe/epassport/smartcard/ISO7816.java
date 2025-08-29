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
 * $Id: ISO7816.java 321 2023-03-09 15:35:49Z martijno $
 */

package com.juncaffe.epassport.smartcard;

/**
 * Constants interface for ISO 7816 (and friends).
 *
 * @author Engelbert Hubbers (hubbers@cs.ru.nl)
 * @author Martijn Oostdijk (martijno@cs.ru.nl)
 *
 * @version $Revision: 321 $
 */
public interface ISO7816 {
    static final byte CLA_ISO7816 = (byte)0x00;
    static final byte CLA_COMMAND_CHAINING = (byte)0x10;

    static final byte INS_EXTERNAL_AUTHENTICATE = (byte)0x82;
    static final byte INS_GET_CHALLENGE = (byte)0x84;
    static final byte INS_INTERNAL_AUTHENTICATE = (byte)0x88;
    static final byte INS_SELECT_FILE = (byte)0xA4;
    static final byte INS_READ_BINARY = (byte)0xB0;
    static final byte INS_READ_BINARY2 = (byte)0xB1;
    static final byte INS_GET_RESPONSE = (byte)0xC0;
    static final byte INS_PSO = (byte)0x2A;
    static final byte INS_MSE = (byte)0x22;

    static final short SW_BYTES_REMAINING_00 = (short)0x6100;
    static final short SW_END_OF_FILE = (short)0x6282;
    static final short SW_LESS_DATA_RESPONDED_THAN_REQUESTED = (short)0x6287;
    static final short SW_NON_VOLATILE_MEMORY_CHANGED_COUNTER_0 = (short)0x63C0;
    static final short SW_WRONG_LENGTH = (short)0x6700;
    static final short SW_LOGICAL_CHANNEL_NOT_SUPPORTED = (short)0x6881;
    static final short SW_SECURE_MESSAGING_NOT_SUPPORTED  = (short)0x6882;
    static final short SW_LAST_COMMAND_EXPECTED = (short)0x6883;
    static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short)0x6982;
    static final short SW_FILE_INVALID = (short)0x6983;
    static final short SW_DATA_INVALID = (short)0x6984;
    static final short SW_CONDITIONS_NOT_SATISFIED = (short)0x6985;
    static final short SW_COMMAND_NOT_ALLOWED = (short)0x6986;
    static final short SW_EXPECTED_SM_DATA_OBJECTS_MISSING = (short)0x6987;
    static final short SW_SM_DATA_OBJECTS_INCORRECT = (short)0x6988;
    static final short SW_APPLET_SELECT_FAILED = (short)0x6999;
    static final short SW_KEY_USAGE_ERROR = (short)0x69C1;
    static final short SW_WRONG_DATA = (short)0x6A80;
    static final short SW_FUNC_NOT_SUPPORTED = (short)0x6A81;
    static final short SW_FILE_NOT_FOUND = (short)0x6A82;
    static final short SW_RECORD_NOT_FOUND = (short)0x6A83;
    static final short SW_OUT_OF_MEMORY = (short)0x6A84;
    static final short SW_INCORRECT_P1P2 = (short)0x6A86;
    static final short SW_KEY_NOT_FOUND = (short)0x6A88;
    static final short SW_WRONG_P1P2 = (short)0x6B00;
    static final short SW_CORRECT_LENGTH_00 = (short)0x6C00;
    static final short SW_INS_NOT_SUPPORTED = (short)0x6D00;
    static final short SW_CLA_NOT_SUPPORTED = (short)0x6E00;
    static final short SW_UNKNOWN = (short)0x6F00;
    static final short SW_CARD_TERMINATED = (short)0x6FFF;
    static final short SW_NO_ERROR = (short)0x9000;
}