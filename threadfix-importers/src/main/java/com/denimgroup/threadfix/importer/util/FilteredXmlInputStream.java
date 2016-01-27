////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////
package com.denimgroup.threadfix.importer.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class FilteredXmlInputStream extends FilterInputStream{

    public static final boolean[] INVALID_XML_CHARACTERS;

    static {
        INVALID_XML_CHARACTERS = new boolean[0x20];

        for (int i = 0; i < INVALID_XML_CHARACTERS.length; ++i) {
            INVALID_XML_CHARACTERS[i] = true;
        }

        INVALID_XML_CHARACTERS[0x9] = false;
        INVALID_XML_CHARACTERS[0xA] = false;
        INVALID_XML_CHARACTERS[0xD] = false;
    }

    public FilteredXmlInputStream(InputStream inputStream) {
        super(inputStream);
    }

    @Override
    public int read() throws IOException {
        return filterCharacters((byte) super.read());
    }

    @Override
    public int read(byte[] bytes, int offset, int length) throws IOException {
        int place = super.read(bytes, offset, length);

        if (place == -1) {
            return place;
        }

        for (int i = offset; i < offset + place; ++i) {
            bytes[i] = filterCharacters(bytes[i]);
        }

        return place;
    }

    private byte filterCharacters(byte currentByte) {
        if (currentByte < 0x20 && currentByte >= 0 && INVALID_XML_CHARACTERS[currentByte]) {
            return 0x20;
        }
        return currentByte;
    }
}
