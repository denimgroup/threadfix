////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
package com.denimgroup.threadfix.util;

import java.io.FilterReader;
import java.io.IOException;
import java.io.Reader;

public class CleanXMLReader extends FilterReader {
    public CleanXMLReader(Reader reader) {
        super(reader);
    }

    public int read(char[] cbuf, int off, int len) throws IOException {
        int charsRead = super.read(cbuf, off, len);
        if(charsRead > -1) {
            int limit = charsRead + off;

            for(int j = off; j < limit; ++j) {
                char c = cbuf[j];
                if(c > -1 && c != 9 && c != 10 && c != 13 && (c < 32 || c > '\ud7ff' && c < '\ue000')) {
                    cbuf[j] = '�';
                }
            }
        }

        return charsRead;
    }

    public int read() throws IOException {
        int i = super.read();
        return i < 32 && i > -1 && i != 9 && i != 10 && i != 13?'�':i;
    }
}

