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
package com.denimgroup.threadfix.sonarplugin.util;

import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

/**
 * Created by mcollins on 2/3/15.
 */
public class InputStreamLanguageDecorator extends InputStream {

    public static void main(String[] args) throws IOException {
        InputStream stream = InputStreamLanguageDecorator.class
                .getResourceAsStream("/threadfix_profile.xml");

        stream = new InputStreamLanguageDecorator(stream, "test");

        String s = IOUtils.toString(stream);

        System.out.println(s);
    }

    private InputStream stream;

    public InputStreamLanguageDecorator(InputStream stream, String language) {
        this.stream = stream;
        temp = language.getBytes();
    }

    final byte[] temp;
    int position = 0;

    boolean writingTemp = false;

    @Override
    public int read() throws IOException {
        int toReturn;

        if (writingTemp) {
            if (position == temp.length) {
                position = 0;
                writingTemp = false;
                toReturn = read();
            } else {
                toReturn = temp[position++];
            }
        } else {
            int original = stream.read();

            if (original == '#') {
                writingTemp = true;
                toReturn = read();
            } else {
                toReturn = original;
            }
        }

        return toReturn;
    }
}
