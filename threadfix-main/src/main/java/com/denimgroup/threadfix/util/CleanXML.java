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

import com.denimgroup.threadfix.importer.util.ScanUtils;
import com.denimgroup.threadfix.logging.SanitizedLogger;

import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;

public class CleanXML {
    private static final SanitizedLogger STATIC_LOGGER = new SanitizedLogger(ScanUtils.class);

    private File file;

    public CleanXML(File file) {
        this.file = file;
    }

    public void clean(File fileOut) throws ParserConfigurationException, SAXException, IOException {
        CleanXMLReader cleanXMLReader = new CleanXMLReader(new FileReader(file));
        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileOut), "UTF-8");

        try {
            char[] characterBuffer = new char['耀'];
            
            int charactersRead;
            while((charactersRead = cleanXMLReader.read(characterBuffer)) > -1) {
                writer.write(characterBuffer, 0, charactersRead);
            }
        } finally {
            if(cleanXMLReader != null) {
                cleanXMLReader.close();
            }

            if(writer != null) {
                writer.flush();
                writer.close();
            }

        }
    }

}
