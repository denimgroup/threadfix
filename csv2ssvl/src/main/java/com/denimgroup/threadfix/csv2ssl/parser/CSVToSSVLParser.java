////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.serializer.RecordToXMLSerializer;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;

import java.io.*;

/**
 * Created by mac on 12/2/14.
 */
public class CSVToSSVLParser {

    private CSVToSSVLParser(){}

    // expects well-formed input
    public static String parse(String filePath, String... format) {

        File file = new File(filePath);

        assert file.isFile() : "File should already have been checked at this point.";

        try {
            return parse(new FileReader(file), format);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Coding error: " + filePath + " wasn't found.", e);
        }
    }

    // expects well-formed input
    public static String parse(String filePath) {

        File file = new File(filePath);

        assert file.isFile() : "File should already have been checked at this point.";

        try {
            return parse(new FileReader(file));
        } catch (FileNotFoundException e) {
            throw new IllegalStateException("Coding error: " + filePath + " wasn't found.", e);
        }
    }

    public static String parse(Reader reader, String... format) {
        try {
            CSVParser parse;

            if (format.length == 0) { // headers must be in the first line of the file

                // Use header row as set of headers? not sure why I have to spell it out like this

                parse = CSVFormat.DEFAULT.withSkipHeaderRecord(false).parse(reader);

            } else {
                parse = CSVFormat.DEFAULT.withSkipHeaderRecord().withHeader(format).parse(reader);
            }

            return RecordToXMLSerializer.getFromReader(parse);
        } catch (IOException e) {
            throw new IllegalStateException("Received IOException while parsing file.", e);
        }
    }
}
