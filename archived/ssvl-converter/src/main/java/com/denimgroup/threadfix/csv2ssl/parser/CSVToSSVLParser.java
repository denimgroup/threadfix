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
package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.serializer.RecordToXMLSerializer;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.*;

import static com.denimgroup.threadfix.csv2ssl.checker.Configuration.CONFIG;

/**
 * Created by mac on 12/2/14.
 */
public class CSVToSSVLParser {

    private CSVToSSVLParser(){}

    // expects well-formed input
    public static String parse(String filePath, String... format) {

        File file = new File(filePath);

        assert file.isFile() : "File should already have been checked at this point.";

        boolean excel = Configuration.isExcel(file);

        if (excel) {
            return parseExcel(file, format);
        } else {
            return parseCsv(file, format);
        }
    }

    public static String parse(Reader reader, String... format) {
        try {
            CSVParser parse = CSVFormat.DEFAULT
                    .withSkipHeaderRecord(CONFIG.shouldSkipFirstLine)
                    .withHeader(format)
                    .parse(reader);

            return RecordToXMLSerializer.getFromReader(parse);
        } catch (IOException e) {
            throw new IllegalStateException("Received IOException while parsing file.", e);
        }
    }

    public static String parseCsv(File file, String... format) {
        try {
            CSVParser parse = CSVFormat.DEFAULT
                    .withSkipHeaderRecord(CONFIG.shouldSkipFirstLine)
                    .withHeader(format)
                    .parse(new FileReader(file));

            return RecordToXMLSerializer.getFromReader(parse);
        } catch (IOException e) {
            throw new IllegalStateException("Received IOException while parsing file.", e);
        }
    }

    public static String parseExcel(File file, String... format) {
        try {
            FileInputStream fis = new FileInputStream(file);
            XSSFWorkbook wb = new XSSFWorkbook(fis);

            return RecordToXMLSerializer.getFromExcel(wb, format);
        } catch (IOException e) {
            throw new IllegalStateException("Received IOException while parsing file.", e);
        }
    }
}
