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

package com.denimgroup.threadfix.csv2ssl.parser;

import com.denimgroup.threadfix.csv2ssl.checker.Configuration;
import com.denimgroup.threadfix.csv2ssl.util.Option;
import com.denimgroup.threadfix.csv2ssl.util.Strings;
import org.apache.poi.xssf.usermodel.XSSFCell;
import org.apache.poi.xssf.usermodel.XSSFRow;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Created by mac on 12/3/14.
 */
public class FormatParser {

    public static Option<String[]> getHeaders(String[] args) {
        for (String arg : args) {
            if (arg.startsWith(Strings.FORMAT_STRING)) {
                return parseFromString(arg);
            } else if (arg.startsWith(Strings.FORMAT_FILE)) {
                return parseFromFileArgument(arg);
            }
        }

        if (Strings.DEFAULT_HEADERS.isValid()) {
            return Option.success(Strings.DEFAULT_HEADERS.getValue().split(","));
        }

        return Option.failure("Didn't find the format string.");
    }

    public static Option<String[]> parseFromFileArgument(String arg) {
        String fileName = arg.substring(arg.indexOf(Strings.FORMAT_STRING));

        File file = new File(fileName);

        return parseFromFile(file);
    }

    public static Option<String[]> parseFromFile(File file) {
        if (Configuration.isExcel(file)) {
            return getHeadersExcel(file);
        } else {
            return getHeadersCSV(file);
        }
    }

    public static Option<String[]> getHeadersExcel(File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            XSSFWorkbook wb = new XSSFWorkbook(fis);

            XSSFSheet ws = wb.getSheetAt(0); // read the first sheet
            int totalRows = ws.getLastRowNum();

            if (totalRows == 0) {
                return Option.failure("No lines found in file " + file.getName());
            }

            XSSFRow row = ws.getRow(0);

            String[] headers = new String[row.getLastCellNum()];

            for (int index = 0; index < row.getLastCellNum(); index++) {
                XSSFCell cell = row.getCell(index);

                assert cell != null : "Got null cell at index " + index;

                headers[index] = cell.toString();
            }

            return Option.success(headers);

        } catch (IOException e) {
            e.printStackTrace();
            return Option.failure("Encountered IOException.");
        }
    }

    private static Option<String[]> getHeadersCSV(File file) {
        String error;

        if (file.exists() && file.isFile()) {
            try {
                String content = readFile(file, StandardCharsets.UTF_8);

                if (content.length() == 0) {
                    error = "No content found in file " + file.getName();
                } else {
                    return getStringsOrError(content);
                }
            } catch (IOException e) {
                error = "Encountered IOException while attempting to read file " + file.getName();
                e.printStackTrace();
            }
        } else {
            error = "Invalid file: " + file.getName();
        }

        return Option.failure(error);
    }

    private static String readFile(File file, Charset encoding)
            throws IOException
    {
        byte[] encoded = Files.readAllBytes(Paths.get(file.toURI()));
        return new String(encoded, encoding);
    }

    private static Option<String[]> parseFromString(String arg) {
        String formatSection = arg.substring(Strings.FORMAT_STRING.length());

        assert formatSection.length() > 0 : "Format string was empty.";

        return getStringsOrError(formatSection);
    }

    public static Option<String[]> getStringsOrError(String inputString) {

        String[] lines = inputString.split("[\n\r]");

        if (lines.length > 0) {
            return Option.success(lines[0].split(","));
        } else {
            return Option.failure("0-length array returned from inputString.split(\"\\n\")");
        }
    }
}
