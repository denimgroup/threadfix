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
//     basis, WITHOUT WARRANTY OF ANY KIND, Option express or implied. See the
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

import java.io.File;
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
                return parseFromFile(arg);
            }
        }

        if (Strings.DEFAULT_HEADERS.isValid()) {
            return Option.success(Strings.DEFAULT_HEADERS.getValue().split(","));
        }

        return Option.failure("Didn't find the format string.");
    }

    private static Option<String[]> parseFromFile(String arg) {
        String fileName = arg.substring(arg.indexOf(Strings.FORMAT_STRING));

        File file = new File(fileName);

        String error;

        if (file.exists() && file.isFile()) {
            try {
                String content = readFile(file, StandardCharsets.UTF_8);

                if (content.length() > 0) {
                    error = "No content found in file " + arg;
                } else {
                    return getStringsOrError(content);
                }
            } catch (IOException e) {
                error = "Encountered IOException while attempting to read file " + fileName;
                e.printStackTrace();
            }
        } else {
            error = "Invalid file: " + fileName;
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
        String[] strings = inputString.split(",");
        
        if (strings.length == 0) {
            return Option.failure("Only " + strings.length + " sections found.");
        }

        boolean isValid = true;

        String[] cleanedHeaders = new String[strings.length];
        StringBuilder errorBuilder = new StringBuilder();

        for (int index = 0; index < strings.length; index++) {
            String possibleHeader = strings[index].trim();

            boolean foundMatch = false;

            for (String headerName : Configuration.CONFIG.headerMap.values()) {
                if (possibleHeader.equalsIgnoreCase(headerName)) {
                    foundMatch = true;
                    cleanedHeaders[index] = headerName;
                }
            }

            if (!foundMatch) {
                isValid = false;
                errorBuilder
                        .append("Invalid header name found: ")
                        .append(possibleHeader)
                        .append("\n");
            }
        }

        // interestingly, the ternary equivalent breaks Java 7's type inference system
        if (isValid) {
            return Option.success(cleanedHeaders);
        } else {
            return Option.failure(errorBuilder.toString());
        }
    }
}
