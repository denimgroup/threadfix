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
package com.denimgroup.threadfix.csv2ssl.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.Set;

import static com.denimgroup.threadfix.csv2ssl.util.CollectionUtils.set;

/**
 * Created by mac on 12/3/14.
 */
public final class Strings {

    private Strings(){}

    public static final String
            SEVERITY = getParameter("fields.severity"),
            CWE = getParameter("fields.cwe"),
            SOURCE = getParameter("fields.source"),
            URL = getParameter("fields.url"),
            PARAMETER = getParameter("fields.parameter"),
            NATIVE_ID = getParameter("fields.nativeId"),
            LINE_NUMBER = getParameter("fields.lineNumber"),
            COLUMN_NUMBER = getParameter("fields.columnNumber"),
            LINE_TEXT = getParameter("fields.lineText"),
            LONG_DESCRIPTION = getParameter("fields.longDescription"),
            SHORT_DESCRIPTION = getParameter("fields.shortDescription"),
            ISSUE_ID = getParameter("fields.issueID"),
            IGNORE = getParameter("fields.ignore"),
            CONFIG_FILE = getParameter("arguments.configFile"),
            TARGET_FILE = getParameter("arguments.targetFile"),
            OUTPUT_FILE = getParameter("arguments.outputFile"),
            FORMAT_FILE = getParameter("arguments.formatFile"),
            FORMAT_STRING = getParameter("arguments.format"),
            SOURCE_FILE_NAME = getParameter("fields.sourceFileName"),
            FINDING_DATE = getParameter("fields.findingDate"),
            DEFAULT_CWE = getParameter("defaults.cwe"),
            DATE_FORMAT = getParameter("formats.date"),
            ALLOW_FILE_HEADERS = getParameter("defaults.allowFileHeaders");

    public static final Either<String, String> DEFAULT_HEADERS =
            getOptionalHeader("defaults.headers");

    private static Either<String, String> getOptionalHeader(String s) {
        if (properties == null) {
            initProperties();
        }

        if (properties == null) {
            throw new IllegalStateException("Failed to initialize parameters.");
        }

        String property = properties.getProperty(s);

        if (property == null) {
            return Either.failure("Property " + s + " wasn't found.");
        } else {
            return Either.success(property);
        }
    }

    public static final Set<String> ARGUMENTS = set(
            TARGET_FILE, OUTPUT_FILE, FORMAT_FILE, FORMAT_STRING
    );

    public static final Set<String> HEADER_NAMES = set(
            SEVERITY, CWE, SOURCE, URL,
            PARAMETER, NATIVE_ID,
            LONG_DESCRIPTION,
            SHORT_DESCRIPTION,
            ISSUE_ID, FINDING_DATE,
            SOURCE_FILE_NAME,
            LINE_NUMBER,
            LINE_TEXT,
            COLUMN_NUMBER
    );

    private static Properties properties = null;

    private static String getParameter(String s) throws IllegalStateException {
        if (properties == null) {
            initProperties();
        }

        if (properties == null) {
            throw new IllegalStateException("Failed to initialize parameters.");
        }

        String property = properties.getProperty(s);

        if (property == null) {
            throw new IllegalStateException("Failed to retrieve property for key " + s);
        }

        return property;
    }

    private static void initProperties() {

        InputStream stream = Strings.class.getResourceAsStream("/constants.properties");

        if (stream == null) {
            throw new IllegalStateException("Unable to load constants.properties.");
        }

        properties = new Properties();

        try {
            properties.load(stream);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load constants.properties: threw IOException.", e);
        }
    }


}
