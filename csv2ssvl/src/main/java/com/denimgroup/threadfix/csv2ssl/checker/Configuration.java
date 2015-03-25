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
package com.denimgroup.threadfix.csv2ssl.checker;

import com.denimgroup.threadfix.csv2ssl.parser.ArgumentParser;
import com.denimgroup.threadfix.csv2ssl.parser.FormatParser;
import com.denimgroup.threadfix.csv2ssl.util.InteractionUtils;
import com.denimgroup.threadfix.csv2ssl.util.Option;
import com.denimgroup.threadfix.csv2ssl.util.Strings;
import org.apache.poi.POIXMLDocument;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;

import java.io.*;
import java.util.Map;
import java.util.Properties;

import static com.denimgroup.threadfix.csv2ssl.util.CollectionUtils.map;

/**
 * Created by mcollins on 1/21/15.
 */
public class Configuration {

    public static enum State {
        VALID, NEEDS_HEADERS, NEEDS_INPUT_FILE, NEEDS_OUTPUT_FILE
    }

    public static Configuration CONFIG = new Configuration();

    public String[] headers;

    public String dateString = Strings.DATE_FORMAT;

    public boolean loadedFromFile = false, useStandardOut = false, shouldSkipFirstLine = false;

    public File csvFile, outputFile;

    public Map<String, String> headerMap = getBasicHeaderMap();

    public static void reset() {
        CONFIG = new Configuration();
    }

    private Map<String, String> getBasicHeaderMap() {
        Map<String, String> returnMap = map();

        for (String headerName : Strings.HEADER_NAMES) {
            returnMap.put(headerName, headerName);
        }

        return returnMap;
    }

    public static State getCurrentState() {
        if (CONFIG.headers == null) {
            return State.NEEDS_HEADERS;
        } else if (CONFIG.csvFile == null || !CONFIG.csvFile.isFile()) {
            return State.NEEDS_INPUT_FILE;
        } else if (CONFIG.outputFile == null && !CONFIG.useStandardOut) {
            return State.NEEDS_OUTPUT_FILE;
        } else {
            return State.VALID;
        }
    }

    public static boolean isExcel(File csvFile) {
        try (BufferedInputStream maybeExcelStream = new BufferedInputStream(new FileInputStream(csvFile))) {

            boolean isExcelFile = POIXMLDocument.hasOOXMLHeader(maybeExcelStream);

            isExcelFile = isExcelFile || POIFSFileSystem.hasPOIFSHeader(maybeExcelStream);

            return isExcelFile;
        } catch (IOException e) {
            System.out.println("Somehow got a FileNotFoundException. Please try again.");
            e.printStackTrace();
            return true;
        }
    }

    public static void writeToFile(File file) {
        FileOutputStream outputStream = null;
        try {
            outputStream = new FileOutputStream(file);

            toProperties().store(outputStream, "Saving contents.");

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private static Properties toProperties() {

        Properties properties = new Properties();

        StringBuilder builder = new StringBuilder("");

        if (CONFIG.headers != null) {
            for (String header : CONFIG.headers) {
                builder.append(header).append(",");
            }
        }

        if (builder.length() > 0) {
            builder.setLength(builder.length() - 1);
        }

        properties.setProperty("headers", builder.toString());

        properties.setProperty("dateFormat", CONFIG.dateString);

        properties.setProperty("outputFile", CONFIG.outputFile  == null ? "" : CONFIG.outputFile.getAbsolutePath());

        properties.setProperty("shouldSkipFirstLine", String.valueOf(CONFIG.shouldSkipFirstLine));
        properties.setProperty("useStandardOut", String.valueOf(CONFIG.useStandardOut));

        for (Map.Entry<String, String> headerEntry : CONFIG.headerMap.entrySet()) {
            properties.setProperty(headerEntry.getKey(), headerEntry.getValue());
        }

        return properties;
    }

    // TODO this is long
    public static void setFromArguments(String[] args) {

        Option<String> configFile = ArgumentParser.parseConfigFileName(args);

        if (configFile.isValid()) {
            loadFromFile(configFile.getValue());
        } else {
            boolean hasConfigurationFile = InteractionUtils.getYNAnswer("Do have a configuration file you would like to use? (y/n)");
            if (hasConfigurationFile) {
                File configuration = InteractionUtils.getValidFileFromStdIn("configuration");
                loadFromFile(configuration.getAbsolutePath());
                System.out.println("In the future, you can start this program with this configuration automatically with the argument " + Strings.CONFIG_FILE + configuration.getAbsolutePath());
            }
        }

        Option<String[]> formatString = FormatParser.getHeaders(args);

        if (formatString.isValid()) {
            CONFIG.headers = formatString.getValue();
        }

        Option<String> maybeCsvFile = ArgumentParser.parseSourceFileName(args);

        if (maybeCsvFile.isValid()) {
            String csvFileName = maybeCsvFile.getValue();

            File csvFile = new File(csvFileName);
            if (!csvFile.exists()) {
                System.out.println("File '" + csvFileName + "' was not found.");
            } else if (!csvFile.isFile()) {
                System.out.println("File '" + csvFileName + "' was not a regular file.");
            } else {
                CONFIG.csvFile = csvFile;
            }
        }

        Option<String> maybeTargetFile = ArgumentParser.parseTargetFileName(args);

        if (maybeTargetFile.isValid()) {
            String targetFileName = maybeTargetFile.getValue();

            File file = new File(targetFileName);

            if (file.exists()) {
                System.out.println("File '" + targetFileName + "' already existed, please specify a different path.");
            }
        }
    }

    private static void loadFromFile(String value) {

        File file = new File(value);

        if (file.exists() && file.isFile()) {
            Properties properties = new Properties();

            try {
                properties.load(new FileInputStream(file));
                loadFromProperties(properties);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static void loadFromProperties(Properties properties) {

        String headersProperty = properties.getProperty("headers");

        if (headersProperty != null) {
            CONFIG.headers = headersProperty.split(",");
        }

        String csvFileLocation = properties.getProperty("csvFile");
        if (csvFileLocation != null) {
            File file = new File(csvFileLocation);
            if (file.exists() && file.isFile()) {
                CONFIG.csvFile = file;
            }
        }

        String outputFileLocation = properties.getProperty("outputFile");
        if (outputFileLocation != null) {
            File file = new File(outputFileLocation);
            if (file.exists() && file.isFile()) {
                CONFIG.outputFile = file;
            }
        }

        for (String key : CONFIG.headerMap.keySet()) {
            if (properties.containsKey(key)) {
                CONFIG.headerMap.put(key, properties.getProperty(key));
            }
        }

        if (properties.containsKey("dateFormat")) {
            CONFIG.dateString = properties.getProperty("dateFormat");
        }

        CONFIG.useStandardOut      = "true".equalsIgnoreCase(properties.getProperty("useStandardOut"));
        CONFIG.shouldSkipFirstLine = "true".equalsIgnoreCase(properties.getProperty("shouldSkipFirstLine"));
        CONFIG.loadedFromFile      = true;
    }

}
