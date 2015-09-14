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
package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.VulnerabilityInfo;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mac on 5/22/14.
 */
public class VulnSearchParameterParser {

    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd-MMM-yyyy");

    private static final Pattern integerPattern = Pattern.compile("[\\,=]([0-9]+)");
    private static final Pattern stringPattern  = Pattern.compile("[\\,=]([^,=]+)");

    static String[] parameters = null;

    static final private List<String> validParameters = list("genericVulnerabilityIds", "teamIds",
            "applicationIds", "scannerNames", "genericSeverityValues", "numberVulnerabilities", "parameter",
            "path", "startDate", "endDate", "showOpen", "showClosed", "showFalsePositive", "showHidden", "numberMerged",
            "showDefectPresent", "showDefectNotPresent", "showDefectOpen", "showDefectClosed",
            "showInconsistentClosedDefectNeedsScan", "showInconsistentClosedDefectOpenInScan", "showInconsistentOpenDefect");

    public static RestResponse<VulnerabilityInfo[]> processVulnerabilitySearchParameters(ThreadFixRestClient client,
                                                                                         String... args) {

        parameters = collapseParameters(args); // This makes me cringe but it's single-threaded right?

        checkArguments();

        return client.searchVulnerabilities(
                getIntegerArray("genericVulnerabilityIds"),
                getIntegerArray("teamIds"),
                getIntegerArray("applicationIds"),
                getStringArray("scannerNames"),
                getIntegerArray("genericSeverityValues"),
                getIntegerValue("numberVulnerabilities"),
                getStringValue("parameter"),
                getStringValue("path"),
                getDateValue("startDate"),
                getDateValue("endDate"),
                getBooleanValue("showOpen"),
                getBooleanValue("showClosed"),
                getBooleanValue("showFalsePositive"),
                getBooleanValue("showHidden"),
                getIntegerValue("numberMerged"),
                getBooleanValue("showDefectPresent"),
                getBooleanValue("showDefectNotPresent"),
                getBooleanValue("showDefectOpen"),
                getBooleanValue("showDefectClosed"),
                getBooleanValue("showInconsistentClosedDefectNeedsScan"),
                getBooleanValue("showInconsistentClosedDefectOpenInScan"),
                getBooleanValue("showInconsistentOpenDefect")
        );
    }

    // This lets us handle fun stuff like scannerNames=Arachni,Cenzic Hailstorm
    private static String[] collapseParameters(String[] parameters) {
        List<String> newList = new ArrayList<String>();
        String lastValue = null;
        if (parameters != null) {
            for (String parameter : parameters) {
                if (parameter.contains("=")) {
                    if (lastValue != null) {
                        newList.add(lastValue);
                    }
                    lastValue = parameter;
                } else if (lastValue != null) {
                    lastValue = lastValue.concat(" ");
                    lastValue = lastValue.concat(parameter);
                }
            }
        }
        if (lastValue != null) {
            newList.add(lastValue);
        }
        System.out.println("Args: " + newList);
        return newList.toArray(new String[newList.size()]);
    }

    private static void checkArguments() {
        for (String parameter : parameters) {
            if (!parameter.contains("=")) {
                throw new IllegalArgumentException(parameter + " was invalid. Expected format is <key>=<value>");
            }

            String shorterName = parameter.substring(0, parameter.indexOf('='));

            if (!validParameters.contains(shorterName)) {
                throw new IllegalArgumentException(parameter + " was invalid. The key should be one of " + validParameters);
            }
        }
    }

    private static List<Integer> getIntegerArray(String key) {
        String argument = getArgument(key);
        return argument != null ? getIntegerValues(argument) : null;
    }

    private static List<String> getStringArray(String key) {
        String argument = getArgument(key);
        return argument != null ? getStringValues(argument) : null;
    }

    private static Boolean getBooleanValue(String key) {
        String stringValue = getStringValue(key);
        return Boolean.parseBoolean(stringValue);
    }

    private static Date getDateValue(String key) {
        String stringValue = getStringValue(key);
        try {
            return stringValue == null ? null : DATE_FORMAT.parse(stringValue);
        } catch (ParseException e) {
            throw new IllegalArgumentException(stringValue + " was not a valid date string. Please use the format " +
                    DATE_FORMAT.toPattern());
        }
    }

    private static String getStringValue(String key) {
        String argument = getArgument(key);
        if (argument != null) {
            List<String> stringArray = getStringValues(argument);
            if (!stringArray.isEmpty()) {
                return stringArray.get(0);
            }
        }
        return null;
    }

    private static Integer getIntegerValue(String key) {
        String argument = getArgument(key);
        if (argument != null) {
            List<Integer> integerArray = getIntegerValues(argument);
            if (!integerArray.isEmpty()) {
                return integerArray.get(0);
            }
        }
        return null;
    }

    private static String getArgument(String key) {
        for (String argument : parameters) {
            if (argument.startsWith(key)) {
                return argument.substring(key.length());
            }
        }
        return null;
    }

    private static List<Integer> getIntegerValues(String parameterString) {
        Matcher matcher = integerPattern.matcher(parameterString);

        List<Integer> returnList = new ArrayList<Integer>();

        while (matcher.find()) {
            String stringValue = parameterString.substring(matcher.start() + 1, matcher.end());
            try {
                returnList.add(Integer.valueOf(stringValue));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(stringValue + " couldn't be parsed as an integer.");
            }
        }

        return returnList;
    }


    private static List<String> getStringValues(String parameterString) {
        Matcher matcher = stringPattern.matcher(parameterString);

        List<String> returnList = new ArrayList<String>();

        while (matcher.find()) {
            String stringValue = parameterString.substring(matcher.start() + 1, matcher.end());
            returnList.add(stringValue);
        }

        return returnList;
    }

}
