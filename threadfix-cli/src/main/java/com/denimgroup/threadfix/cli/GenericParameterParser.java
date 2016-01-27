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

package com.denimgroup.threadfix.cli;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author zabdisubhan
 */
public class GenericParameterParser {
    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd-MMM-yyyy");

    private static final Pattern integerPattern = Pattern.compile("[\\,=]([0-9]+)");
    private static final Pattern stringPattern  = Pattern.compile("[\\,=]([^,=]+)");

    static String[] parameters = null;

    public static String[] getParameters() {
        return parameters;
    }

    public static void setParameters(String[] parameters) {
        GenericParameterParser.parameters = parameters;
    }

    // This lets us handle fun stuff like scannerNames=Arachni,Cenzic Hailstorm
    protected static String[] collapseParameters(String[] parameters) {
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

    protected static List<Integer> getIntegerArray(String key) {
        String argument = getArgument(key);
        return argument != null ? getIntegerValues(argument) : null;
    }

    protected static List<String> getStringArray(String key) {
        String argument = getArgument(key);
        return argument != null ? getStringValues(argument) : null;
    }

    protected static Boolean getBooleanValue(String key) {
        String stringValue = getStringValue(key);
        return Boolean.parseBoolean(stringValue);
    }

    protected static Date getDateValue(String key) {
        String stringValue = getStringValue(key);
        try {
            return stringValue == null ? null : DATE_FORMAT.parse(stringValue);
        } catch (ParseException e) {
            throw new IllegalArgumentException(stringValue + " was not a valid date string. Please use the format " +
                    DATE_FORMAT.toPattern());
        }
    }

    protected static String getStringValue(String key) {
        String argument = getArgument(key);
        if (argument != null) {
            List<String> stringArray = getStringValues(argument);
            if (!stringArray.isEmpty()) {
                return stringArray.get(0);
            }
        }
        return null;
    }

    protected static Integer getIntegerValue(String key) {
        String argument = getArgument(key);
        if (argument != null) {
            List<Integer> integerArray = getIntegerValues(argument);
            if (!integerArray.isEmpty()) {
                return integerArray.get(0);
            }
        }
        return null;
    }

    protected static String getArgument(String key) {
        for (String argument : parameters) {
            if (argument.startsWith(key)) {
                return argument.substring(key.length());
            }
        }
        return null;
    }

    protected static List<Integer> getIntegerValues(String parameterString) {
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

    protected static List<String> getStringValues(String parameterString) {
        Matcher matcher = stringPattern.matcher(parameterString);

        List<String> returnList = new ArrayList<String>();

        while (matcher.find()) {
            String stringValue = parameterString.substring(matcher.start() + 1, matcher.end());
            returnList.add(stringValue);
        }

        return returnList;
    }

    protected static String getParameterName(String parameter) {
        return parameter.substring(0, parameter.indexOf('='));
    }

}
