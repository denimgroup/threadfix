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
package com.denimgroup.threadfix.importer.impl.upload.fortify;

import com.denimgroup.threadfix.importer.util.RegexUtils;

import java.util.regex.Pattern;

import static com.denimgroup.threadfix.importer.impl.upload.fortify.RegexMaps.SPECIAL_REGEX_MAP;

/**
 * Created by mcollins on 2/16/15.
 */
public class ParameterParser {

    /**
     * TODO clean up / improve
     * @param action
     * @param line
     * @return the resulting parameter
     */
    static String getParameterName(String action, String line, FortifyChannelImporter.FortifySAXParser saxParser) {
        boolean tookOutReturn = false;

        String parameter = null;

        String functionName = RegexUtils.getRegexResult(action, "^([^?\\(\\[]*)");
        if (functionName == null){
            return null;
        }

        String argument = RegexUtils.getRegexResult(action, functionName + "\\(\"?([^\"]+\"?)\\)");

        if ("main".equals(functionName)) {
            saxParser.paramParsed = true;
        }

        if (argument == null
                || "this.myName".equals(argument)
                || "error".equals(functionName)
                || "main".equals(functionName)) {
            return null;
        }

        boolean isObjectOfCall = argument.startsWith("this");

        String strippedNumbers = RegexUtils.getRegexResult(argument, "^([0-9]+)");

        if (argument.contains(" : return")) {
            tookOutReturn = true;
            argument = argument.replaceAll(" : return\\[?\\]?","");
        }
        int number = FortifyUtils.getNumber(strippedNumbers);

        if (argument != null) {

            if (SPECIAL_REGEX_MAP.containsKey(functionName)) {
                parameter = RegexUtils.getRegexResult(line, SPECIAL_REGEX_MAP.get(functionName));
            }

            if (parameter == null && isObjectOfCall) {
                parameter = RegexUtils.getRegexResult(line, "([a-zA-Z0-9_\\[]+\\]?)\\." + Pattern.quote(functionName));
            } else if (number != -1) {
                if (line.contains(functionName)) {
                    String commas = "";
                    while (number-- != 0) {
                        commas = commas + "[^,]+,";
                    }

                    String paramRegex = "([^,\\)]+)";

                    parameter = RegexUtils.getRegexResult(line, Pattern.quote(functionName) + "\\(" + commas + paramRegex);

                    if (tookOutReturn) {
                        String testParameter = RegexUtils.getRegexResult(parameter,
                                "\\([ ]*([a-zA-Z0-9_]+)(?:\\.Text)?[ ]*\\)?$");
                        if (testParameter != null) {
                            parameter = testParameter;
                        }

                        tookOutReturn = false;
                    }
                } else if (functionName.equals("Concat")) {
                    String regex = "([^\\+]*[^;\\+])";
                    while (number-- != 0) {
                        regex = "[^\\+]*\\+" + regex;
                    }
                    regex = "^[^=]+= ?" + regex;
                    String result = RegexUtils.getRegexResult(line, regex);

                    if (result != null && !result.startsWith("\"")
                            && !result.trim().equals("")) {
                        parameter = result;
                    }
                }
            }
        }

        if (parameter == null) {
            return null;
        }

        saxParser.paramParsed = true;

        // This section checks to see if the result is a call to getParameter()
        // if it is, then we can get a valid web parameter out of it.
        String requestParameter = RegexUtils.getRegexResult(parameter,
                ".getParameter\\(\"?([a-zA-Z0-9_]+)\"?\\)");

        // also try GET[] or POST[]
        if (requestParameter == null) {
            requestParameter = RegexUtils.getRegexResult(parameter,
                    "(?:GET|POST)\\[\"([a-zA-Z0-9_]+)\"\\]");
        }

        if (requestParameter != null && !requestParameter.trim().equals("")) {
            parameter = requestParameter;
        }

        // if it passes any of these conditions we probably don't want it
        if (parameter.endsWith("(") || parameter.endsWith("\"") || parameter.endsWith(")") ||
                parameter.startsWith("(") || parameter.startsWith("\"") || parameter.contains("+")) {
            parameter = null;
        }

        return parameter;
    }


}
