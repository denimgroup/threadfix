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
public class VulnSearchParameterParser extends GenericParameterParser {

    static final private List<String> validParameters = list("genericVulnerabilityIds", "teamIds",
            "applicationIds", "scannerNames", "genericSeverityValues", "numberVulnerabilities", "parameter",
            "path", "startDate", "endDate", "showOpen", "showClosed", "showFalsePositive", "showHidden", "numberMerged",
            "showDefectPresent", "showDefectNotPresent", "showDefectOpen", "showDefectClosed");

    public static RestResponse<VulnerabilityInfo[]> processVulnerabilitySearchParameters(ThreadFixRestClient client,
                                                                                         String... args) {

        setParameters(collapseParameters(args)); // This makes me cringe but it's single-threaded right?

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
                getBooleanValue("showDefectClosed")
        );
    }

    private static void checkArguments() {
        for (String parameter : getParameters()) {
            if (!parameter.contains("=")) {
                throw new IllegalArgumentException(parameter + " was invalid. Expected format is <key>=<value>");
            }

            String shorterName = parameter.substring(0, parameter.indexOf('='));

            if (!validParameters.contains(shorterName)) {
                throw new IllegalArgumentException(parameter + " was invalid. The key should be one of " + validParameters);
            }
        }
    }
}
