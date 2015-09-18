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

import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
import com.google.gson.Gson;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * @author zabdisubhan
 */
public class DefectSubmissionParameterParser extends GenericParameterParser {

    static String[] parameters = null;

    public static RestResponse<Object> processDefectSubmissionParameters(ThreadFixRestClient client,
                                                                                         String... args) {

        setParameters(collapseParameters(args)); // This makes me cringe but it's single-threaded right?

        checkArguments(client);

        String[] params = getParameters();
        List<String> paramNames  = list();
        List<String> paramValues = list();

        for (String param : params) {
            String paramName = getParameterName(param);

            if (param.contains(",")) {

                List<Integer> vulnIds = getIntegerArray(paramName);

                for (Integer vulnId : vulnIds) {
                    paramNames.add(paramName);
                    paramValues.add(vulnId.toString());
                }
            } else {
                paramNames.add(paramName);
                paramValues.add(getStringValue(paramName));
            }
        }

        String[] paramNamesArr = paramNames.toArray(new String[paramNames.size()]);
        String[] paramValuesArr = paramValues.toArray(new String[paramValues.size()]);
        Integer appId = getIntegerValue("applicationId");

        return client.submitDefect(paramNamesArr, paramValuesArr, appId);
    }

    @SuppressWarnings("unchecked")
    private static void checkArguments(ThreadFixRestClient client) {
        List<String> validParameters = list("applicationId", "vulnerabilityIds");
        Integer appId = getIntegerValue("applicationId");

        if (appId == null) {
            throw new IllegalArgumentException("No application id was provided in arguments");
        }

        String jsonString = client.getDefectTrackerFields(appId).getOriginalJson();
        Map<?, ?> response = new Gson().fromJson(jsonString, HashMap.class);

        if (response == null) {
            throw new IllegalArgumentException("No fields to return from Defect Tracker");
        }

        List<Map<String, String>> dynamicFormFields = (List<Map<String, String>>)response.get("object");

        for (String parameter : getParameters()) {
            if (!parameter.contains("=")) {
                throw new IllegalArgumentException(parameter + " was invalid. Expected format is <key>=<value>");
            }

            String shorterName = getParameterName(parameter);

            if (dynamicFormFields == null) {
                throw new IllegalArgumentException("No fields to return from Defect Tracker");
            }

            for (Map<String,String> map : dynamicFormFields) {
                validParameters.add(map.get("name"));
            }

            if (!validParameters.contains(shorterName)) {
                throw new IllegalArgumentException(parameter + " was invalid. The key should be one of " + validParameters);
            }
        }
    }
}
