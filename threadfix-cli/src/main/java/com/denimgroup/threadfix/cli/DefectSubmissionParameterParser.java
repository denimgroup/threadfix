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
import com.denimgroup.threadfix.viewmodels.DynamicFormField;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.remote.response.RestResponse.failure;
import static com.denimgroup.threadfix.remote.response.RestResponse.success;

/**
 * @author zabdisubhan
 */
public class DefectSubmissionParameterParser extends GenericParameterParser {

    static String[] parameters = null;

    public static RestResponse<Object> processDefectSubmissionParameters(ThreadFixRestClient client,
                                                                                         String... args) {

        setParameters(collapseParameters(args)); // This makes me cringe but it's single-threaded right?

        RestResponse<?> result = checkArguments(client);
        if (!result.success) {
            return (RestResponse<Object>) result;
        }

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
    private static RestResponse checkArguments(ThreadFixRestClient client) {
        List<String> validParameters = list("applicationId", "vulnerabilityIds");
        Integer appId = getIntegerValue("applicationId");

        if (appId == null) {
            return failure("Please specify the application's ID with applicationId={id here}");
        }

        RestResponse<DynamicFormField[]> response = client.getDefectTrackerFields(appId);
        if (!response.success) {
            return response;
        }

        DynamicFormField[] dynamicFormFields = response.object;

        if (dynamicFormFields == null || dynamicFormFields.length == 0) {
            return failure("No fields returned from Defect Tracker");
        }

        for (String parameter : getParameters()) {
            if (!parameter.contains("=")) {
                return failure(parameter + " was invalid. Expected format is <key>=<value>");
            }

            String shorterName = getParameterName(parameter);

            for (DynamicFormField dynamicFormField : dynamicFormFields) {
                validParameters.add(dynamicFormField.getName());
            }

            if (!validParameters.contains(shorterName)) {
                return failure(parameter + " was invalid. The key should be one of " + validParameters);
            }
        }

        return success(null);
    }
}
