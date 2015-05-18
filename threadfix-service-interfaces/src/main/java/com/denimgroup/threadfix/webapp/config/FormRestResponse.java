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

package com.denimgroup.threadfix.webapp.config;

import com.denimgroup.threadfix.remote.response.RestResponse;
import com.denimgroup.threadfix.webapp.utils.MessageConstants;
import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.map;

/**
 * This is the basic RestResponse which is returned by all the methods on the ThreadFix server side.
 */
public class FormRestResponse<T> extends RestResponse<T> {

    @JsonView(Object.class)
    public Map<String, String> errorMap;

    public static <T> FormRestResponse<T> failure(String response, Map<String, String> errorMap) {
        FormRestResponse<T> restResponse = new FormRestResponse<T>();
        restResponse.errorMap = errorMap;
        restResponse.message = response;
        return restResponse;
    }

    public static <T> FormRestResponse<T> failure(String response, BindingResult result) {
        return failure(response, result, new HashMap<String, String>()); // Java 8 will be able to figure this out
    }

    public static <T> FormRestResponse<T> failure(String response, BindingResult result, Map<String,String> errors) {
        FormRestResponse<T> restResponse = new FormRestResponse<T>();

        Map<String, String> resultMap = map();
        resultMap.putAll(errors);
        if (result != null) {
            if (result.getFieldErrors() != null && result.getFieldErrors().size() > 0) {
                resultMap = map();
                for (FieldError error : result.getFieldErrors()) {
                    String value = getErrorMessage(error);
                    String field = error.getField().replace(".", "_");
                    resultMap.put(field, value);
                }
            }
        }

        restResponse.errorMap = resultMap;
        restResponse.message = response;
        return restResponse;
    }

    public static <T> FormRestResponse<T> failure(String response, String field, String fieldErrorMessage) {
        FormRestResponse<T> restResponse = new FormRestResponse<T>();

        Map<String, String> resultMap = map();
        resultMap.put(field, fieldErrorMessage);

        restResponse.errorMap = resultMap;
        restResponse.message = response;
        return restResponse;
    }

    private static String getErrorMessage(FieldError error) {
        if (error.getDefaultMessage() != null)
            return error.getDefaultMessage();
        String code = error.getCode();
        String[] args = null;
        if (error.getArguments() != null)
            args = (String[]) error.getArguments();
        return MessageConstants.getValue(code, args);

    }
}
