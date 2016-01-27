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

package com.denimgroup.threadfix.remote.response;

import com.denimgroup.threadfix.util.Result;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;

/**
 * This is the basic RestResponse which is returned by all the methods on the ThreadFix server side.
 */
public class RestResponse<T> {

    @JsonView(Object.class)
    public String message = "";
    @JsonView(Object.class)
    public boolean success = false;
    @JsonView(Object.class)
    public int responseCode = -1;
    @JsonView(Object.class)
    public T object = null;

    String jsonString = null;

    public static <T> RestResponse<T> failure(String response) {
        RestResponse<T> restResponse = new RestResponse<T>();
        restResponse.message = response;
        return restResponse;
    }

    public static <T> RestResponse<T> success(T object) {
        RestResponse<T> restResponse = new RestResponse<T>();
        restResponse.success = true;
        restResponse.object  = object;
        return restResponse;
    }

    public static <T> RestResponse<T> resultError(Result result) {
        return failure(result.getErrorMessage());
    }

    @JsonIgnore
    public String getOriginalJson() {
        return jsonString;
    }

    public void setJsonString(String jsonString) {
        this.jsonString = jsonString;
    }

    public String toString() {
        return jsonString;
    }

}
