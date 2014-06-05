////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

package com.denimgroup.threadfix.cli.util;

import com.denimgroup.threadfix.remote.response.RestResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashSet;
import java.util.Set;

/**
 * Created by mcollins on 6/5/14.
 */
public class JsonTestUtils {

    public static <T> String getId(RestResponse<T> restResponse) {
        assert restResponse.success;

        return getJsonObject(restResponse)
                .getAsJsonObject("object")
                .getAsJsonPrimitive("id")
                .getAsString();

    }

    public static <T> void assertHasFields(RestResponse<T> object, String... fields) {
        // get the nested object
        JsonObject jsonObject = getJsonObject(object).getAsJsonObject("object");

        innerValidate(jsonObject, fields);
    }

    public static <T> void assertHasObjectWithFields(RestResponse<T> restResponse, String objectKey, String... fields) {
        JsonObject jsonObject = getJsonObject(restResponse).getAsJsonObject("object");

        jsonObject = jsonObject.getAsJsonObject(objectKey);

        innerValidate(jsonObject, fields);
    }

    // { [ { field1: value, field2: value } ] }
    public static <T> void assertHasArrayOfObjectsWithFields(RestResponse<T> restResponse, String objectKey, String... fields) {
        JsonArray jsonArray = getJsonObject(restResponse).getAsJsonObject(objectKey).getAsJsonArray("object");

        assert jsonArray != null;

        innerValidate(jsonArray.get(0).getAsJsonObject(), fields);

    }

    public static <T> void assertIsArrayWithFields(RestResponse<T> restResponse, String... fields) {
        JsonArray jsonArray = getJsonObject(restResponse).getAsJsonArray("object");

        assert jsonArray != null;

        innerValidate(jsonArray.get(0).getAsJsonObject(), fields);
    }

    private static <T> JsonObject getJsonObject(RestResponse<T> restResponse) {
        return new JsonParser().parse(restResponse.getOriginalJson()).getAsJsonObject();
    }

    private static void innerValidate(JsonObject jsonObject, String[] fields) {
        Set<String> missingFields = new HashSet<String>();
        for (String field : fields) {
            if (!jsonObject.has(field)) {
                missingFields.add(field);
            }
        }

        assert missingFields.isEmpty() : "JsonObject was missing " + missingFields;
        assert jsonObject.entrySet().size() == fields.length;
    }

}
