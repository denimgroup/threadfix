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

package com.denimgroup.threadfix.remote.response;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;

public class ResponseParser {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(ResponseParser.class);

    private static <T> Type getTypeReference() {
        return new TypeReference<RestResponse<T>>(){}.getType();
    }

    private static Gson getGson() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Calendar.class, new CalendarSerializer());
        gsonBuilder.registerTypeAdapter(GregorianCalendar.class, new CalendarSerializer());
        gsonBuilder.registerTypeAdapter(Date.class, new DateSerializer());
        gsonBuilder.registerTypeAdapter(byte[].class, new ByteToStringSerializer()); // needed for files.
        return gsonBuilder.create();
    }

    // TODO remove the double JSON read for efficiency
    // I still think this will be IO-bound in most cases
    @SuppressWarnings("unchecked") // the JSON String preservation broke this
    public static <T> RestResponse<T> getRestResponse(String responseString, int responseCode, Class<T> internalClass) {

        LOGGER.debug("Parsing response for type " + internalClass.getCanonicalName());

        RestResponse<T> response = new RestResponse<T>();

        if (responseString != null && responseString.trim().indexOf('{') == 0) {
            try {
                Gson gson = getGson();
                response = gson.fromJson(responseString, getTypeReference()); // turn everything into an object
                String innerJson = gson.toJson(response.object); // turn the inner object back into a string

                if (response.object instanceof String) {
                    // No need to do any more work
                    response.object = (T) innerJson;
                    LOGGER.debug("Parsed inner object as JSON String correctly.");
                }  else {
                    // turn the inner object into the correctly typed object
                    response.object = gson.fromJson(innerJson, internalClass);
                    LOGGER.debug("Parsed result into " + internalClass.getName() + " correctly.");
                }
            } catch (JsonSyntaxException e) {
                LOGGER.error("Encountered JsonSyntaxException", e);
            }
        }

        response.responseCode = responseCode;
        response.jsonString = responseString;

        LOGGER.debug("Setting response code to " + responseCode + ".");

        return response;
    }

    public static <T> RestResponse<T> getRestResponse(InputStream responseStream, int responseCode, Class<T> target) {
        String inputString = null;
        try {
            inputString = IOUtils.toString(responseStream, "UTF-8");
        } catch (IOException e) {
            LOGGER.error("Unable to parse response stream due to IOException.", e);
        }

        return getRestResponse(inputString, responseCode, target);
    }

    public static <T> RestResponse<T> getErrorResponse(String errorText, int responseCode) {
        RestResponse<T> instance = new RestResponse<T>();

        instance.message = errorText;
        instance.responseCode = responseCode;
        instance.success = false;

        return instance;
    }

}
