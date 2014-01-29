package com.denimgroup.threadfix.remote.response;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.io.InputStream;
import java.lang.reflect.Type;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Scanner;

public class ResponseParser {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(ResponseParser.class);

    private static <T> Type getTypeReference() {
        return new TypeReference<RestResponse<T>>(){}.getType();
    }

    private static Gson getGson() {
        GsonBuilder gsonB = new GsonBuilder();
        gsonB.registerTypeAdapter(Calendar.class, new CalendarSerializer());
        gsonB.registerTypeAdapter(GregorianCalendar.class, new CalendarSerializer());
        return gsonB.create();
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
                } else {
                    // turn the inner object into the correctly typed object
                    response.object = gson.fromJson(innerJson, internalClass);
                    LOGGER.debug("Parsed result into " + internalClass.getName() + " correctly.");
                }
            } catch (JsonSyntaxException e) {
                LOGGER.error("Encountered JsonSyntaxException", e);
            }
        }

        response.responseCode = responseCode;

        LOGGER.debug("Setting response code to " + responseCode + ".");

        return response;
    }

    public static <T> RestResponse<T> getRestResponse(InputStream responseStream, int responseCode, Class<T> target) {
        String inputString = convertStreamToString(responseStream);

        return getRestResponse(inputString, responseCode, target);
    }

    public static <T> RestResponse<T> getErrorResponse(String errorText, int responseCode) {
        RestResponse<T> instance = new RestResponse<T>();

        instance.message = errorText;
        instance.responseCode = responseCode;
        instance.success = false;

        return instance;
    }

    // from https://weblogs.java.net/blog/pat/archive/2004/10/stupid_scanner_1.html
    private static String convertStreamToString(InputStream inputStream) {
        Scanner s = new Scanner(inputStream, "UTF-8").useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

}
