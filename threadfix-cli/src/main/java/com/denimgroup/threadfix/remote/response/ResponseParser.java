package com.denimgroup.threadfix.remote.response;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;

public class ResponseParser {

    private static <T> Type getTypeReference() {
        return new TypeReference<RestResponse<T>>(){}.getType();
    }

    // TODO remove the double JSON read for efficiency
    // I still think this will be IO-bound in most cases
    public static <T> RestResponse<T> getRestResponse(String responseString, int responseCode, Class<T> internalClass) {
        RestResponse<T> response = new RestResponse<T>();

        if (responseString != null && responseString.trim().indexOf('{') == 0) {
            try {
                Gson gson = new Gson();
                response = gson.fromJson(responseString, getTypeReference()); // turn everything into an object
                String innerJson = gson.toJson(response.object); // turn the inner object back into a string
                // turn the inner object into the correctly typed object
                response.object = gson.fromJson(innerJson, internalClass);
            } catch (JsonSyntaxException e) {
                System.out.println("Encountered JsonSyntaxException");
                e.printStackTrace();
            }
        }

        response.responseCode = responseCode;

        return response;
    }

    public static <T> RestResponse<T> getRestResponse(InputStream responseStream, int responseCode, Class<T> target) {
        String inputString = null;

        try {
            inputString = IOUtils.toString(responseStream);
        } catch (IOException e) {
            e.printStackTrace();
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
