package com.denimgroup.threadfix.remote.response;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;

public class ResponseParser {

    public static <T extends AbstractRestResponse> T getRestResponse(String responseString, int responseCode, Class<T> target) {

        T response = null;

        if (responseString != null && responseString.trim().indexOf('{') == 0) {
            try {
                response = new Gson().fromJson(responseString, target);
            } catch (JsonSyntaxException e) {
                System.out.println("Encountered JsonSyntaxException");
                e.printStackTrace();
            }
        }

        if (response == null) {
            response = instantiateOrNull(target);
        }

        if (response != null) {
            response.responseCode = responseCode;
        }

        return response;
    }

    public static <T extends AbstractRestResponse> T getRestResponse(InputStream responseStream, int responseCode, Class<T> target) {
        String inputString = null;

        try {
            inputString = IOUtils.toString(responseStream);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return getRestResponse(inputString, responseCode, target);
    }

    private static <T extends AbstractRestResponse> T instantiateOrNull(Class<T> target) {
        try {
            return target.newInstance();
        } catch (InstantiationException | IllegalAccessException e1) {
            // It's important to have a no-arg constructor
            e1.printStackTrace();
            return null;
        }
    }

    public static <T extends AbstractRestResponse> T getErrorResponse(String errorText, int responseCode, Class<T> target) {
        T instance = instantiateOrNull(target);

        if (instance != null) {
            instance.message = errorText;
            instance.responseCode = responseCode;
            instance.success = false;
        }

        return instance;
    }

}
