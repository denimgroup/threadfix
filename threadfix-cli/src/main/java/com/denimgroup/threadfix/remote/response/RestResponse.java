package com.denimgroup.threadfix.remote.response;

import com.google.gson.Gson;

/**
 * This is the basic RestResponse which is returned by all the methods on the ThreadFix server side.
 */
public class RestResponse<T> {

    public String message = "Failed to parse REST response.";
    public boolean success = false;
    public int responseCode = -1;
    public T object = null;

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

    public String getObjectAsJsonString() {
        return new Gson().toJson(object);
    }

}
