package com.denimgroup.threadfix.remote.response;

import com.google.gson.Gson;

/**
 * This is the basic RestResponse which is returned by all the methods on the ThreadFix server side.
 */
public class RestResponse extends AbstractRestResponse {

    public Object object;

    public static RestResponse failure(String response) {
        RestResponse restResponse = new RestResponse();
        restResponse.message = response;
        return restResponse;
    }

    public static RestResponse success(Object object) {
        RestResponse restResponse = new RestResponse();
        restResponse.success = true;
        restResponse.object  = object;
        return restResponse;
    }

    public String getObjectAsJsonString() {
        return new Gson().toJson(object);
    }

}
