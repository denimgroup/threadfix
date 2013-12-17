package com.denimgroup.threadfix.webapp.controller.rest;

/**
 * Created by mac on 12/16/13.
 */
public class RestResponse {

    private boolean success = false;
    private Object object = null;
    private String message = null;

    private RestResponse(){}

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

    // For serialization

    public Object getObject() {
        return object;
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }
}
