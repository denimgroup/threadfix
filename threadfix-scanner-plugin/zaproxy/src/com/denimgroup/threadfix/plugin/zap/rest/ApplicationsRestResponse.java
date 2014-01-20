package com.denimgroup.threadfix.plugin.zap.rest;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by mac on 1/20/14.
 */
public class ApplicationsRestResponse {

    private final RestResponse baseResponse;

    public ApplicationsRestResponse(RestResponse baseResponse) {
        this.baseResponse = baseResponse;
    }

    public RestResponse getBaseResponse() {
        return baseResponse;
    }

    public Iterable<Application> getApplications() {
        JSONObject object = null;

        if (baseResponse != null) {
            object = baseResponse.getInnerObject();
        }

        List<Application> apps = new ArrayList<>();

        if (object != null) {
            try {
                apps.add(new Application(object.getString("applicationName"), object.getString("applicationId"), object.getString("organizationName")));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }

        return apps;
    }
}
