package com.denimgroup.threadfix.plugin.zap.rest;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.InputStream;
import java.io.InputStreamReader;

/**
 * Created by mac on 1/20/14.
 */
public class RestResponse {

    private final InputStream stream;
    final int responseCode;

    private JSONObject jsonObject = null, innerObject = null;
    private boolean wasSuccessful = false;
    private String failureMessage = "Unable to parse JSON return.";

    public RestResponse(InputStream stream, int responseCode) {
        this.stream = stream;
        this.responseCode = responseCode;

        if (stream != null) {
            initializeStream();
        }
    }

    private void initializeStream() {
        try {
            jsonObject     = new JSONObject(new JSONTokener(new InputStreamReader(stream)));
            wasSuccessful  = jsonObject.getBoolean("success");
            innerObject    = jsonObject.getJSONObject("object");
            failureMessage = jsonObject.getString("message");
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public InputStream getInputStream() {
        return stream;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public boolean wasSuccessful() {
        return wasSuccessful;
    }

    public JSONObject getJsonObject() {
        return jsonObject;
    }

    public JSONObject getInnerObject() {
        return innerObject;
    }

    public String getFailureMessage() {
        return failureMessage;
    }
}
