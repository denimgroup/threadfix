package com.denimgroup.threadfix.service.defects.utils;

import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Created by mac on 4/4/14.
 */
public class JsonUtils {

    private static final SanitizedLogger LOG = new SanitizedLogger(JsonUtils.class);

    /**
     * Convenience method to wrap the exception catching.
     * TODO validate to save generating an exception on invalid input
     * @param responseContents
     * @return
     */
    public static JSONArray getJSONArray(String responseContents) {
        try {
            return new JSONArray(responseContents);
        } catch (JSONException e) {
            LOG.warn("JSON Parsing failed.", e);
            return null;
        }
    }

    /**
     * Convenience method to wrap the exception catching.
     * TODO validate to save generating an exception on invalid input
     * @param responseContents
     * @return
     */
    public static JSONObject getJSONObject(String responseContents) {
        try {
            return new JSONObject(responseContents);
        } catch (JSONException e) {
            LOG.warn("JSON Parsing failed.", e);
            return null;
        }
    }

}
