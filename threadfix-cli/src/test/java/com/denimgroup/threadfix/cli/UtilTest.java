package com.denimgroup.threadfix.cli;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Created with IntelliJ IDEA.
 * User: stran
 * Date: 11/21/13
 * Time: 4:00 PM
 * To change this template use File | Settings | File Templates.
 */
public class UtilTest {

    public static final String URL = "http://localhost:8080/threadfix/rest";
    public static final String API_KEY = "N5bfcd6L00QLR5jdsaA76YEtkZ7LEWotk43AjOkfmoo";

    public static JSONObject getJSONObject(String responseContents) {
        if (responseContents == null)
            return null;
        try {
            return new JSONObject(responseContents);
        } catch (JSONException e) {
            return null;
        }
    }
}
