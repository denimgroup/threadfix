package com.denimgroup.threadfix.service.defects.utils;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.InputStream;
import java.net.HttpURLConnection;

// Having the interface allows us to mock for testing.
public interface RestUtils {

    public boolean hasXSeraphLoginReason(String urlString, String username, String password);

    public String getUrlAsString(String urlString, String username, String password);

    public String postUrlAsString(String urlString, String data, String username, String password, String contentType);

    public String getPostErrorResponse();

    /**
     *
     * @param urlString JIRA URL to connect to
     * @return true if we get an HTTP 401, false if we get another HTTP response code (such as 200:OK)
     * 		or if an exception occurs
     */
    public boolean requestHas401Error(String urlString);

}
