package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class RestUtilsMock implements RestUtils, TestConstants {

    boolean reporterRestricted = false;

    private String postErrorResponse = null;

    public static final Map<String, String> urlToResponseMap = new HashMap<>();
    static {
        urlToResponseMap.put("/rest/api/2/search", "jira-issue-search");
        urlToResponseMap.put("/rest/api/2/priority", "jira-priorities");
        urlToResponseMap.put("/rest/api/2/project/", "jira-projects");
        urlToResponseMap.put("/rest/api/2/project", "jira-projects");
        urlToResponseMap.put("/rest/api/2/issue", "jira-issue-submit");
        urlToResponseMap.put("/rest/api/2/project/NCT/components", "jira-nct-components");
        urlToResponseMap.put("/rest/api/2/issue/NCT-38", "jira-issue-status-NCT-38");
        urlToResponseMap.put("/rest/api/2/issue/PDP-60", "jira-issue-status-PDP-60");
        urlToResponseMap.put("/rest/api/2/user?username=threadfix", "jira-user-search");

        for (String value : urlToResponseMap.values()) {
            assertTrue("Missing file for " + value, HttpTrafficFileLoader.getResponse(value) != null);
        }
    }

    @Override
    public String getUrlAsString(String urlString, String username, String password) {
        return getResponse(urlString, username, password);
    }

    private String getResponse(String urlString, String username, String password) {
        if (JIRA_USERNAME.equals(username) && JIRA_PASSWORD.equals(password)) {
            for (Map.Entry<String, String> entry : urlToResponseMap.entrySet()) {
                if ((JIRA_BASE_URL + entry.getKey()).equals(urlString)) {
                    return HttpTrafficFileLoader.getResponse(entry.getValue());
                }
            }
        }
        return null;
    }

    @Override
    public String postUrlAsString(String urlString, String data, String username, String password, String contentType) {
        if ((JIRA_BASE_URL + "/rest/api/2/issue").equals(urlString) && hasReporter(data) && reporterRestricted) {
            postErrorResponse = "{\"errorMessages\":[],\"errors\":{\"reporter\":\"Field 'reporter' cannot be set. It is not on the appropriate screen, or unknown.\"}}";
            return null;
        } else {
            return getResponse(urlString, username, password);
        }
    }

    private boolean hasReporter(String data) {
        Map<?, ?> map = new Gson().fromJson(data, HashMap.class);

        return ((Map)map.get("fields")).get("reporter") != null;
    }

    @Override
    public String getPostErrorResponse() {
        return postErrorResponse;
    }

    @Override
    public boolean requestHas401Error(String urlString) {
        return urlString.equals(JIRA_BASE_URL + "/rest/api/2/user");
    }

    // TODO actually test this
    @Override
    public boolean hasXSeraphLoginReason(String urlString, String username, String password) {
        return false;
    }
}
