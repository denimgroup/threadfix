package com.denimgroup.threadfix.service.defects;

import com.denimgroup.threadfix.service.defects.utils.RestUtils;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertTrue;

public class RestUtilsMock implements RestUtils, TestConstants {

    public static final Map<String, String> urlToResponseMap = new HashMap<>();
    static {
        urlToResponseMap.put("/rest/api/2/search", "jira-issue-search");
        urlToResponseMap.put("/rest/api/2/priority", "jira-priorities");
        urlToResponseMap.put("/rest/api/2/project", "jira-projects");
        urlToResponseMap.put("/rest/api/2/issue", "jira-issue-submit");
        urlToResponseMap.put("/rest/api/2/project/NCT/components", "jira-nct-components");
        urlToResponseMap.put("/rest/api/2/issue/PDP-57", "jira-issue-status");
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
        return getResponse(urlString, username, password);
    }

    @Override
    public String getPostErrorResponse() {
        return null;
    }

    @Override
    public boolean requestHas401Error(String urlString) {
        return urlString.equals(JIRA_BASE_URL + "/rest/api/2/user");
    }

    @Override
    public boolean hasXSeraphLoginReason(String urlString, String username, String password) {
        return false;
    }
}
