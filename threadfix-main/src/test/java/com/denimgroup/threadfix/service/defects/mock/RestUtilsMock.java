////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.service.defects.mock;

////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.service.defects.util.HttpTrafficFileLoader;
import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

import static com.denimgroup.threadfix.service.defects.util.TestConstants.*;
import static org.junit.Assert.assertTrue;

public class RestUtilsMock implements RestUtils {

    // don't do this in actual code
    public boolean reporterRestricted = false;

    private String postErrorResponse = null;

    public static final Map<String, String> urlToResponseMap = new HashMap<>();
    static {
        urlToResponseMap.put("/rest/api/2/search", "jira/issue-search");
        urlToResponseMap.put("/rest/api/2/priority", "jira/priorities");
        urlToResponseMap.put("/rest/api/2/project/", "jira/projects");
        urlToResponseMap.put("/rest/api/2/project", "jira/projects");
        urlToResponseMap.put("/rest/api/2/issue", "jira/issue-submit");
        urlToResponseMap.put("/rest/api/2/project/NCT/components", "jira/nct-components");
        urlToResponseMap.put("/rest/api/2/issue/NCT-38", "jira/issue-status-NCT-38");
        urlToResponseMap.put("/rest/api/2/issue/PDP-60", "jira/issue-status-PDP-60");
        urlToResponseMap.put("/rest/api/2/user?username=threadfix", "jira/user-search");
        urlToResponseMap.put("/rest/api/2/issue/createmeta?expand=projects.issuetypes.fields&projectKeys=NCT", "jira/issuemetadata");
        urlToResponseMap.put("/rest/api/2/issue/createmeta?expand=projects.issuetypes.fields&projectKeys=NCT&issuetypeIds=1", "jira/issuemetadata");
        urlToResponseMap.put("/rest/api/2/issue/createmeta?expand=projects.issuetypes.fields&projectKeys=TEST", "jira/custom-fields");
        urlToResponseMap.put("/rest/api/2/user/permission/search?projectKey=NCT&permissions=ASSIGNABLE_USER&username", "jira/users");
        urlToResponseMap.put("/rest/api/2/user/permission/search?projectKey=TEST&permissions=ASSIGNABLE_USER&username", "jira/users");

        for (String value : urlToResponseMap.values()) {
            assertTrue("Missing file for " + value, HttpTrafficFileLoader.getResponse(value) != null);
        }
    }

    @Override
    public String getUrlAsString(String urlString, String username, String password) {
        return getResponse(urlString, username, password);
    }

    private String getResponse(String urlString, String username, String password) {

        System.out.println("Got request for " + urlString);

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
            throw new RestIOException(new Exception(), "Throwing mock 401 error.", 401);
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
    public ConnectionStatus checkConnectionStatus(String urlString) {
        if (urlString.equals(JIRA_BASE_URL + "/rest/api/2/user")) {
            return ConnectionStatus.UNAUTHORIZED;
        } else {
            return ConnectionStatus.OTHER;
        }
    }

    // TODO actually test this
    @Override
    public boolean hasXSeraphLoginReason(String urlString, String username, String password) {
        return false;
    }
}
