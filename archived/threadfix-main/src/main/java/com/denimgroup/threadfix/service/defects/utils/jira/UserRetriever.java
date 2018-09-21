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
package com.denimgroup.threadfix.service.defects.utils.jira;

import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.importer.util.JsonUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import org.json.JSONArray;
import org.json.JSONException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by mac on 7/11/14.
 */
public class UserRetriever {

    private static final SanitizedLogger LOG = new SanitizedLogger(UserRetriever.class);

    final String username, password, url, project;
    final RestUtils restUtils;

    public UserRetriever(String username, String password, String project, String urlWithRest, RestUtils restUtils) {
        this.username = username;
        this.password = password;
        this.project = project;
        this.url = urlWithRest;
        this.restUtils = restUtils;
    }

    public Map<String, String> getUserMap() {

        String extension = "user/permission/search?projectKey=" + project
                + "&permissions=ASSIGNABLE_USER&username";

        LOG.debug("Requesting " + url + extension);
        Map<String, String> nameFieldMap = new HashMap<>();

        try {
            String result = restUtils.getUrlAsString(url + extension, username, password);

            LOG.debug("Got " + result);

            if (result == null) {
                assert false : "Got null result for project " + project + ".";
                return null;
            }

            JSONArray returnArray = JsonUtils.getJSONArray(result);

            if (returnArray != null) {
                for (int i = 0; i < returnArray.length(); i++) {
                    try {
                        String name = returnArray.getJSONObject(i).getString("name");
                        nameFieldMap.put(name, name);
                    } catch (JSONException e) {
                        e.printStackTrace();
                    }
                }
            }

            LOG.debug("Returning map with " + nameFieldMap.size() + " entries.");

        } catch (RestIOException e) {

            nameFieldMap = null;
            LOG.debug("Exception happens", e);
            throw new RestIOException(e, "Unable to get response from server.");

        } finally {
            return nameFieldMap;
        }

    }

}
