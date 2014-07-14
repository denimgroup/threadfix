////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.service.defects.utils.JsonUtils;
import com.denimgroup.threadfix.service.defects.utils.RestUtils;
import org.json.JSONArray;
import org.json.JSONException;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by mac on 7/11/14.
 */
public class FieldRetriever {

    String username, password, url;
    RestUtils restUtils;

    public FieldRetriever(String username, String password, String url, RestUtils restUtils) {
        this.username = username;
        this.password = password;
        this.url = url;
        this.restUtils = restUtils;
    }

    public Map<String, String> getOptions(String path) {

        System.out.println("Requesting " + url + path);

        String result = restUtils.getUrlAsString(url + path, username, password);

        System.out.println("Got " + result);

        if (result == null) {
            assert false : "This method should only be called with a valid connection.";
            return null;
        }

        JSONArray returnArray = JsonUtils.getJSONArray(result);

        Map<String, String> nameFieldMap = new HashMap<>();

        if (returnArray != null) {
            for (int i = 0; i < returnArray.length(); i++) {
                try {
                    nameFieldMap.put(returnArray.getJSONObject(i).getString("name"),
                            returnArray.getJSONObject(i).getString("key"));
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }

        return nameFieldMap;
    }

}
