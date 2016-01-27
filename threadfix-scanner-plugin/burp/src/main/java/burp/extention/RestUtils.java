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

package burp.extention;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.io.File;

public class RestUtils {

    private RestUtils(){}

    public static RestResponse<Object> uploadScan(File file) {

        if (BurpPropertiesManager.getBurpPropertiesManager().getUrl() == null || BurpPropertiesManager.getBurpPropertiesManager().getKey() == null) {
            return RestResponse.failure("Url and API key were not saved correctly.");
        }

        return getPluginClient().uploadScan(BurpPropertiesManager.getBurpPropertiesManager().getAppId(), file);
    }

    public static Application.Info[] getApplications() {
        return getPluginClient().getThreadFixApplications();
    }

    public static Endpoint.Info[] getEndpoints() {
        return getPluginClient().getEndpoints(BurpPropertiesManager.getBurpPropertiesManager().getAppId());
    }

    private static PluginClient getPluginClient() {
        return new PluginClient(BurpPropertiesManager.getBurpPropertiesManager());
    }
}
