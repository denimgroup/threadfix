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

package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.RestResponse;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;

// TODO use unchecked exceptions for stuff like the threadfix server not being found or the wrong data coming back.
// TODO figure out how to instantiate array objects from their class objects.
public class PluginClient {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(PluginClient.class);

    final HttpRestUtils httpRestUtils;

    public PluginClient(String url, String key) {
        PropertiesManager propertiesManager = new PropertiesManager();
        propertiesManager.setMemoryKey(key);
        propertiesManager.setUrl(url);
        httpRestUtils = new HttpRestUtils(propertiesManager);

        String baseUrl = httpRestUtils.propertiesManager.getUrl();
        if (!baseUrl.endsWith("/")) {
            httpRestUtils.propertiesManager.setUrl(baseUrl + "/");
        }
    }

    public PluginClient(PropertiesManager manager) {
        httpRestUtils = new HttpRestUtils(manager);
    }

    @Nonnull
    public Application.Info[] getThreadFixApplications() {
        Application.Info[] appInfoArray = getItem("code/applications", Application.Info[].class);
        return appInfoArray == null ? new Application.Info[]{} : appInfoArray;
    }

    @Nonnull
    public RestResponse<Application.Info[]> getThreadFixApplicationsResponse() {
        RestResponse<Application.Info[]> response = getRestResponse("code/applications", Application.Info[].class);
        return response;
    }

    @Nonnull
    public VulnerabilityMarker[] getVulnerabilityMarkers(String appId) {
        VulnerabilityMarker[] markers = getItem("code/markers/" + appId, VulnerabilityMarker[].class);
        return markers == null ? new VulnerabilityMarker[]{} : markers;
    }

    @Nonnull
    public Endpoint.Info[] getEndpoints(String appId) {
        Endpoint.Info[] endpoints = getItem("code/applications/" + appId + "/endpoints", Endpoint.Info[].class);
        return endpoints == null ? new Endpoint.Info[]{} : endpoints;
    }

    @Nonnull
    public RestResponse<Endpoint.Info[]> getEndpointsResponse(String appId) {
        RestResponse<Endpoint.Info[]> response = getRestResponse("code/applications/" + appId + "/endpoints", Endpoint.Info[].class);
        return response;
    }

    @Nonnull
    public RestResponse<Object> uploadScan(String appId, File inputFile) {
        return httpRestUtils.httpPostFile("applications/" + appId + "/upload",
                inputFile, new String[]{}, new String[]{}, Object.class);
    }

    @Nullable
    private <T> T getItem(String path, Class<T> targetClass) {
        RestResponse<T> response = getRestResponse(path, targetClass);

        if (response.success) {
            return response.object;
        } else {
            return null;
        }
    }

    @Nullable
    private <T> RestResponse<T> getRestResponse(String path, Class<T> targetClass) {
        RestResponse<T> response = httpRestUtils.httpGet(path, "", targetClass);

        if (!response.success) {
            LOGGER.error("Request for ThreadFix data failed at " + path +
                    ". Reason: " + response.message);
        }
        return response;
    }

}
