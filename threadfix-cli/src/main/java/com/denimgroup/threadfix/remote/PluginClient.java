package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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
    }

    public PluginClient(PropertiesManager manager) {
        httpRestUtils = new HttpRestUtils(manager);
    }

    @NotNull
    public Application.Info[] getThreadFixApplications() {
        Application.Info[] appInfoArray = getItem("code/applications", Application.Info[].class);
        return appInfoArray == null ? new Application.Info[]{} : appInfoArray;
    }

    @NotNull
    public VulnerabilityMarker[] getVulnerabilityMarkers(String appId) {
        VulnerabilityMarker[] markers = getItem("code/markers/" + appId, VulnerabilityMarker[].class);
        return markers == null ? new VulnerabilityMarker[]{} : markers;
    }

    @NotNull
    public Endpoint.Info[] getEndpoints(String appId) {
        Endpoint.Info[] endpoints = getItem("code/applications/" + appId + "/endpoints", Endpoint.Info[].class);
        return endpoints == null ? new Endpoint.Info[]{} : endpoints;
    }

    @NotNull
    public RestResponse<Object> uploadScan(String appId, File inputFile) {
        return httpRestUtils.httpPostFile("applications/" + appId + "/upload",
                inputFile, new String[]{}, new String[]{}, Object.class);
    }

    @Nullable
    private <T> T getItem(String path, Class<T> targetClass) {
        RestResponse<T> appsInfo = httpRestUtils.httpGet(path, "", targetClass);

        if (appsInfo.success) {
            return appsInfo.object;
        } else {
            LOGGER.error("Request for ThreadFix data failed at " + path +
                    ". Reason: " + appsInfo.message);
            return null;
        }
    }

}
