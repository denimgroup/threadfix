package com.denimgroup.threadfix.remote;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.VulnerabilityMarker;
import com.denimgroup.threadfix.framework.engine.full.Endpoint;
import com.denimgroup.threadfix.framework.util.SanitizedLogger;
import com.denimgroup.threadfix.properties.PropertiesManager;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.jetbrains.annotations.Nullable;

// TODO use unchecked exceptions for stuff like the threadfix server not being found or the wrong data coming back.
public class PluginClient {

    private static final SanitizedLogger LOGGER = new SanitizedLogger(PluginClient.class);

    final HttpRestUtils httpRestUtils;

    public PluginClient(String url, String key) {
        PropertiesManager propertiesManager = new PropertiesManager();
        propertiesManager.setMemoryKey(key);
        propertiesManager.setUrl(url);
        httpRestUtils = new HttpRestUtils(propertiesManager);
    }

    @Nullable
    public Application.Info[] getThreadFixApplications() {
        return getItem("code/applications", Application.Info[].class);
    }

    @Nullable
    public VulnerabilityMarker[] getVulnerabilityMarkers(String appId) {
        return getItem("code/markers/" + appId, VulnerabilityMarker[].class);
    }

    @Nullable
    public Endpoint[] getEndpoints(String appId) {
        return getItem("/applications/{appId}/endpoints" + appId, Endpoint[].class);
    }

    @Nullable
    private <T> T getItem(String path, Class<T> targetClass) {
        RestResponse<T> appsInfo = httpRestUtils.httpGet(path, "", targetClass);

        if (appsInfo.success) {
            return appsInfo.object;
        } else {
            LOGGER.error("Request for ThreadFix data failed at " + path +
                    ". Reason: " + appsInfo.message);
            try {
                return targetClass.newInstance();
            } catch (InstantiationException e) {
                LOGGER.error("Encountered InstantiationException while trying to instantiate new class. " +
                        "This indicates a programming error.", e);
            } catch (IllegalAccessException e) {
                LOGGER.error("Encountered IllegalAccessException while trying to instantiate new class. " +
                        "This indicates a programming error.", e);
            }
            return null;
        }
    }

}
