package burp.extention;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.remote.PluginClient;
import com.denimgroup.threadfix.remote.response.RestResponse;

import java.io.File;

public class RestUtils {

    private RestUtils(){}

    public static RestResponse<Object> uploadScan(File file) {

        if (BurpPropertiesManager.getUrlStatic() == null || BurpPropertiesManager.getKeyStatic() == null) {
            return RestResponse.failure("Url and API key were not saved correctly.");
        }

        return getPluginClient().uploadScan(BurpPropertiesManager.getAppId(), file);
    }

    public static Application.Info[] getApplications() {
        return getPluginClient().getThreadFixApplications();
    }

    public static Endpoint.Info[] getEndpoints() {
        return getPluginClient().getEndpoints(BurpPropertiesManager.getAppId());
    }

    private static PluginClient getPluginClient() {
        return new PluginClient(new BurpPropertiesManager());
    }
}
