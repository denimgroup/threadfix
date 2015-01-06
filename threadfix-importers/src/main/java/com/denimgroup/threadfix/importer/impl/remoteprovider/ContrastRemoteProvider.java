package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.*;
import org.apache.commons.httpclient.HttpMethodBase;
import org.apache.xerces.impl.dv.util.Base64;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;

import static com.denimgroup.threadfix.CollectionUtils.list;

/**
 * Created by mcollins on 1/5/15.
 */
@RemoteProvider(name = "Contrast")
public class ContrastRemoteProvider extends AbstractRemoteProvider {

    public static final String
            API_KEY = "API Key",
            SERVICE_KEY = "Service Key",
            USERNAME = "Username",
            APPS_URL = "https://app.contrastsecurity.com/Contrast/api/applications",
            TRACES_URL = "https://app.contrastsecurity.com/Contrast/api/traces/";

    public ContrastRemoteProvider() {
        super(ScannerType.CONTRAST);
    }

    RemoteProviderHttpUtils httpUtils = new RemoteProviderHttpUtilsImpl<>(ContrastRemoteProvider.class);

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
        return null;
    }

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        RequestConfigurer configurer = getConfigurer();

        HttpResponse response = httpUtils.getUrlWithConfigurer(APPS_URL, configurer);

        try {
            if (response.isValid()) {

                List<RemoteProviderApplication> applicationList = list();

                IterableJSONArray array = new IterableJSONArray(response.getBodyAsString());

                for (JSONObject object : array) {
                    applicationList.add(getApplicationFromJson(object));
                }

                return applicationList;

            } else {
                String body = response.getBodyAsString();
                log.info("Contents:\n" + body);
                String errorMessageOrNull = getErrorOrNull(body);

                if (errorMessageOrNull == null) {
                    errorMessageOrNull =
                            "Invalid response received from Contrast servers, check the logs for more details.";
                }

                throw new RestIOException(errorMessageOrNull, response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }
    }

    private String getErrorOrNull(String body) throws JSONException {

        JSONObject object = new JSONObject(body);

        if (object.has("success") && "false".equals(object.getString("success"))) {
            JSONArray errors = object.getJSONArray("messages");

            if (errors.length() > 0) {
                StringBuilder builder = new StringBuilder("Contrast error: ");

                for (int i = 0; i < errors.length(); i++) {
                    builder.append(errors.getString(i)).append(", ");
                }

                builder.setLength(builder.length() - 2);

                return builder.toString();
            }
        }

        return null;
    }

    private RemoteProviderApplication getApplicationFromJson(JSONObject object) throws JSONException {
        RemoteProviderApplication application = new RemoteProviderApplication();

        application.setNativeName(object.getString("name"));
        application.setNativeId(object.getString("app-id"));

        return application;
    }

    private RequestConfigurer getConfigurer() {
        final String username = remoteProviderType.getAuthenticationFieldValue(USERNAME),
                apiKey = remoteProviderType.getAuthenticationFieldValue(API_KEY),
                serviceKey = remoteProviderType.getAuthenticationFieldValue(SERVICE_KEY);

        assert username != null : "Username was null.";
        assert apiKey != null : "API Key was null.";
        assert serviceKey != null : "Service Key was null.";

        byte[] bytes = (username + ":" + serviceKey).getBytes();
        final String encoded = Base64.encode(bytes);

        return new RequestConfigurer() {
            @Override
            public void configure(HttpMethodBase method) {
                method.setRequestHeader("Authorization", encoded);
                method.setRequestHeader("API-Key", apiKey);
                method.setRequestHeader("Accept", "application/json");
                method.removeRequestHeader("Content-type");
            }
        };
    }
}
