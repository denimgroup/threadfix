package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RequestConfigurer;
import org.apache.commons.httpclient.HttpMethodBase;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.xml.bind.DatatypeConverter;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;
import static com.denimgroup.threadfix.importer.util.JsonUtils.toJSONObjectIterable;

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

    RemoteProviderHttpUtils httpUtils = getImpl(ContrastRemoteProvider.class);

    ////////////////////////////////////////////////////////////////////////
    //                     Get Applications
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        HttpResponse response = makeRequest(APPS_URL);

        try {
            if (response.isValid()) {

                List<RemoteProviderApplication> applicationList = list();

                for (JSONObject object : toJSONObjectIterable(response.getBodyAsString())) {
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

    private RemoteProviderApplication getApplicationFromJson(JSONObject object) throws JSONException {
        RemoteProviderApplication application = new RemoteProviderApplication();

        application.setNativeName(object.getString("name"));
        application.setNativeId(object.getString("app-id"));

        return application;
    }


    ////////////////////////////////////////////////////////////////////////
    //                         Get Applications
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
        assert remoteProviderType != null : "Remote Provider Type was null.";

        HttpResponse response = makeRequest(TRACES_URL + remoteProviderApplication.getNativeId());

        try {
            if (response.isValid()) {

                List<Finding> findingList = list();

                Scan scan = new Scan();

                for (JSONObject object : toJSONObjectIterable(response.getBodyAsString())) {
                    findingList.add(getFindingFromObject(object));
                }

                scan.setFindings(findingList);

                return list(scan);

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

    private Finding getFindingFromObject(JSONObject object) throws JSONException {

        Map<FindingKey, String> findingMap = map (
            FindingKey.SEVERITY_CODE, object.getString("severity"),
            FindingKey.VULN_CODE, object.getString("rule-name")
        );

        if (object.has("request") && object.getJSONObject("request").has("uri")) {
            findingMap.put(FindingKey.PATH, object.getJSONObject("request").getString("uri"));
        } else {
            findingMap.put(FindingKey.PATH, "/");
            LOG.info("URI not found.");
        }

        String title = object.getString("title");
        if (title.contains("\" Parameter")) {
            findingMap.put(FindingKey.PARAMETER, getParamFrom(title));
        }

        Finding finding = constructFinding(findingMap);

        assert finding != null : "Null finding received from constructFinding";

        finding.setNativeId(object.getString("uuid"));

        finding.setRawFinding(object.toString(2));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(object.getLong("last-time-seen"));
        finding.setScannedDate(calendar);

        finding.setAttackRequest(object.getJSONObject("request").toString(2));

        finding.setUrlReference(getUrlReference(object));

        return finding;
    }

    private String getParamFrom(String title) {

        int startIndex = title.indexOf("\"");
        int endIndex = title.indexOf("\" Parameter");

        if (startIndex > -1 && endIndex > -1) {
            return title.substring(startIndex + 1, endIndex);
        } else {
            return null;
        }
    }

    private String getUrlReference(JSONObject object) throws JSONException {

        for (JSONObject link : toJSONObjectIterable(object.getJSONArray("links"))) {
            if (link.has("rel") && "self".equals(link.get("rel"))) {
                return link.getString("href");
            }
        }

        return null;
    }


    ////////////////////////////////////////////////////////////////////////
    //                             Helpers
    ////////////////////////////////////////////////////////////////////////

    private HttpResponse makeRequest(String url) {
        return httpUtils.getUrlWithConfigurer(url, getConfigurer());
    }

    private RequestConfigurer getConfigurer() {
        final String username = remoteProviderType.getAuthenticationFieldValue(USERNAME),
                apiKey = remoteProviderType.getAuthenticationFieldValue(API_KEY),
                serviceKey = remoteProviderType.getAuthenticationFieldValue(SERVICE_KEY);

        assert username != null : "Username was null.";
        assert apiKey != null : "API Key was null.";
        assert serviceKey != null : "Service Key was null.";

        byte[] bytes = (username + ":" + serviceKey).getBytes();
        final String encoded = DatatypeConverter.printBase64Binary(bytes);

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
}
