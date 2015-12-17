package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RequestConfigurer;
import com.denimgroup.threadfix.importer.util.JsonUtils;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import org.apache.commons.httpclient.HttpMethodBase;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.jsoup.Jsoup;

import javax.xml.bind.DatatypeConverter;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;
import static com.denimgroup.threadfix.importer.util.JsonUtils.getJSONObject;
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
            BASE_URL = "https://app.contrastsecurity.com",
            API_V2 = "/Contrast/api/",
            API_V3 = "/Contrast/api/ng/",
            ORGS_URL = "/profile/organizations/default",
            APPS_URL = "/applications",
            MODULE_URL="/modules/",
            TRACES_URL = "/traces/",
            EVENTS_SUMMARY_URL = "/events/summary",
            TRACE_WEB_URL = "https://app.contrastsecurity.com/Contrast/static/ng/index.html#/",
            FILE_PATTERN = "@(.+?):",
            LINE_PATTERN = ":([0-9]*)";

    public ContrastRemoteProvider() {
        super(ScannerType.CONTRAST);
    }

    RemoteProviderHttpUtils httpUtils = getImpl(ContrastRemoteProvider.class);

    ////////////////////////////////////////////////////////////////////////
    //                     Get Applications
    ////////////////////////////////////////////////////////////////////////

    @SuppressWarnings("unchecked")
    private String fetchDefaultOrgUuid() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        HttpResponse response = makeRequest(getContrastBaseUrl() + API_V3 + ORGS_URL);
        String orgUuid = null;

        try {
            if (response.isValid()) {
                JSONObject orgResponse = JsonUtils.getJSONObject(response.getBodyAsString());

                if (orgResponse != null) {
                    JSONObject organization = orgResponse.getJSONObject("organization");
                    orgUuid = organization.getString("organization_uuid");

                    if (orgUuid == null) {
                        throw new RestIOException("There are no teams in ThreadFix that match any Contrast " +
                                "organizations. Check your team names before continuing", response.getStatus());
                    }
                }
            } else {
                throwException(response);
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }

        return orgUuid;
    }

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        List<RemoteProviderApplication> applicationList = list();
        List<RemoteProviderApplication> moduleList = list();
        String orgUuid = fetchDefaultOrgUuid();

        applicationList.addAll(getApplications(orgUuid));

        for (RemoteProviderApplication application : applicationList) {
            if (application.getMasterApp()) {
                moduleList.addAll(getModules(orgUuid, application.getNativeId()));
            }
        }

        if (!moduleList.isEmpty()) {
            applicationList.addAll(moduleList);
        }

        return applicationList;
    }

    private List<RemoteProviderApplication> getApplications(String orgUuid) {
        return getApplications(makeRequest(getContrastBaseUrl() + API_V3 + orgUuid + APPS_URL));
    }

    private List<RemoteProviderApplication> getApplications(HttpResponse response) {
        List<RemoteProviderApplication> applicationList = list();

        try {
            if (response.isValid()) {

                JSONObject object = new JSONObject(response.getBodyAsString().trim());

                for (JSONObject application : toJSONObjectIterable(object.getJSONArray("applications"))) {
                    applicationList.add(getApplicationFromJson(application));
                }

            } else {
                throwException(response);
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }

        return applicationList;
    }

    private List<RemoteProviderApplication> getModules(String orgUuid, String masterAppId) {
        List<RemoteProviderApplication> modules = getApplications(makeRequest(getContrastBaseUrl() + API_V3 + orgUuid + MODULE_URL + masterAppId));

        for(RemoteProviderApplication module : modules) {
            module.setMasterAppId(masterAppId);
        }

        return modules;
    }

    private RemoteProviderApplication getApplicationFromJson(JSONObject object) throws JSONException {
        RemoteProviderApplication application = new RemoteProviderApplication();

        boolean isMaster = object.getBoolean("master");

        application.setNativeName(isMaster ? object.getString("name") + " (Master Application)" : object.getString("name"));
        application.setNativeId(object.getString("app_id"));
        application.setMasterApp(isMaster);

        return application;
    }

    ////////////////////////////////////////////////////////////////////////
    //                         Get Findings
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
        assert remoteProviderType != null : "Remote Provider Type was null.";

        String orgUuid = fetchDefaultOrgUuid();

        if (orgUuid != null) {
            HttpResponse response = makeRequest(getContrastBaseUrl() + API_V2 + orgUuid + TRACES_URL + remoteProviderApplication.getNativeId());

            try {
                if (response.isValid()) {

                    List<Finding> findingList = list();
                    Scan scan = new Scan();
                    for (JSONObject object : toJSONObjectIterable(response.getBodyAsString())) {
                        findingList.add(getFindingFromObject(object, remoteProviderApplication.getNativeId(), orgUuid));
                    }
                    scan.setFindings(findingList);
                    return list(scan);
                } else {
                    throwException(response);
                }
            } catch (JSONException e) {
                throw new RestIOException(e, "Invalid response received: not JSON.");
            }
        }
        return list();
    }

    private Finding getFindingFromObject(JSONObject object, String remoteAppId, String orgUuid) throws JSONException {

        Map<FindingKey, String> findingMap = map (
                FindingKey.SEVERITY_CODE, object.getString("severity"),
                FindingKey.VULN_CODE, object.getString("rule-name")
        );

        String traceId = object.getString("uuid");


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

        finding.setDataFlowElements(getEventsSummary(traceId, orgUuid));

        assert finding != null : "Null finding received from constructFinding";

        finding.setNativeId(traceId);

        finding.setRawFinding(object.toString(2));

        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(object.getLong("last-time-seen"));
        finding.setScannedDate(calendar);

        finding.setAttackRequest(object.getJSONObject("request").toString(2));

        finding.setUrlReference(TRACE_WEB_URL + orgUuid + "/applications/" + remoteAppId + "/traces/workflow/00001/" + traceId + "/details");

        return finding;
    }

    private List<DataFlowElement> getEventsSummary(String traceId, String orgUuid) {

        LOG.warn("About to get trace story/static information for trace Id " + traceId);

        List<DataFlowElement> dataFlowElementList = list();

        if (orgUuid != null) {

            HttpResponse response = makeRequest(getContrastBaseUrl() + API_V3 + orgUuid + TRACES_URL + traceId + EVENTS_SUMMARY_URL);

            if (response.isValid()) {
                try {

                    JSONObject traceObj = getJSONObject(response.getBodyAsString());
                    int seqId = 1;
                    String startLocation, lineNoText;
                    for (JSONObject event : toJSONObjectIterable(traceObj.getString("events"))) {
                        DataFlowElement element = new DataFlowElement();
                        element.setSequence(seqId++);
                        startLocation = event.getString("probableStartLocation");
                        element.setSourceFileName(RegexUtils.getRegexResult(startLocation, FILE_PATTERN).trim());
                        lineNoText = RegexUtils.getRegexResult(startLocation, LINE_PATTERN);
                        if (lineNoText != null)
                            element.setLineNumber(Integer.valueOf(lineNoText));
                        element.setLineText(Jsoup.parse(event.getString("rawCodeRecreation")).text());
                        dataFlowElementList.add(element);
                    }
                } catch (JSONException e) {
                    LOG.warn("Can't parse trace " + traceId + ". Trace story response isn't valid.");
                    return dataFlowElementList;
                }

            } else {
                LOG.warn("Trace story response isn't valid.");
            }
        }

        return dataFlowElementList;
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
        if (body == null || !body.contains("{")) {
            log.error("Got invalid body from Contrast: " + body);
            return null;
        }

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

    private void throwException(HttpResponse response) throws RestIOException, JSONException {
        String body = response.getBodyAsString();
        log.info("Contents:\n" + body);
        String errorMessageOrNull = getErrorOrNull(body);

        if (errorMessageOrNull == null) {
            errorMessageOrNull =
                    "Invalid response received from Contrast servers, check the logs for more details.";
        }

        throw new RestIOException(errorMessageOrNull, response.getStatus());
    }

    private String getContrastBaseUrl() {
        for (RemoteProviderAuthenticationField authField : remoteProviderType.getAuthenticationFields()) {
            if (authField.getName().equals("URL")){
                return authField.getValue();
            }
        }

        return BASE_URL;
    }
}
