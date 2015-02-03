package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.list;
import static com.denimgroup.threadfix.CollectionUtils.map;
import static com.denimgroup.threadfix.CollectionUtils.newMap;
import static com.denimgroup.threadfix.importer.util.JsonUtils.getJSONObject;
import static com.denimgroup.threadfix.importer.util.JsonUtils.toJSONObjectIterable;

/**
 * Created by mcollins on 1/5/15.
 */
@RemoteProvider(name = "Sonatype")
public class SonatypeRemoteProvider extends AbstractRemoteProvider {

    public static final String
            APPS_REPORT_URL = "http://api.cs.sonatype.com:8070/api/v2/reports/applications",
            APPS_URL = "http://api.cs.sonatype.com:8070/api/v2/applications",
            TRACES_URL = "http://api.cs.sonatype.com:8070/";

    private static final String APP_PATTERN = "api/v2/applications/(.*)/reports/";

    private Map<String, String>  appsMap = newMap();

    public SonatypeRemoteProvider() {
        super(ScannerType.SONATYPE);
    }

    RemoteProviderHttpUtils httpUtils = new RemoteProviderHttpUtilsImpl<>(SonatypeRemoteProvider.class);

    ////////////////////////////////////////////////////////////////////////
    //                     Get Applications
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        getAppNamesMap();

        HttpResponse response = httpUtils.getUrl(APPS_REPORT_URL, remoteProviderType.getUsername(), remoteProviderType.getPassword());

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

                throw new RestIOException("Invalid response received from Contrast servers, check the logs for more details.", response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }
    }

    private void getAppNamesMap() {
        HttpResponse response = httpUtils.getUrl(APPS_URL, remoteProviderType.getUsername(), remoteProviderType.getPassword());

        try {
            if (response.isValid()) {
                JSONObject appObj = getJSONObject(response.getBodyAsString());
                if (appObj.has("applications")) {
                    for (JSONObject object : toJSONObjectIterable(appObj.getString("applications"))) {
                        appsMap.put(object.getString("id"), object.getString("name"));
                    }
                }

            } else {
                String body = response.getBodyAsString();
                log.info("Contents:\n" + body);

                throw new RestIOException("Invalid response received from Contrast servers, check the logs for more details.", response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }
    }

    private RemoteProviderApplication getApplicationFromJson(JSONObject object) throws JSONException {
        RemoteProviderApplication application = new RemoteProviderApplication();
        String name = appsMap.get(object.getString("applicationId")) != null ?
                appsMap.get(object.getString("applicationId")) : RegexUtils.getRegexResult(object.getString("reportDataUrl"), APP_PATTERN);

        name = name + " (" + object.getString("stage") + ")";
        application.setNativeName(name);
        application.setNativeId(name);
        application.setReportUrl(object.getString("reportDataUrl"));

        return application;
    }


    ////////////////////////////////////////////////////////////////////////
    //                         Get Applications
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
        assert remoteProviderType != null : "Remote Provider Type was null.";

        HttpResponse response = httpUtils.getUrl(TRACES_URL + remoteProviderApplication.getReportUrl(), remoteProviderType.getUsername(), remoteProviderType.getPassword());

        try {
            if (response.isValid()) {

                JSONObject json = getJSONObject(response.getBodyAsString());

                List<Finding> findingList = list();

                Scan scan = new Scan();

                for (JSONObject object : toJSONObjectIterable(json.getString("components"))) {
                    findingList.addAll(getFindingsFromObject(object));
                }

                scan.setFindings(findingList);

                return list(scan);

            } else {
                String body = response.getBodyAsString();
                log.info("Contents:\n" + body);

                throw new RestIOException("Invalid response received from Contrast servers, check the logs for more details.", response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }


    }

    private List<Finding> getFindingsFromObject(JSONObject object) throws JSONException {

        List<Finding> findings = list();
        String pathName = object.getString("pathnames");
        Map<FindingKey, String> findingMap = map (
                FindingKey.PATH, pathName,
                FindingKey.VULN_CODE, "Configuration"
        );

        JSONObject securityData = null;
        if (object.has("securityData") && !"null".equals(object.getString("securityData")))
            securityData = getJSONObject(object.getString("securityData"));

        if (securityData == null)
            return findings;

        String rawFinding = object.toString(2);

        for (JSONObject issue : toJSONObjectIterable(securityData.getString("securityIssues"))) {

            if (issue.has("status") && "Open".equals(issue.getString("status"))) {
                Dependency dependency = new Dependency();
                dependency.setCve(issue.getString("reference"));
                dependency.setSource(issue.getString("source"));
                dependency.setComponentName(pathName);
                dependency.setComponentFilePath(pathName);
                findingMap.put(FindingKey.SEVERITY_CODE, getSeverity(issue.getInt("severity")));
                Finding finding = constructFinding(findingMap);
                assert finding != null : "Null finding received from constructFinding";
                finding.setRawFinding(rawFinding);
                finding.setDependency(dependency);
                finding.setNativeId(object.getString("hash") + "-" + issue.getString("reference"));
                finding.setIsStatic(true);
                findings.add(finding);
            }
        }

        return findings;
    }

    private String getSeverity(int severity) {
        if (severity>=7 && severity<=10)
            return "Critical";
        else if (severity >=4 && severity<7)
            return "Severe";
        else if (severity>=1 && severity <4)
            return "Moderate";
        else return "No Threat";
    }

}
