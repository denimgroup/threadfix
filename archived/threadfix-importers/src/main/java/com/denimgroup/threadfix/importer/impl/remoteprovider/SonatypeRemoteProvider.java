////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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

package com.denimgroup.threadfix.importer.impl.remoteprovider;

import com.denimgroup.threadfix.annotations.RemoteProvider;
import com.denimgroup.threadfix.data.entities.*;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.util.RegexUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;
import static com.denimgroup.threadfix.importer.util.JsonUtils.getJSONObject;
import static com.denimgroup.threadfix.importer.util.JsonUtils.toJSONObjectIterable;

/**
 * Created by stran on 1/30/15.
 */
@RemoteProvider(name = "Sonatype")
public class SonatypeRemoteProvider extends AbstractRemoteProvider {

    public static final String
            URL = "URL",
            PASSWORD = "Password",
            USERNAME = "Username",
            APPS_REPORT_URL = "api/v2/reports/applications",
            APPS_URL = "api/v2/applications";

    private static final String APP_PATTERN = "api/v2/applications/(.*)/reports/";

    private Map<String, String>  appsMap = map();

    public SonatypeRemoteProvider() {
        super(ScannerType.SONATYPE);
    }

    RemoteProviderHttpUtils httpUtils = getImpl(SonatypeRemoteProvider.class);

    ////////////////////////////////////////////////////////////////////////
    //                     Get Applications
    ////////////////////////////////////////////////////////////////////////

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        assert remoteProviderType != null : "Remote Provider Type was null, please set before calling any methods.";

        getAppNamesMap();

        HttpResponse response = httpUtils.getUrl(getAuthenticationFieldValue(URL) + APPS_REPORT_URL,
                getAuthenticationFieldValue(USERNAME),
                getAuthenticationFieldValue(PASSWORD));

        try {
            if (response.isValid()) {

                List<RemoteProviderApplication> applicationList = list();

                for (JSONObject object : toJSONObjectIterable(response.getBodyAsString())) {
                    applicationList.add(getApplicationFromJson(object));
                }

                return applicationList;

            } else {
                String body = response.getBodyAsString();
                log.info("Contents: " + body);

                throw new RestIOException("Invalid response received from Sonatype servers, check the logs for more details.", response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }
    }

    private void getAppNamesMap() {
        HttpResponse response = httpUtils.getUrl(getAuthenticationFieldValue(URL) + APPS_URL,
                getAuthenticationFieldValue(USERNAME),
                getAuthenticationFieldValue(PASSWORD));

        try {
            if (response.isValid()) {
                JSONObject appObj = getJSONObject(response.getBodyAsString());
                if (appObj.has("applications")) {
                    for (JSONObject object : toJSONObjectIterable(appObj.getString("applications"))) {
                        appsMap.put(object.getString("id"), object.getString("name"));
                    }
                }

            } else {
                if (response.getInputStream() == null) {
                    log.info("Bad response.");
                } else {
                    String body = response.getBodyAsString();
                    log.info("Contents: " + body);
                }
                throw new RestIOException("Invalid response " + response.getStatus() + " received from Sonatype servers, check the logs for more details.", response.getStatus());
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

        HttpResponse response = httpUtils.getUrl(getUrl(getAuthenticationFieldValue(URL)) + remoteProviderApplication.getReportUrl(),
                getAuthenticationFieldValue(USERNAME),
                getAuthenticationFieldValue(PASSWORD));

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
                log.info("Contents: " + body);

                throw new RestIOException("Invalid response received from Sonatype servers, check the logs for more details.", response.getStatus());
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received: not JSON.");
        }


    }


    ////////////////////////////////////////////////////////////////////////
    //                             Helpers
    ////////////////////////////////////////////////////////////////////////

    private List<Finding> getFindingsFromObject(JSONObject object) {

        List<Finding> findings = list();
        try {

            if (!object.has("pathnames") || "null".equals(object.getString("pathnames")))
                return findings;

            JSONArray jsonArray = object.getJSONArray("pathnames");
            Map<FindingKey, String> findingMap;
            String pathName, component;

            for (int i = 0; i< jsonArray.length(); i++) {
                pathName = jsonArray.getString(i).replace("\\", "/");
                component = pathName.split("/")[pathName.split("/").length - 1];

                findingMap = map (
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
                        dependency.setComponentName(component);
                        dependency.setComponentFilePath(pathName);
                        dependency.setRefLink(issue.getString("url"));
                        findingMap.put(FindingKey.SEVERITY_CODE, issue.getString("threatCategory"));
                        Finding finding = constructFinding(findingMap);
                        assert finding != null : "Null finding received from constructFinding";
                        finding.setRawFinding(rawFinding);
                        finding.setDependency(dependency);
                        finding.setNativeId(object.getString("hash") + "-" + issue.getString("reference"));
                        finding.setIsStatic(true);
                        findings.add(finding);
                    }
                }
            }

        } catch (JSONException e) {
            throw new RestIOException(e, "Invalid response received.");
        }

        return findings;
    }

    private String getUrl(String inputUrl) {
        if (inputUrl != null && inputUrl.trim().endsWith("/"))
            return inputUrl.trim();
        else
            return inputUrl.trim() + "/";
    }

}
