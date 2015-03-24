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
import com.denimgroup.threadfix.data.Option;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.HttpResponse;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtils;
import com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RequestConfigurer;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.apache.commons.httpclient.HttpMethodBase;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.denimgroup.threadfix.CollectionUtils.*;
import static com.denimgroup.threadfix.importer.impl.remoteprovider.utils.RemoteProviderHttpUtilsImpl.getImpl;

/**
 * Created by mac on 11/18/14.
 */
@RemoteProvider(name = "Trustwave Hailstorm")
public class TrustwaveHailstormRemoteProvider extends AbstractRemoteProvider {

    String url = "https://ctsarc.cenzic.com/ResultEngineApi/applications",
            secret = null,
            accessToken = null;

    private       RequestConfigurer       addCtsAuth = new RequestConfigurer() {
        @Override
        public void configure(HttpMethodBase method) {
            method.setRequestHeader("CTSAuth", constructHeaderValue());
        }
    };
    private final RemoteProviderHttpUtils utils      = getImpl(TrustwaveHailstormRemoteProvider.class);

    private static final Set<String> CLOSED_CODES = set("Fixed");

    // CTSAuth: client_secret=<<answer>>,access_token=<<answer>>
    private String constructHeaderValue() {
        return "client_secret=" + getSecret() + ",access_token=" + getAccessToken();
    }

    private String getAccessToken() {
        if (accessToken == null) {
            accessToken = getAuthenticationFieldValue("Access Token");
        }

        return accessToken;
    }

    private String getSecret() {
        if (secret == null) {
            secret = getAuthenticationFieldValue("Client Secret");
        }

        return secret;
    }

    // TODO move to code that calls the server
    private String getApplicationJson() {
        HttpResponse response = utils.getUrlWithConfigurer(getUrl(), addCtsAuth);

        return response.getBodyAsString();
    }

    private String getScansJSON(String applicationId) {
        HttpResponse response = utils.getUrlWithConfigurer(url + "/" + applicationId + "/uFindings", addCtsAuth);

        return response.getBodyAsString();
    }

    private static final SanitizedLogger LOG = new SanitizedLogger(TrustwaveHailstormRemoteProvider.class);

    Map<Integer, String> statusMap = map(
            0, "Success",
            1, "Fail",
            3, "AuthenticationFailed",
            4, "UnknownKey",
            9, "InvalidAccessToken",
            201, "UserNotFound",
            301, "SubscriptionNotFound",
            401, "ScanNotFound",
            500, "ServerError");

    public TrustwaveHailstormRemoteProvider() {
        super(ScannerType.CENZIC_HAILSTORM);
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                   Scans parsing
    //////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public List<Scan> getScans(RemoteProviderApplication remoteProviderApplication) {
        String scansJson = getScansJSON(remoteProviderApplication.getNativeId());

        checkReturnCode(scansJson);

        HailstormRemoteXmlParser parser = new HailstormRemoteXmlParser();

        parse(getXmlStream(scansJson), parser);

        Scan scan = new Scan();

        scan.setFindings(parser.findings);
        scan.setApplicationChannel(remoteProviderApplication.getApplicationChannel());

        // fixes one error?
        Calendar instance = Calendar.getInstance();
        if (parser.latestDate != null) {
            instance.setTime(parser.latestDate);
        }
        scan.setImportTime(instance);

        return list(scan);
    }

    private InputStream getXmlStream(String scansJson) {
        try {
            JSONObject object = new JSONObject(scansJson);

            String xml = object.getString("UniqueVulnerabilities");

            if (xml == null || xml.trim().equals("")) {
                throw new RestIOException("Got no Finding XML back from server.", -1);
            }

            return new ByteArrayInputStream(xml.getBytes());
        } catch (JSONException e) {
            throw new RestIOException("Unable to connect to Trustwave servers. Check your URL and credentials.", -1);
        }
    }

    public String getUrl() {
        return "https://ctsarc.cenzic.com/ResultEngineApi/applications";
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                Findings XML Parser
    //////////////////////////////////////////////////////////////////////////////////////////

    class HailstormRemoteXmlParser extends HandlerWithBuilder {

        private FindingKey key = null;
        Map<String, FindingKey> keyMap    = map(
                "Url", FindingKey.PATH,
                "TypeName", FindingKey.VULN_CODE,
                "TypeDescription", FindingKey.DETAIL
        );
        Map<FindingKey, String> map       = map();
        boolean                 getStatus = false, findingIsOpen = false, getDate = false, inFinding = false;

        List<Finding> findings = list();

        StringBuffer rawFindingXML = new StringBuffer();
        Date latestDate = null;

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if (keyMap.containsKey(qName)) {
                key = keyMap.get(qName);
            } else if ("Status".equals(qName)) {
                getStatus = true;
            } else if ("UniqueFinding".equals(qName)) {
                inFinding = true;
                map.put(FindingKey.NATIVE_ID, attributes.getValue("Id"));
            } else if ("LastFoundDate".equals(qName)) {
                getDate = true;
            }

            if (inFinding) {
                rawFindingXML.append(makeTag(localName, qName, attributes));
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {

            if (getStatus) {
                findingIsOpen = !CLOSED_CODES.contains(getBuilderText());
                getStatus = false;
            }

            if (key != null) {
                map.put(key, getBuilderText());
                key = null;
            }

            if (getDate) {
                Date date = parseDate(getBuilderText());

                if (date != null && (latestDate == null || latestDate.before(date))) {
                    latestDate = date;
                }

                getDate = false;
            }

            if (inFinding) {
                rawFindingXML.append(makeEndTag(localName, qName));
            }

            if ("UniqueFinding".equals(qName)) {

                String detail = map.get(FindingKey.DETAIL);
                if (detail != null && detail.startsWith("No vulnerabilities were found for:")) {
                    findingIsOpen = false;
                }

                if (findingIsOpen) {
                    map.put(FindingKey.RAWFINDING, rawFindingXML.toString());

                    Finding finding = constructFinding(map);
                    if (finding != null) {
                        finding.setNativeId(map.get(FindingKey.NATIVE_ID));
                        findings.add(finding);
                    }
                }
                map.clear();
                map.put(FindingKey.SEVERITY_CODE, "High");
                inFinding = false;
                rawFindingXML.setLength(0);
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            if (key != null || getStatus || getDate) {
                addTextToBuilder(ch, start, length);
            }

            if (inFinding) {
                rawFindingXML.append(ch, start, length);
            }
        }
    }

    private static final DateFormat myFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSSSSS'Z'");

    Date parseDate(String builderText) {
        try {
            return myFormat.parse(builderText);
        } catch (ParseException e) {
            LOG.info("Couldn't parse date " + builderText);
            return null;
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                Applications parsing
    //////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public List<RemoteProviderApplication> fetchApplications() {
        String serverReturn = getApplicationJson();

        checkReturnCode(serverReturn);

        Option<List<String>> applicationUUIDs = getUUIDs(serverReturn);

        if (applicationUUIDs.isValid()) {
            return createRemoteProviderApplications(applicationUUIDs.getValue());
        } else {
            throw new RestIOException("No applications found.", -1);
        }
    }

    private List<RemoteProviderApplication> createRemoteProviderApplications(List<String> appIds) {
        List<RemoteProviderApplication> applications = list();

        for (String applicationUUID : appIds) {
            RemoteProviderApplication application = new RemoteProviderApplication();

            application.setNativeId(applicationUUID);
            application.setNativeName(applicationUUID);
            application.setRemoteProviderType(remoteProviderType);

            applications.add(application);
        }

        return applications;
    }

    private Option<List<String>> getUUIDs(String serverReturn) {
        try {
            JSONObject object = new JSONObject(serverReturn);

            JSONArray applicationIds = object.getJSONArray("ApplicationIds");

            List<String> strings = list();

            for (int i = 0; i < applicationIds.length(); i++) {
                strings.add(applicationIds.getString(i));
            }

            return Option.success(strings);
        } catch (JSONException e) {
            LOG.error("Unable to parse JSON from string: " + serverReturn);
            return Option.failure();
        }
    }

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                Common JSON parsing
    //////////////////////////////////////////////////////////////////////////////////////////

    private void checkReturnCode(String jsonString) throws RestIOException {
        try {
            JSONObject object = new JSONObject(jsonString);

            int returnCode = object.getInt("ReturnCode");

            if (returnCode != 0) {
                throw new RestIOException(
                        "Server returned code " + returnCode +
                                " (" + statusMap.get(returnCode) + ")", returnCode);
            }

        } catch (JSONException e) {
            throw new RestIOException(e,
                    "Error parsing Trustwave response. " +
                    "This is usually due to an incorrect access token value.",
                    -1);
        }
    }
}
