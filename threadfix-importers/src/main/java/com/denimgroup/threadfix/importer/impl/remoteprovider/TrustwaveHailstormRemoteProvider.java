////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
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

import com.denimgroup.threadfix.data.Option;
import com.denimgroup.threadfix.data.entities.Finding;
import com.denimgroup.threadfix.data.entities.RemoteProviderApplication;
import com.denimgroup.threadfix.data.entities.Scan;
import com.denimgroup.threadfix.data.entities.ScannerType;
import com.denimgroup.threadfix.exception.RestIOException;
import com.denimgroup.threadfix.importer.util.HandlerWithBuilder;
import com.denimgroup.threadfix.logging.SanitizedLogger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import static com.denimgroup.threadfix.CollectionUtils.*;

/**
 * Created by mac on 11/18/14.
 */
public class TrustwaveHailstormRemoteProvider extends RemoteProvider {

    // TODO move to code that calls the server
    private String getApplicationJson() {
        return "{\n" +
                "\"ReturnCode\": 0, \"ApplicationIds\": [\n" +
                "\"0a6c98bf-3f83-41a5-9deb-bd3a4e41a645\", \"0f4938fb-8e4e-45e3-b7c0-610939080a7b\", \"1e3c16f4-c14a-4fe0-abbe-53430be8370d\",\n" +
                "] }";
    }

    private String getScansJSON() {
        return "{\n" +
                "ReturnCode: 0 UniqueVulnerabilities: \" <Applications>\n" +
                "<Application ApplicationId=\"2abbb729-1e14-467b-8a44-a7046f727907\"> <UniqueFindings>\n" +
                "<UniqueFinding Id=\"7df1868f4e0db072814880ea2bf497a9a93573c\"> <Url>http://crackme.cenzic.com/Kelev/register/register.php</Url> <Type>35</Type>\n" +
                "<TypeName>Form Caching</TypeName>\n" +
                "<TypeDescription>No caching directives found.</TypeDescription> <FirstFoundDate>2013-05-21T18:58:23.0000000Z</FirstFoundDate> <LastFoundDate>2013-05-21T18:58:23.0000000Z</LastFoundDate> <Status>Fixed</Status>\n" +
                "</UniqueFinding>\n" +
                "<UniqueFinding Id=\"7df1868f4e0db072814880ea2bf497a9a93573c \">\n" +
                "<Url>http://crackme.cenzic.com/Kelev/register/register.php</Url> <Type>23</Type>\n" +
                "<TypeName>Non-SSL Form</TypeName>\n" +
                "<TypeDescription>Number of forms found without SSL =1</TypeDescription> <FirstFoundDate>2013-05-21T18:58:23.0000000Z</FirstFoundDate> <LastFoundDate>2013-05-21T18:58:23.0000000Z</LastFoundDate> <Status>Open</Status>\n" +
                "</UniqueFinding> </UniqueFindings>\n" +
                "</Application> <Applications>\"\n" +
                "}";
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
        String scansJson = getScansJSON();

        checkReturnCode(scansJson);

        HailstormRemoteXmlParser parser = new HailstormRemoteXmlParser();

        parse(getXmlStream(scansJson), parser);

        Scan scan = new Scan();

        scan.setFindings(parser.findings);

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

    //////////////////////////////////////////////////////////////////////////////////////////
    //                                Findings XML Parser
    //////////////////////////////////////////////////////////////////////////////////////////

    class HailstormRemoteXmlParser extends HandlerWithBuilder {

        private FindingKey key = null;
        Map<String, FindingKey> keyMap    = map(
                "Url", FindingKey.PATH,
                "Type", FindingKey.VULN_CODE
        );
        Map<FindingKey, String> map       = newMap();
        boolean                 getStatus = false, findingIsOpen = false;

        List<Finding> findings = list();

        @Override
        public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
            if (keyMap.containsKey(qName)) {
                key = keyMap.get(qName);
            } else if ("Status".equals(qName)) {
                getStatus = true;
            }
        }

        @Override
        public void endElement(String uri, String localName, String qName) throws SAXException {

            if (getStatus) {
                findingIsOpen = "Open".equals(getBuilderText());
                getStatus = false;
            }

            if (key != null) {
                map.put(key, getBuilderText());
                key = null;
            }

            if ("UniqueFinding".equals(qName)) {
                if (findingIsOpen) {
                    findings.add(constructFinding(map));
                }
                map.clear();
            }
        }

        @Override
        public void characters(char[] ch, int start, int length) throws SAXException {
            if (key != null || getStatus) {
                addTextToBuilder(ch, start, length);
            }
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
                        "Got error from server with code " + returnCode +
                                " and string value " + statusMap.get(returnCode), returnCode);
            }
        } catch (JSONException e) {
            throw new RestIOException("Unable to connect to Trustwave servers. Check your URL and credentials.", -1);
        }
    }
}
