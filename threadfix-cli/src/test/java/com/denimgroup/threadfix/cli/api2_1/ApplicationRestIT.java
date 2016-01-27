////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2016 Denim Group, Ltd.
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

package com.denimgroup.threadfix.cli.api2_1;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.cli.util.JsonTestUtils;
import com.denimgroup.threadfix.cli.util.TestUtils;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Created by mcollins on 6/5/14.
 */
@Category(CommunityTests.class)
public class ApplicationRestIT {

    String[] applicationFields = { "id", "name", "uniqueId", "totalVulnCount", "criticalVulnCount", "highVulnCount",
            "mediumVulnCount", "lowVulnCount", "infoVulnCount", "organization", "scans", "waf" };

    String[] applicationScanListFields = {
            "numberTotalVulnerabilities",
            "numberRepeatResults",
            "numberRepeatFindings",
            "numberOldVulnerabilities",
            "numberNewVulnerabilities",
            "numberClosedVulnerabilities",
            "numberResurfacedVulnerabilities",
            "numberInfoVulnerabilities",
            "numberLowVulnerabilities",
            "numberMediumVulnerabilities",
            "numberHighVulnerabilities",
            "numberCriticalVulnerabilities",
            "importTime",
            "scannerName",
            "id"
    };

    @Test
    public void createApplicationTest() {
        testAllApplicationFields(TestUtils.createApplicationWithScan());
    }

    @Test
    public void lookupByIdTest() {
        String id = JsonTestUtils.getId(TestUtils.createApplicationWithScan());

        testAllApplicationFields(TestUtils.getConfiguredClient().searchForApplicationById(id));
    }

    @Test
    public void lookupByNameTest() {
        RestResponse<Application> applicationResponse = TestUtils.createApplicationWithScan();

        String teamName = applicationResponse.object.getOrganization().getName();
        String appName = applicationResponse.object.getName();

        assert teamName != null : "Teamname was null in " + applicationResponse;
        assert appName != null : "Application name was null in " + applicationResponse;

        applicationResponse = TestUtils.getConfiguredClient().searchForApplicationByName(appName, teamName);
        testAllApplicationFields(applicationResponse);
    }

    @Test
    public void setParametersTest() {
        RestResponse<Application> applicationResponse = TestUtils.createApplicationWithScan();

        applicationResponse =
            TestUtils.getConfiguredClient().setParameters(JsonTestUtils.getId(applicationResponse),
                    "SPRING_MVC", "http://test.com");

        testAllApplicationFields(applicationResponse);
    }

    @Test
    public void setWafTest() {
        RestResponse<Application> applicationResponse = TestUtils.createApplicationWithScan();

        RestResponse<Waf> wafRestResponse = TestUtils.getConfiguredClient().createWaf("test", "Snort");

        applicationResponse = TestUtils.getConfiguredClient().addWaf(
                JsonTestUtils.getId(applicationResponse),
                JsonTestUtils.getId(wafRestResponse)
        );

        testAllApplicationFields(applicationResponse);
    }

    @Test
    public void addAppUrlTest() {
        RestResponse<Application> applicationResponse = TestUtils.createApplicationWithScan();

        applicationResponse = TestUtils.getConfiguredClient().addAppUrl(
                JsonTestUtils.getId(applicationResponse),
                "http://test2"
        );

        testAllApplicationFields(applicationResponse);
    }

    private void testAllApplicationFields(RestResponse<Application> applicationRestResponse) {
        JsonTestUtils.assertHasFields(applicationRestResponse, applicationFields);
        JsonTestUtils.assertHasObjectWithFields(applicationRestResponse, "organization", "name", "id");
        JsonTestUtils.assertHasArrayOfObjectsWithFields(applicationRestResponse, "scans", applicationScanListFields);
    }


}
