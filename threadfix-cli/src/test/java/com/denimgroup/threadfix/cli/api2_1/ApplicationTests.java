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

package com.denimgroup.threadfix.cli.api2_1;

import com.denimgroup.threadfix.cli.util.JsonTestUtils;
import com.denimgroup.threadfix.cli.util.TestUtils;
import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.junit.Test;

/**
 * Created by mcollins on 6/5/14.
 */
public class ApplicationTests {

    String[] applicationFields = { "id", "name", "uniqueId", "totalVulnCount", "criticalVulnCount", "highVulnCount",
            "lowVulnCount", "infoVulnCount", "team", "scans" };

    @Test
    public void createApplicationTest() {
        JsonTestUtils.assertHasFields(TestUtils.createApplication(), applicationFields);
    }

    @Test
    public void teamFieldTest() {
        JsonTestUtils.assertHasObjectWithFields(TestUtils.createApplication(), "team", "name", "id");
    }

    @Test
    public void lookupByIdTest() {
        String id = JsonTestUtils.getId(TestUtils.createApplication());

        JsonTestUtils.assertHasFields(TestUtils.getConfiguredClient().searchForApplicationById(id), applicationFields);
    }

    @Test
    public void lookupByNameTest() {
        RestResponse<Application> applicationResponse = TestUtils.createApplication();

        String teamName = applicationResponse.object.getOrganization().getName();
        String appName = applicationResponse.object.getName();

        JsonTestUtils.assertHasFields(
                TestUtils.getConfiguredClient().searchForApplicationByName(teamName, appName), applicationFields);
    }


}
