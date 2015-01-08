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

package com.denimgroup.threadfix.cli.api2_1;

import com.denimgroup.threadfix.CommunityTests;
import com.denimgroup.threadfix.cli.util.JsonTestUtils;
import com.denimgroup.threadfix.cli.util.TestUtils;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Created by mcollins on 6/4/14.
 */
@Category(CommunityTests.class)
public class TeamRestIT {

    String[] teamFields = { "id", "name", "applications", "totalVulnCount",
            "criticalVulnCount", "highVulnCount", "mediumVulnCount", "lowVulnCount", "infoVulnCount" };

    @Test
    public void testCreateTeamFormat() {
        RestResponse<Organization> response = TestUtils.getConfiguredClient().createTeam(TestUtils.getRandomName());

        assert response.getOriginalJson() != null : "Json was null.";
        assert response.success : "Failed to create a team. Check the configured credentials. Json was " + response.getOriginalJson();

        JsonTestUtils.assertHasFields(response, teamFields);
    }

    @Test
    public void testFindTeamIdFormat() {
        ThreadFixRestClient client = TestUtils.getConfiguredClient();

        RestResponse<Organization> response = client.createTeam(TestUtils.getRandomName());

        response = client.searchForTeamById(JsonTestUtils.getId(response));

        JsonTestUtils.assertHasFields(response, teamFields);
    }

    @Test
    public void testFindTeamNameFormat() {
        ThreadFixRestClient client = TestUtils.getConfiguredClient();

        RestResponse<Organization> response = client.createTeam(TestUtils.getRandomName());

        response = client.searchForTeamByName(String.valueOf(response.object.getName()));

        JsonTestUtils.assertHasFields(response, teamFields);
    }

    @Test
    public void testAllTeams() {
        ThreadFixRestClient client = TestUtils.getConfiguredClient();

        RestResponse<Organization> response = client.createTeam(TestUtils.getRandomName());

        assert response.getOriginalJson() != null : "Json was null.";
        assert response.success : "Failed to create a team. Check the configured credentials. Json was " + response.getOriginalJson();

        RestResponse<Organization[]> teamsResponse = client.getAllTeams();

        JsonTestUtils.assertIsArrayWithFields(teamsResponse, teamFields);
    }

    // assert that applications in activeApplications get just name and id fields
    @Test
    public void testTeamApplicationList() {
        ThreadFixRestClient client = TestUtils.getConfiguredClient();

        RestResponse<Organization> response = client.createTeam(TestUtils.getRandomName());

        client.createApplication(JsonTestUtils.getId(response),
                TestUtils.getRandomName(),
                "http://test");

        response = client.searchForTeamById(JsonTestUtils.getId(response));

        JsonTestUtils.assertHasArrayOfObjectsWithFields(response, "applications", "name", "id");
    }




}
