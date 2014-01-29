package com.denimgroup.threadfix.cli;

import com.denimgroup.threadfix.data.entities.Application;
import com.denimgroup.threadfix.data.entities.Organization;
import com.denimgroup.threadfix.data.entities.Waf;
import com.denimgroup.threadfix.data.entities.WafType;
import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.remote.ThreadFixRestClient;
import com.denimgroup.threadfix.remote.ThreadFixRestClientImpl;
import com.denimgroup.threadfix.remote.response.RestResponse;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ThreadFixRestClientTests {

    String dummyUrl = "http://test.com";

    /**
     * !!!!!!! ATTENTION: Before running these testcases, please making sure:
     *      + ThreadFix server is running with API_KEY
     *      + There TEAM_ID with TEAM_NAME in ThreadFix server
     *      + There APPLICATION_ID with APPLICATION_NAME in ThreadFix server
     *      + There's WAF_ID with WAF_NAME in TF, and rules are generated
     *      + There's TASK_ID
     *      + There's config file ACUNETIX_CONFIG_FILE
     */

    private ThreadFixRestClient getClient() {
        return new ThreadFixRestClientImpl(new TestUtils());
    }


    private RestResponse<Organization> createTeam(String name) {
        return getClient().createTeam(name);
    }

    private Integer getTeamId(String name) {
        RestResponse<Organization> teamResponse = createTeam(name);

        assertTrue("Rest Response was a failure. message was: " + teamResponse.message,
                teamResponse.success);
        assertNotNull("The returned team object was null.", teamResponse.object);

        return teamResponse.object.getId();
    }

    private RestResponse<Application> createApplication(String teamId, String name, String url) {
        return getClient().createApplication(teamId, name, url);
    }

    private Integer getApplicationId(String teamName, String name, String url) {
        RestResponse<Application> teamResponse = createApplication(
                getTeamId(teamName).toString(), name, url);

        assertTrue("Rest Response was a failure. message was: " + teamResponse.message,
                teamResponse.success);
        assertNotNull("The returned application object was null.", teamResponse.object);

        return teamResponse.object.getId();
    }

    private RestResponse<Waf> createWaf(String name, String type) {
        return getClient().createWaf(name, type);
    }

    private Integer getWafId(String name, String type) {
        RestResponse<Waf> wafsResponse = createWaf(name, type);

        assertTrue("Rest Response was a failure. message was: " + wafsResponse.message,
                wafsResponse.success);
        assertNotNull("The returned application object was null.", wafsResponse.object);

        return wafsResponse.object.getId();
    }

    @Test
    public void testCreateTeam() {
        String name = TestUtils.getName();

        RestResponse<Organization> organizationResponse = createTeam(name);

        assertTrue(organizationResponse.object.getName().equals(name));
    }

    @Test
    public void testSearchForTeamById() {
        String name = TestUtils.getName();

        String teamId = getTeamId(name).toString();

        RestResponse<Organization> organizationResponse = getClient().searchForTeamById(teamId);

        assertEquals("Names didn't match.", organizationResponse.object.getName(), name);
    }

    @Test
    public void testSearchForTeamByName() {
        String name = TestUtils.getName();

        Integer teamId = getTeamId(name);

        RestResponse<Organization> organizationResponse = getClient().searchForTeamByName(name);

        assertEquals("Ids didn't match", organizationResponse.object.getId(), teamId);
    }

    @Test
    public void testGetAllTeams() {

        String name = TestUtils.getName();

        Integer teamId = getTeamId(name);

        RestResponse<Organization[]> teamsResponse = getClient().getAllTeams();

        assertTrue("Rest Response was a failure. message was: " + teamsResponse.message,
                teamsResponse.success);

        boolean foundIt = false;

        for (Organization organization : teamsResponse.object) {
            if (organization.getId().equals(teamId)) {
                assertTrue(organization.getName().equals(name));
                foundIt = true;
            }
        }

        assertTrue("Didn't find the team in the teams list.", foundIt);
    }

    @Test
    public void testCreateApplication() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName();

        RestResponse<Application> response =
                createApplication(getTeamId(teamName).toString(), appName, dummyUrl);

        assertNotNull("Response was null.", response.object);
        assertTrue("Application name was incorrect: " + response.object.getName() +
                " instead of " + appName, response.object.getName().equals(appName));
        assertTrue("Application URL was not correct.", response.object.getUrl().equals(dummyUrl));
    }


    @Test
    public void testSearchForApplicationById() {
        String name = TestUtils.getName(), teamName = TestUtils.getName();

        String idString = getApplicationId(teamName, name, dummyUrl).toString();

        RestResponse<Application> appResponse = getClient().searchForApplicationById(idString);

        assertTrue("Rest Response was a failure. message was: " + appResponse.message,
                appResponse.success);

        assertNotNull(appResponse.object);
        assertEquals("Names didn't match.", appResponse.object.getName(), name);
    }

    @Test
    public void testSearchForApplicationByName() {
        String name = TestUtils.getName(), teamName = TestUtils.getName();

        String idString = getApplicationId(teamName, name, dummyUrl).toString();

        RestResponse<Application> appResponse = getClient().searchForApplicationByName(name, teamName);

        assertTrue("Rest Response was a failure. message was: " + appResponse.message,
                appResponse.success);

        assertNotNull(appResponse.object);
        assertEquals("Names didn't match.", appResponse.object.getId().toString(), idString);
    }

    @Test
    public void testSetParameters() {
        String appName = TestUtils.getName(), teamName = TestUtils.getName(),
                url = "http://www.test.com";

        FrameworkType type = FrameworkType.SPRING_MVC;

        RestResponse<Application> appRet = getClient().setParameters(
                getApplicationId(teamName, appName, url).toString(),
                type.toString(),
                "http://repositoryUrl.com");

        Application app = appRet.object;

        assertTrue("Test was a failure.", appRet.success);
        assertNotNull("Returned Application was null.", app);
        assertTrue("Application frameworkType was " + app.getFrameworkType() + " instead of " +
                type.getDisplayName(), app.getFrameworkTypeEnum() == type);
    }

    @Test
    public void testCreateWaf() {
        String name = TestUtils.getName();

        RestResponse<Waf> wafRestResponse = createWaf(name, WafType.BIG_IP_ASM);

        assertTrue("Names weren't equal.", wafRestResponse.object.getName().equals(name));
    }

    @Test
    public void testSearchForWafByName() {
        String name = TestUtils.getName();

        Integer wafId = getWafId(name, WafType.DENY_ALL_RWEB);

        RestResponse<Waf> wafRestResponse = getClient().searchForWafByName(name);

        assertEquals("Names weren't equal.", wafRestResponse.object.getId(), wafId);
    }

    @Test
    public void testSearchForWafById() {
        String name = TestUtils.getName();

        Integer wafId = getWafId(name, WafType.DENY_ALL_RWEB);

        RestResponse<Waf> wafRestResponse = getClient().searchForWafById(wafId.toString());

        assertTrue(wafRestResponse.object.getName().equals(name));
    }

    @Test
    public void testAddWaf() {

        String wafName = TestUtils.getName(), appName = TestUtils.getName(), teamName = TestUtils.getName();

        String appId = getApplicationId(teamName, appName, dummyUrl).toString();
        String wafId = getWafId(wafName, WafType.MOD_SECURITY).toString();

        RestResponse<Application> response = getClient().addWaf(appId, wafId);

        assertTrue("Response was a failure. Message: " + response.message, response.success);
        assertEquals("Application ID didn't match.", response.object.getId().toString(), appId);
        assertEquals("WAF ID didn't match.", response.object.getWaf().getId().toString(), wafId);
    }

    // TODO write tests for the scan agent methods.

}
