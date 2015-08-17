package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.CommandLineUtils;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.json.JSONObject;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineIT extends BaseDataTest {

    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");
    private static CommandLineUtils cliUtils = new CommandLineUtils();
    private static DatabaseUtils dbUtils = new DatabaseUtils();

    static {
        cliUtils.setApiKey(API_KEY);
        cliUtils.setUrl(REST_URL);
    }

    @Test
    public void testCreateTeam() {
        String teamName = getName();

        JSONObject response = cliUtils.createTeam(teamName);
        assertTrue("Response wasn't successful.", cliUtils.isCommandResponseSuccessful(response));

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();
        assertTrue("Team was not present.", teamIndexPage.isTeamPresent(teamName));
    }

    @Test
    public void testCreateApplication() {
        String teamName = getName();
        String appName = getName();
        String APP_URL = "http://this.com";

        JSONObject team = cliUtils.createTeam(teamName);
        int teamId = cliUtils.getObjectId(team);
        JSONObject response = cliUtils.createApplication(teamId, appName, "http://this.com");

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName);
        assertTrue("App is not present.", teamIndexPage.isAppDisplayed(teamName, appName));

        ApplicationDetailPage applicationDetailPage = teamIndexPage.clickApplicationName(teamName, appName)
                .clickEditDeleteBtn();
        assertTrue("URL was not set correctly.", APP_URL.equals(applicationDetailPage.getUrlText()));
    }
}
