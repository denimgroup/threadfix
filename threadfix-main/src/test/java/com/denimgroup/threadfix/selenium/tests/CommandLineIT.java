package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TagIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;
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

    @Test
    public void testCreateWaf() {
        String wafName = getName();
        String wafType = "mod_security";

        JSONObject response = cliUtils.createWaf(wafName, wafType);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));

        WafIndexPage wafIndexPage = loginPage.defaultLogin()
                .clickWafsHeaderLink();
        assertTrue("WAF is not present.", wafIndexPage.isWafPresent(wafName));
        //TODO: Uncomment when ID is updated
        //assertTrue("WAF type is not correct.", wafIndexPage.getWafType(wafName).equals(wafType));
    }

    @Test
    public void testSearchTagByName() {
        dbUtils.createTag("ExampleTag", "Application");

        JSONObject response = cliUtils.searchTagByName("ExampleTag");
        assertTrue("Tag was not found.", cliUtils.isCommandResponseSuccessful(response));
    }

    @Test
    public void testUploadScanFile() {
        initializeTeamAndAppViaCli();
        String scanPath = ScanContents.SCAN_FILE_MAP.get("IBM Rational AppScan");

        JSONObject response = cliUtils.uploadScanFile(appId, scanPath);
        assertTrue("Upload status wasn't successful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickScansTab();

        assertTrue("Scan is not present in Scans tab.",
                applicationDetailPage.getFirstScanChannelType().equals("IBM Security AppScan Standard"));
    }

    @Test
    public void testGetWafRules() {
        initializeTeamAndAppWithIbmScan();
        String wafName = getName();
        JSONObject waf = cliUtils.createWaf(wafName, "Snort");
        int wafId = cliUtils.getObjectId(waf);

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .clickSetWaf()
                .addWaf(wafName)
                .saveWafAdd()
                .clickUpdateApplicationButton();

        JSONObject response = cliUtils.getWafRules(wafId);
        assertTrue("Response was not successful.", cliUtils.isCommandResponseSuccessful(response));
    }

    public void testCreateTagApplication() {
        String tag = getName();

        JSONObject response = cliUtils.createTag(tag);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink();
        assertTrue("Tag is not present.", tagIndexPage.isAppTagNameLinkPresent(tag));
    }

    @Test
    public void testCreateTagComment() {
        String tag = getName();

        JSONObject response = cliUtils.createTag(tag, "Comment");

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink();
        assertTrue("Tag is not present.", tagIndexPage.isCommentTagNameLinkPresent(tag));
    }

    @Test
    public void testCreateTagVulnerability() {
        String tag = getName();

        JSONObject response = cliUtils.createTag(tag, "Vulnerability");

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));

        TagIndexPage tagIndexPage = loginPage.defaultLogin()
                .clickTagsLink();
        assertTrue("Tag is not present.", tagIndexPage.isVulnerabilityTagNameLinkPresent(tag));
    }

    @Test
    public void testSearchTeamByID() {
        String teamName = getName();
        DatabaseUtils.createTeam(teamName);
        String teamID = DatabaseUtils.getTeamID(teamName);

        JSONObject response = cliUtils.searchTeam("id", teamID);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned team was not correct.", cliUtils.getObjectField(response, "name").equals(teamName));
    }

    @Test
    public void testQueueScan() {

    }
}
