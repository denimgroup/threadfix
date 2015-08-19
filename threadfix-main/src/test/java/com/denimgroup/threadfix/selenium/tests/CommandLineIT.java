package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.TagIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.pages.WafIndexPage;
import com.denimgroup.threadfix.selenium.utils.CommandLineUtils;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;

import java.util.List;

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

    @Test
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

        JSONObject response = cliUtils.searchTeamByID(teamID);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned team was not correct.", cliUtils.getObjectField(response, "name").equals(teamName));
    }

    @Test
    public void testQueueScan() {
        initializeTeamAndAppViaCli();

        JSONObject response = cliUtils.queueScan(appId, "zap");
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickScanAgentTasksTab(1);
        assertTrue("Scheduled scan isn't present.",
                ("OWASP Zed Attack Proxy").equals(applicationDetailPage.getScanAgentTaskScannerType(0)));
    }

    @Test
    public void testSearchTeamByName() {
        String teamName = getName();
        DatabaseUtils.createTeam(teamName);

        JSONObject response = cliUtils.searchTeamByName(teamName);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned team was not correct.", cliUtils.getObjectField(response, "name").equals(teamName));
    }

    @Test
    public void testSearchApplicationByID() {
        String teamName = getName();
        String appName = getName();
        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);
        String appID = DatabaseUtils.getApplicationID(teamName, appName);

        JSONObject response = cliUtils.searchAppByID(appID);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned application was not correct.", cliUtils.getObjectField(response, "name").equals(appName));
    }

    @Test
    public void testSearchApplicationByName() {
        String teamName = getName();
        String appName = getName();
        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        JSONObject response = cliUtils.searchAppByName(appName, teamName);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned application was not correct.", cliUtils.getObjectField(response, "name").equals(appName));
    }

    @Test
    public void testSearchApplicationByUniqueID() {
        String teamName = getName();
        String appName = getName();
        String uniqueID = getName();
        DatabaseUtils.createTeam(teamName);
        DatabaseUtils.createApplication(teamName, appName);

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandAllTeams()
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn()
                .setUniqueId(uniqueID)
                .clickModalSubmit();

        JSONObject response = cliUtils.searchAppByUniqueID(uniqueID, teamName);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned application was not correct.", cliUtils.getObjectField(response, "name").equals(appName));
    }

    @Test
    public void testSearchWafByID() {
        String wafName = getName();
        DatabaseUtils.createWaf(wafName, "mod_security");
        String wafID = DatabaseUtils.getWafID(wafName);

        JSONObject response = cliUtils.searchWafByID(wafID);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned WAF was not correct.", cliUtils.getObjectField(response, "name").equals(wafName));
    }

    @Test
    public void testSearchWafByName() {
        String wafName = getName();
        DatabaseUtils.createWaf(wafName, "mod_security");

        JSONObject response = cliUtils.searchWafByName(wafName);

        assertTrue("JSON response was not successful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Returned WAF was not correct.", cliUtils.getObjectField(response, "name").equals(wafName));
    }

    @Test
    public void testAddUrl() {
        initializeTeamAndAppViaCli();
        final String CHANGED_URL = "http://changedurl.com";

        JSONObject response = cliUtils.addUrlToApp(appId, CHANGED_URL);
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn();
        assertTrue("URL was not changed in modal.", CHANGED_URL.equals(applicationDetailPage.getUrlText()));
    }

    @Test
    public void testSetTaskConfigFile() {
        final String SCANNER = "zap";
        final String CONFIG_FILEPATH = ScanContents.SCAN_FILE_MAP.get("Snort Log");

        initializeTeamAndAppViaCli();
        cliUtils.queueScan(appId, SCANNER);

        JSONObject response = cliUtils.setTaskConfigFile(appId, SCANNER, CONFIG_FILEPATH);
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickFilesTab();
        assertTrue("Config file wasn't set properly.", applicationDetailPage.isUploadedFilePresent("zap"));
    }

    @Test
    public void testSetParameters() {
        final String FRAMEWORK_TYPE = "RAILS";
        final String REPOSITORY_URL = "https://github.com/denimgroup/threadfix.git";
        initializeTeamAndAppViaCli();

        JSONObject response = cliUtils.setParameters(appId, FRAMEWORK_TYPE, REPOSITORY_URL);
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName)
                .clickEditDeleteBtn();
        assertTrue("Framework type was not set correctly.",
                FRAMEWORK_TYPE.equals(applicationDetailPage.getApplicationType()));
        applicationDetailPage.clickSourceInfo();
        System.out.println("Repo URL is " + applicationDetailPage.getRepositoryUrl());

        assertTrue("Repository URL was not set correctly.",
                REPOSITORY_URL.equals(applicationDetailPage.getRepositoryUrl()));
    }

    @Test
    public void testAddTagToApplication() {
        final String TAG_NAME = getName();
        final String TAG_TYPE = "Application";
        initializeTeamAndAppViaCli();

        JSONObject tag = cliUtils.createTag(TAG_NAME, TAG_TYPE);
        int tagId = cliUtils.getObjectId(tag);

        JSONObject response = cliUtils.addTagToApplication(appId, tagId);
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        ApplicationDetailPage applicationDetailPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink()
                .expandTeamRowByName(teamName)
                .clickApplicationName(teamName, appName);
        System.out.println();
        assertTrue("Tag isn't present on application.", applicationDetailPage.isTagLinkPresent());
    }

    @Test
    public void testLookupAllTags() throws JSONException{
        String tagName = getName();
        DatabaseUtils.createTag(tagName, "Application");

        JSONObject response = cliUtils.lookupTags();
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));
    }

    @Test
    public void testSearchTagByID() {
        String tagName = getName();
        DatabaseUtils.createTag(tagName, "Application");
        int tagID = DatabaseUtils.getTagId(tagName, true);

        JSONObject response = cliUtils.searchTagByID(tagID);
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));
        assertTrue("Tag was not correct.", cliUtils.getObjectField(response, "name").equals(tagName));
    }

    @Test
    public void testVulnerabilitySearchByID() {
        initializeTeamAndAppWithWebInspectScan();

        JSONObject response = cliUtils.vulnSearchByID("79");
        assertTrue("Response was unsuccessful.", cliUtils.isCommandResponseSuccessful(response));

        JSONArray vulnerabilities = cliUtils.getObject(response, "object");
        assertTrue("Number of vulnerabilities was incorrect.", vulnerabilities.length() == 1);
    }
}
