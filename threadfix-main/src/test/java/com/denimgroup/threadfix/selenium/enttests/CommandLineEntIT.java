package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.EnterpriseTests;
import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.tests.BaseDataTest;
import com.denimgroup.threadfix.selenium.tests.ScanContents;
import com.denimgroup.threadfix.selenium.utils.CommandLineUtils;
import com.denimgroup.threadfix.selenium.utils.DatabaseUtils;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertTrue;

/**
 * Created by rtimmons on 8/20/2015.
 */
@Category(EnterpriseTests.class)
public class CommandLineEntIT extends BaseDataTest {
    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String CLI_REST_URL = System.getProperty("CLI_REST_URL");
    private static CommandLineUtils cliUtils = new CommandLineUtils();
    private static DatabaseUtils dbUtils = new DatabaseUtils();

    static {
        cliUtils.setApiKey(API_KEY);
        cliUtils.setUrl(CLI_REST_URL);
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
}
