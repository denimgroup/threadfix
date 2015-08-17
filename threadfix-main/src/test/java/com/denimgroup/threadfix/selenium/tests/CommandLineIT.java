package com.denimgroup.threadfix.selenium.tests;

import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.utils.CommandLineUtils;
import org.junit.Test;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import javax.validation.constraints.AssertTrue;

/**
 * Created by rtimmons on 8/17/2015.
 */
public class CommandLineIT extends BaseDataTest {

    private static final String API_KEY = System.getProperty("API_KEY");
    private static final String REST_URL = System.getProperty("REST_URL");
    private static CommandLineUtils utils = new CommandLineUtils();

    static {
        utils.setApiKey(API_KEY);
        utils.setUrl(REST_URL);
    }

    @Test
    public void testCreateTeam() {
        String teamName = getName();
        String result = utils.executeJarCommand("-ct", teamName);
        assertTrue("Response wasn't successful.", utils.isCommandResponseSuccessful(result));

        TeamIndexPage teamIndexPage = loginPage.defaultLogin()
                .clickOrganizationHeaderLink();
        assertTrue("Team was not present.", teamIndexPage.isTeamPresent(teamName));
    }
}
