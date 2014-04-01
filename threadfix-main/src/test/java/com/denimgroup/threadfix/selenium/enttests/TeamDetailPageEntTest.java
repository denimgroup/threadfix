package com.denimgroup.threadfix.selenium.enttests;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;
import com.denimgroup.threadfix.selenium.tests.BaseTest;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class TeamDetailPageEntTest extends BaseTest {

	private DashboardPage dashboardPage;
	private String teamName = getRandomString(8);
	private String appName = getRandomString(8);

	@Ignore // permissions are being tested, should not test for current setup
	@Test
	public void permUsersModalTest(){
        assertTrue("Build did not work properly", buildElements());
        TeamDetailPage teamDetailPage = dashboardPage.clickOrganizationHeaderLink().clickViewTeamLink(teamName).clickUserPermLink();
		boolean editPresent = teamDetailPage.isPUEditPermLinkPresent();
		boolean editClick = teamDetailPage.isPUEditPermLinkClickable();
		boolean closePresent = teamDetailPage.isPUClosePresent();
		boolean closeClick = teamDetailPage.isPUCloseClickable();
		
		teamDetailPage.clickCloseUserPermModal().logout();
		
		String ep,ec,cp,cc;
		ep = ec = cp = cc = "";
		if(!editPresent){ep = "Edit Perm Link was not present";}
		if(!editClick){ec = "Edit Perm Link was not clickable";}
		if(!closePresent){cp = "Close button was not present";}
		if(!closeClick){cc = "Close button was not clickable";}
		assertTrue(ep + " | "+ ec + " | "+ cp + " | "+ cc,
				editPresent && editClick && closePresent && closeClick);
		
//		assertTrue(true);
//		dashboardPage.logout();
	}
	
	private  boolean buildElements(){
		dashboardPage = loginPage.login("user", "password");
		String whiteHatApplication = "Demo Site BE";
		String whiteHatKey = System.getProperty("WHITEHAT_KEY");

        if(whiteHatKey == null){
			return false;
		}

		//Add Team
        TeamIndexPage teamIndexPage = dashboardPage.clickOrganizationHeaderLink()
                .clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam();

		//Add Application
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
                .addNewApplication(teamName, appName, "", "Low")
                .saveApplication(teamName);

		//Import RemoteProviders
		teamIndexPage.clickRemoteProvidersLink()
                .clickConfigureWhiteHat()
                .setWhiteHatAPI(whiteHatKey)
                .saveWhiteHat()
                .clickEditMapping(whiteHatApplication)
                .setTeamMapping(whiteHatApplication, teamName)
                .setAppMapping(whiteHatApplication, appName)
                .clickSaveMapping(whiteHatApplication)
                .clickImportScan(whiteHatApplication)
                .logout();

		dashboardPage = loginPage.login("user", "password");
		
		return true;
	}
}
