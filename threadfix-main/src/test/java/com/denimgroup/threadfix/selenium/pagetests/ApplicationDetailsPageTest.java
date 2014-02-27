package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.assertTrue;

import com.denimgroup.threadfix.selenium.pages.*;
import com.denimgroup.threadfix.selenium.tests.BaseTest;
import org.junit.*;

public class ApplicationDetailsPageTest extends BaseTest {
	
	private  DashboardPage dashboardPage;
	private  boolean build;
	private  String teamName = getRandomString(8);
	private  String appName = getRandomString(8);
	private  String wafName = getRandomString(8);
	private  String dtName = getRandomString(8);
	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	private static final String BUGZILLA_USERNAME = System.getProperty("BUGZILLA_USERNAME");
	private static final String BUGZILLA_PASSWORD = System.getProperty("BUGZILLA_PASSWORD");
	private static final String BUGZILLAPROJECTNAME = System.getProperty("BUGZILLAPROJECTNAME");
	private static final String whKey = System.getProperty("WHITEHAT_KEY");

	

	@Test
	public void pageBuild(){
        buildElements();
		assertTrue("page was able to build database completely", true);
		dashboardPage.logout();
	}
	
	private boolean buildElements(){
		String rtApp = "Demo Site BE";
		String wafType = "mod_security";
		String dtType = "Bugzilla";

        //login
        dashboardPage = loginPage.login("user", "password");

		//add team
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(teamName)
										.addNewTeam();
		//add app
		ti = ti	.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, "", "Low")
				.saveApplication(teamName);
		
		//add defect tacker
		DefectTrackerIndexPage dt = ti.clickDefectTrackersLink()
									.clickAddDefectTrackerButton()
									.enterName(null, dtName)
									.enterType(null, dtType)
									.enterURL(null, TEST_BUGZILLA_URL)
									.clickSaveNewDefectTracker();
		
		//import remoteProvider
		ApplicationDetailPage ap = dt.clickRemoteProvidersLink()
										.clickConfigureWhiteHat()
										.setWhiteHatAPI(whKey)
										.saveWhiteHat()
										.clickEditMapping(rtApp)
										.setTeamMapping(rtApp, teamName)
										.setAppMapping(rtApp, appName)
										.clickSaveMapping(rtApp)
										.clickImportScan(rtApp);



		
		//attach defectTracker
		ap = ap.addDefectTracker(dtName, BUGZILLA_USERNAME,
				BUGZILLA_PASSWORD, BUGZILLAPROJECTNAME);
		
		sleep(5000);
		//mark closed false positive
		ap = ap.clickExpandAllVulns()
		.clickVulnCheckBox(1)
		.clickMarkClosedLink()
		.clickExpandAllVulns()
		.clickVulnCheckBox(1)
		.clickMarkFalsePositiveLink();

		
		//add attach waf

		dt.clickWafsHeaderLink()
				.clickAddWafLink()
				.createNewWaf(wafName, wafType)
				.clickCreateWaf()
				.clickOrganizationHeaderLink()
				.expandTeamRowByIndex(teamName)
				.clickViewAppLink(appName,teamName)
				.clickEditDeleteBtn()
				.clickAddWaf()
				.addWaf(wafName)
				.logout();


        destroyElements();
		return true;
	}
	
	private void destroyElements(){
		
		dashboardPage = loginPage.login("user", "password");
		
		dashboardPage.clickOrganizationHeaderLink()
					.clickViewTeamLink(teamName)
					.clickDeleteButton()
					.clickRemoteProvidersLink()
					.clickRemoveWhiteHatConfig()
					.clickDefectTrackersLink()
					.clickDeleteButton(dtName)
					.clickWafsHeaderLink()
					.clickDeleteWaf(wafName)
					.logout();
		
	}

}
