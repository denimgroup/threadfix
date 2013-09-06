package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.assertTrue;

import org.junit.*;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class ApplicationDetailsPageTest extends PageBaseTest {
	
	public ApplicationDetailsPageTest(String browser){
		super(browser);
	}
	
	private  DashboardPage dashboardPage;
	private  boolean build;
	private  String teamName = getRandomString(8);
	private  String appName = getRandomString(8);
	private  String wafName = getRandomString(8);
	private  String dtName = getRandomString(8);
	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
	private static String BUGZILLA_USERNAME = null;
	private static String BUGZILLA_PASSWORD = null;
	private static String BUGZILLA_PROJECTNAME = "For ThreadFix";
	
	
	
	@Before
	public void init() {
		super.init();
		String tmp = System.getProperty("BUGZILLA_USERNAME");
		if (tmp != null) {
			BUGZILLA_USERNAME = tmp;
		}
		tmp = System.getProperty("BUGZILLA_PASSWORD");
		if (tmp != null) {
			BUGZILLA_PASSWORD = tmp;
		}
		tmp = System.getProperty("bugzillaProjectName");
		if (tmp != null) {
			BUGZILLA_PROJECTNAME = tmp;
		}
		build = buildElements();
	}
	
	@After
	public  void cleanup(){
		destroyElements();
		super.shutDown();
	}
	
	@Test
	public void pageBuild(){
		assertTrue(build);
//		dashboardPage.logout();
	}
	
	private  boolean buildElements(){
		dashboardPage = login();
		String rtApp = "Demo Site BE";
		String wafType = "mod_security";
		String dtType = "Bugzilla";
		String whKey = System.getProperty("WHITEHAT_KEY");
		if(whKey == null){
			return false;
		}
		//add team
		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink()
										.clickAddTeamButton()
										.setTeamName(teamName)
										.addNewTeam();
		//add app
		ti = ti	.expandTeamRowByName(teamName)
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
		sleep(5000);
		//submit defect
//		ap = ap.clickExpandAllVulns()
//		.clickVulnCheckBox(1)
//		.clickSubmitDefectLink();
		

		
		//attach defectTracker
		ap = ap.addDefectTracker(dtName, BUGZILLA_USERNAME,
				BUGZILLA_PASSWORD, BUGZILLA_PROJECTNAME);
		
		sleep(5000);
		//mark closed false positive
		ap = ap.clickExpandAllVulns()
		.clickVulnCheckBox(1)
		.clickMarkClosedLink()
		.clickExpandAllVulns()
		.clickVulnCheckBox(1)
		.clickMarkFalsePositiveLink();
//		.addCommentToFirstVuln("comment");
		
		//add attach waf
		dt.clickWafsHeaderLink()
				.clickAddWafLink()
				.createNewWaf(wafName, wafType)
				.clickCreateWaf()
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName,teamName)
				.clickEditDeleteBtn()
				.clickAddWaf()
				.addWaf(wafName)
				.logout();
		

//		dashboardPage = login();
		
		return true;
	}
	
	private void destroyElements(){
		
		dashboardPage = login();
		
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
