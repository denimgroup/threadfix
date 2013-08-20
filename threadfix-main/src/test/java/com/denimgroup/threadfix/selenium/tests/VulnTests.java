package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.*;



import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DefectTrackerIndexPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class VulnTests extends BaseTest {
	public VulnTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}
	
	private RemoteWebDriver driver;
	private static LoginPage loginPage;
	private String teamName = getRandomString(8);
	private String appName = getRandomString(8);
	private String dtName = getRandomString(8);
	
	private final static int JIRA = 0;
	private final static int BUG = 1;
	private final static int TFS = 2;
	
//	private static final String TEST_BUGZILLA_URL = DefectTrackerIndexPage.DT_URL;
//	private static final String TEST_JIRA_URL = DefectTrackerIndexPage.JIRA_URL;
	private static String JIRA_USERNAME = null;
	private static String JIRA_PASSWORD = null;
	private static String JIRA_URL = null;
	private static String JIRA_PROJECTNAME = null;
	private static String BUGZILLA_USERNAME = null;
	private static String BUGZILLA_PASSWORD = null;
	private static String BUGZILLA_URL = null;
	private static String BUGZILLA_PROJECTNAME = "For ThreadFix";
	private static String TFS_USERNAME = null;
	private static String TFS_PASSWORD = null;
	private static String TFS_URL = null;
	private static String TFS_PROJECTNAME = null;
	
	@Before
	public void init() {
		super.init();
		assignVars();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
		}
	
//	public static URL getScanFilePath(String category, String scannerName,
//			String fileName) {
//		String string = "/SupportingFiles/" + category + "/" + scannerName + "/"
//				+ fileName;
//
//		return ClassLoader.getSystemResource(string);// .getFile();
//	}
	
	@After
	public void shutDown() {
		driver.quit();
	}
	
	@Test
	public void mergeSingleVulnJira(){
		assertTrue("Jira",build(JIRA));
		//merge here
		//nav to app detail page
		ApplicationDetailPage ad = loginPage.login("user", "password")
											.clickOrganizationHeaderLink()
											.expandTeamRowByName(teamName)
											.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-89")
				.clickMergeDefectSubmit();
		
		//verify
		ad = ad.clickExpandAllVulns();
		
		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 1);
		
		
		ad.logout();
		destroy();
	}
	
	@Test
	public void mergeSingleVulnBugzilla(){
		assertTrue("bug",build(BUG));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//verify
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 1);


		ad.logout();
		destroy();
	}
	@Ignore
	@Test
	public void mergeSingleVulnTFS(){
		assertTrue("bug",build(TFS));
		//merge here
		destroy();
	}
	
	@Test
	public void mergeMultiVulnJira(){
		assertTrue("Jira",build(JIRA));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-89")
				.clickMergeDefectSubmit();

		//verify
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 3);


		ad.logout();
		destroy();
	}
	
	@Test
	public void mergeMultiVulnBugzilla(){
		assertTrue("bug",build(BUG));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//verify
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 3);


		ad.logout();
		destroy();
	}
	@Ignore
	@Test
	public void mergeMultiVulnTFS(){
		assertTrue("bug",build(TFS));
		//merge here
		destroy();
	}
	
	@Test
	public void changeMergeSingleVulnJira(){
		assertTrue("Jira",build(JIRA));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-89")
				.clickMergeDefectSubmit();

		//change merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-88")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 1);


		ad.logout();
		destroy();
	}
	
	@Test
	public void changeMergeSingleVulnBugzilla(){
		assertTrue("bug",build(BUG));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();

		//change merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 1);


		ad.logout();
		destroy();
	}
	@Ignore
	@Test
	public void changeMergeSingleVulnTFS(){
		assertTrue("bug",build(TFS));
		//merge here
		destroy();
	}
	
	@Test
	public void changeMergeMultiVulnJira(){
		assertTrue("Jira",build(JIRA));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-89")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-88")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 3);


		ad.logout();
		destroy();
	}
	
	@Test
	public void changeMergeMultiVulnBugzilla(){
		assertTrue("bug",build(BUG));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 3);


		ad.logout();
		
		destroy();
	}
	@Ignore
	@Test
	public void changeMergeMultiVulnTFS(){
		assertTrue("bug",build(TFS));
		//merge here
		destroy();
	}
	
	@Test
	public void changeMergeMultiDiffVulnJira(){
		assertTrue("Jira",build(JIRA));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-89")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(5)
				.clickVulnCheckBox(6)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-88")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("THREAD-86")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 6);


		ad.logout();
		destroy();
	}
	
	@Test
	public void changeMergeMultiDiffVulnBugzilla(){
		assertTrue("bug",build(BUG));
		ApplicationDetailPage ad = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.expandTeamRowByName(teamName)
				.clickViewAppLink(appName, teamName);
		//submit merge
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(2)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("2")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(4)
				.clickVulnCheckBox(5)
				.clickVulnCheckBox(6)
				.clickMergeDefectLink()
				.selectMergeDefect("4")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns()
				.clickVulnCheckBox(1)
				.clickVulnCheckBox(6)
				.clickVulnCheckBox(3)
				.clickMergeDefectLink()
				.selectMergeDefect("3")
				.clickMergeDefectSubmit();
		
		ad = ad.clickExpandAllVulns();

		assertTrue("Number of submitted vulns is incorrect",ad.getNumOfSubmitedDefects() == 6);


		ad.logout();
		destroy();
	}
	@Ignore
	@Test
	public void changeMergeMultiDiffVulnTFS(){
		assertTrue("bug",build(TFS));
		//merge here
		destroy();
	}
	
	private boolean build(int dtType){
		String dt = "";
		String dturl = "";
		String uName = "";
		String pWord = "";
		String pName = "";
		String rtApp = "Demo Site BE";
		String whKey = System.getProperty("WHITEHAT_KEY");
		switch(dtType){
			case JIRA:
				dt = "Jira";
				dturl = JIRA_URL;
				uName = JIRA_USERNAME;
				pWord = JIRA_PASSWORD;
				pName = JIRA_PROJECTNAME;
				break;
			case BUG:
				dt = "Bugzilla";
				dturl = BUGZILLA_URL;
				uName = BUGZILLA_USERNAME;
				pWord = BUGZILLA_PASSWORD;
				pName = BUGZILLA_PROJECTNAME;
				break;
			case TFS:
				dt = "Microsoft TFS";
				dturl = TFS_URL;
				uName = TFS_USERNAME;
				pWord = TFS_PASSWORD;
				pName = TFS_PROJECTNAME;
				break;
			default:
				return false;
		}
		//add team
		TeamIndexPage teamIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam();
		
		//add app
		teamIndexPage = teamIndexPage.expandTeamRowByName(teamName)
					.addNewApplication(teamName, appName, "", "Low")
					.saveApplication(teamName);
		
		//add defect Tracker
		DefectTrackerIndexPage defectTrackerIndexPage = teamIndexPage.clickDefectTrackersLink()
																	.clickAddDefectTrackerButton()
																	.enterName(null, dtName)
																	.enterType(null, dt)
																	.enterURL(null, dturl)
																	.clickSaveNewDefectTracker();
		
		//attach defect Tracker
		ApplicationDetailPage applicationDetailPage = defectTrackerIndexPage.clickOrganizationHeaderLink()
																			.expandTeamRowByName(teamName)
																			.clickViewAppLink(appName, teamName)
																			.addDefectTracker(dtName, uName, pWord, pName);
		//import scan
		applicationDetailPage.clickRemoteProvidersLink()
							.clickConfigureWhiteHat()
							.setWhiteHatAPI(whKey)
							.saveWhiteHat()
							.clickEditMapping(rtApp)
							.setTeamMapping(rtApp, teamName)
							.setAppMapping(rtApp, appName)
							.clickSaveMapping(rtApp)
							.clickImportScan(rtApp)
							.logout();
		
		
		return true;
	}
	
	private void destroy(){
		loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickViewTeamLink(teamName)
				.clickDeleteButton()
				.clickRemoteProvidersLink()
				.clickRemoveWhiteHatConfig()
				.clickDefectTrackersLink()
				.clickDeleteButton(dtName)
				.logout();
	}
	
	private void assignVars() {
		String tmp = System.getProperty("JIRA_USERNAME");
		if (tmp != null) {
			JIRA_USERNAME = tmp;
		}
		tmp = System.getProperty("JIRA_PASSWORD");
		if (tmp != null) {
			JIRA_PASSWORD = tmp;
		}
		tmp = System.getProperty("JIRA_URL");
		if (tmp != null) {
			JIRA_URL = tmp;
		}
		tmp = System.getProperty("JIRAPROJECTNAME");
		if (tmp != null) {
			JIRA_PROJECTNAME = tmp;
		}
		tmp = System.getProperty("BUGZILLA_USERNAME");
		if (tmp != null) {
			BUGZILLA_USERNAME = tmp;
		}
		tmp = System.getProperty("BUGZILLA_PASSWORD");
		if (tmp != null) {
			BUGZILLA_PASSWORD = tmp;
		}
		tmp = System.getProperty("BUGZILLA_URL");
		if (tmp != null) {
			BUGZILLA_URL = tmp;
		}
		tmp = System.getProperty("BUGZILLAPROJECTNAME");
		if (tmp != null) {
			BUGZILLA_PROJECTNAME = tmp;
		}
		tmp = System.getProperty("TFS_USERNAME");
		if (tmp != null) {
			TFS_USERNAME = tmp;
		}
		tmp = System.getProperty("TFS_PASSWORD");
		if (tmp != null) {
			TFS_PASSWORD = tmp;
		}
		tmp = System.getProperty("TFS_URL");
		if (tmp != null) {
			TFS_URL = tmp;
		}
		tmp = System.getProperty("TFS_PROJNAME");
		if (tmp != null) {
			TFS_PROJECTNAME = tmp;
		}
	}
}
