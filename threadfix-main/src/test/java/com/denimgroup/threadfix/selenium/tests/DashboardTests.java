package com.denimgroup.threadfix.selenium.tests;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.*;
import org.openqa.selenium.WebDriver;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.ReportsIndexPage;
import com.denimgroup.threadfix.selenium.pages.ScanDetailPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class DashboardTests extends BaseTest{

	private static LoginPage loginPage;
	private WebDriver driver;
	private ApplicationDetailPage applicationDetailPage;
	private TeamIndexPage teamIndexPage;
	private DashboardPage dashboardPage;
	
	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}
	
	@Test
	public void linkNavigationTest(){
		String teamName = "linkNavTeam" + getRandomString(3);
		String appName = "linkNavAPP" + getRandomString(3);
		String urlText = "http://testurl.com";
		
		dashboardPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByName(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName)
				.clickViewAppLink(appName, teamName)
				.clickUploadScanLink()
				.setFileInput(ScanContents.SCAN_FILE_MAP.get("FindBugs"))
				.submitScan()
				.clickDashboardLink();
		
		assertTrue("6 month vuln graph is not displayed",dashboardPage.is6MonthGraphPresent());
		assertTrue("Top 10 graph is not displayed",dashboardPage.isTop10GraphPresent());
		
//		applicationDetailPage = dashboardPage.clickLatestUploadApp();
//		
//		assertTrue("Did not navigate to correct Application page",applicationDetailPage.getH2Tag().trim().contains(appName));
//		
//		ScanDetailPage scanDetailPage = applicationDetailPage.clickDashboardLink()
//															.clickLatestUploadScan();
//		
//		assertTrue("Did not navigate to correct Scan Detail Page",scanDetailPage.getScanHeader().contains("FindBugs"));
//		
//		ReportsIndexPage reportIndexPage = scanDetailPage.clickDashboardLink()
//														.click6MonthViewMore();
//		
//		reportIndexPage.getCurrentReport();
		
		
		
		
		
		
		
		
		
	}
}
