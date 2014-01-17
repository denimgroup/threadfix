package com.denimgroup.threadfix.selenium.tests;
import static org.junit.Assert.*;

import org.junit.*;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;


public class DashboardTests extends BaseTest{

	public DashboardTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

    private static LoginPage loginPage;
	private RemoteWebDriver driver;
	private DashboardPage dashboardPage;

    String teamName = "linkNavTeam" + getRandomString(3);
    String appName = "linkNavAPP" + getRandomString(3);
    String urlText = "http://testurl.com";
	
	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver)super.getDriver();
		loginPage = LoginPage.open(driver);
	}
    @After
    public void shutdown(){
        cleanUpApplicaitons();
        driver.quit();
    }


	@Test
	public void dashboardGraphsTest(){

		dashboardPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.expandTeamRowByIndex(teamName)
				.addNewApplication(teamName, appName, urlText, "Low")
				.saveApplication(teamName)
				.clickViewAppLink(appName, teamName)
				.clickUploadScanLink()
				.setFileInput(ScanContents.SCAN_FILE_MAP.get("FindBugs"))
				.submitScan()
				.clickDashboardLink();

        //check if the graphs are present
		assertTrue("6 month vuln graph is not displayed",dashboardPage.is6MonthGraphPresent());
		assertTrue("Top 10 graph is not displayed",dashboardPage.isTop10GraphPresent());

        dashboardPage.logout();


	}
    @Test
    public void dashboardApplicationLoadTest(){
        dashboardPage = loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickAddTeamButton()
                .setTeamName(teamName)
                .addNewTeam()
                .expandTeamRowByIndex(teamName)
                .addNewApplication(teamName, appName, urlText, "Low")
                .saveApplication(teamName)
                .clickViewAppLink(appName, teamName)
                .clickUploadScanLink()
                .setFileInput(ScanContents.SCAN_FILE_MAP.get("Skipfish"))
                .submitScan()
                .clickDashboardLink();

        dashboardPage.click6MonthViewMore().clickDashboardLink();

        dashboardPage.clickTop10ViewMore().clickDashboardLink();

        dashboardPage.logout();

    }

    public void cleanUpApplicaitons(){
        loginPage.login("user", "password")
                .clickOrganizationHeaderLink()
                .clickViewTeamLink(teamName)
                .clickDeleteButton()
                .clickOrganizationHeaderLink()
                .logout();

    }
}
