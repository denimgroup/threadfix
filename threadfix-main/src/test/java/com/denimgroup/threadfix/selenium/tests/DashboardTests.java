////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2014 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.selenium.tests;
import static org.junit.Assert.assertTrue;

import org.junit.*;
import org.openqa.selenium.remote.RemoteWebDriver;

import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;

public class DashboardTests extends BaseTest{

	public DashboardTests(String browser) {
		super(browser);
		// TODO Auto-generated constructor stub
	}

	private static LoginPage loginPage;
	private RemoteWebDriver driver;
	private DashboardPage dashboardPage;
	
	@Before
	public void init() {
		super.init();
		driver = (RemoteWebDriver) super.getDriver();
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
