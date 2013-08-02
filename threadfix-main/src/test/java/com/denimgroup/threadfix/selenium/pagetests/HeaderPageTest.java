////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2013 Denim Group, Ltd.
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
package com.denimgroup.threadfix.selenium.pagetests;

import static org.junit.Assert.*;


import org.junit.*;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.DashboardPage;
import com.denimgroup.threadfix.selenium.pages.TeamIndexPage;

public class HeaderPageTest extends PageBaseTest {
	public HeaderPageTest(String browser) {
		super(browser);
	}

//	private static LoginPage loginPage;
//	private RemoteWebDriver driver;
	private  DashboardPage dashboardPage;
	private  boolean build;
	private  String teamName = getRandomString(8);;
	private  String wafName = getRandomString(8);;
	private  String appName = getRandomString(8);;
	
//	@BeforeClass
//	public void setup(){
//		build = buildElements();
//	}
	
	@Before
	public void init() {
		super.init();
		build = buildElements();
	}
	
	@After
	public  void cleanup(){
		destroyElements();
	}
	
	@Test
	public void dashboardHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present on dashboard page",dashboardPage.isDashboardMenuLinkPresent());
//		TeamIndexPage ti = dashboardPage.clickOrganizationHeaderLink();
//		assertTrue("Dashboard header link is not present on Team Index page",ti.isDashboardMenuLinkPresent());
		
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void applicationsHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isApplicationMenuLinkPresent());
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void scansHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isScansMenuLinkPresent());
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void reportsHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isReportsMenuLinkPresent());
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void userHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isUsersMenuLinkPresent());
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void configHeaderElementPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isConfigMenuLinkPresent());
		//logout
		dashboardPage.logout();
	}
	
	@Test
	public void logoIsPresentTest(){
		org.junit.Assume.assumeTrue(build);
		assertTrue("Dashboard header link is not present",dashboardPage.isLogoPresent());
		//logout
		dashboardPage.logout();
	}
	
	private  boolean buildElements(){
		dashboardPage = login();
		String rtApp = "Demo Site BE";
		String wafType = "mod_security";
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
		
		//import remoteProvider
		ApplicationDetailPage ap = ti.clickRemoteProvidersLink()
										.clickConfigureWhiteHat()
										.setWhiteHatAPI(whKey)
										.saveWhiteHat()
										.clickEditMapping(rtApp)
										.setTeamMapping(rtApp, teamName)
										.setAppMapping(rtApp, appName)
										.clickSaveMapping(rtApp)
										.clickImportScan(rtApp);
		
		//add attach waf
		ap.clickWafsHeaderLink()
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
		
		dashboardPage = login();
		
		return true;
	}
	
	private void destroyElements(){
		
		dashboardPage = login();
		
		dashboardPage.clickOrganizationHeaderLink()
					.clickViewTeamLink(teamName)
					.clickDeleteButton()
					.clickRemoteProvidersLink()
					.clickRemoveWhiteHatConfig()
					.clickWafsHeaderLink()
					.clickDeleteWaf(wafName)
					.logout();
		
	}
	
}
