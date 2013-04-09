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
package com.denimgroup.threadfix.selenium.tests;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.openqa.selenium.firefox.FirefoxDriver;

import com.denimgroup.threadfix.selenium.pages.ApplicationDetailPage;
import com.denimgroup.threadfix.selenium.pages.EditMappingPage;
import com.denimgroup.threadfix.selenium.pages.LoginPage;
import com.denimgroup.threadfix.selenium.pages.RemoteProviderCredentialsPage;
import com.denimgroup.threadfix.selenium.pages.RemoteProvidersIndexPage;


public class RemoteProvidersTests extends BaseTest {
	private FirefoxDriver driver;

	private static LoginPage loginPage;

	private EditMappingPage edtMapPage;
	
	private static final String SENTINEL_API_KEY = "your-key";
	private static final String VERACODE_USER = "username";
	private static final String VERACODE_PASSWORD = "password";
	private static final String QUALYS_USER = "username";
	private static final String QUALYS_PASS = "password";

	@Before
	public void init() {
		super.init();
		driver = super.getDriver();
		loginPage = LoginPage.open(driver);
	}

	@Test
	public void navigationTest() {
		String pageHeader = loginPage.login("user", "password")
									.clickRemoteProvidersLink()
									.getH2Tag();
		
		assertTrue("Remote Provider Page not found",
				pageHeader.contains("Remote Providers"));
	}

	@Test
	public void configureSentinel() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		
		RemoteProviderCredentialsPage rpCredPage = loginPage.login("user", "password")
							  								.clickRemoteProvidersLink()
							  								.clickConfigure(2);
		
		String headerText = rpCredPage.getH2Tag();
		assertTrue("Configure Page Not Found",
				headerText.contains("Remote Provider WhiteHat Sentinel"));
		
		String pageHeader = rpCredPage.setAPI(SENTINEL_API_KEY).clickSave(false).getH2Tag();
		assertTrue("Remote Provider Page not found",
				pageHeader.contains("Remote Providers"));
	}

	@Test
	public void testClearSentinel() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}

		String PageHeader = loginPage.login("user", "password")
									 .clickRemoteProvidersLink()
									 .clickClearConfigButton(0)
									 .getH2Tag();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
	}

	@Test
	public void configureVeracode() {
		if (VERACODE_PASSWORD.equals("password") || VERACODE_USER.equals("username")) {
			return;
		}
		
		RemoteProviderCredentialsPage rpCredPage = loginPage.login("user", "password")
															.clickRemoteProvidersLink()
															.clickConfigure(1);

		String headerText = rpCredPage.getH2Tag();
		assertTrue("Configure Page Not Found",
				headerText.contains("Remote Provider Veracode"));
		
		String pageHeader = rpCredPage.fillAllClickSaveUsernamePassword(VERACODE_USER,
				VERACODE_PASSWORD, false).getH2Tag();
		assertTrue("Remote Provider Page not found",
				pageHeader.contains("Remote Providers"));
	}

	// Remove Configuration User Name Pwd

	@Test
	public void clearVeracodeConfig() {
		if (VERACODE_PASSWORD.equals("password") || VERACODE_USER.equals("username")) {
			return;
		}

		String pageHeader = loginPage.login("user", "password")
									 .clickRemoteProvidersLink()
									 .clickClearConfigButton(0)
									 .getH2Tag();
		
		assertTrue("Remote Provider Page not found",
				pageHeader.contains("Remote Providers"));
	}

	@Test
	public void configureQualys() {
		if (QUALYS_PASS.equals("password") || QUALYS_USER.equals("username")) {
			return;
		}
		RemoteProvidersIndexPage rpIndexPage = loginPage.login("user", "password")
														.clickRemoteProvidersLink();
		
		rpIndexPage.clickConfigure(0);
		RemoteProviderCredentialsPage rpCredPage = new RemoteProviderCredentialsPage(
				driver);
		String HeaderText = driver.findElementByTagName("h2").getText();
		assertTrue("Configure Page Not Found",
				HeaderText.contains("Remote Provider QualysGuard WAS"));
		rpIndexPage = rpCredPage.fillAllClickSaveUsernamePassword(QUALYS_USER,QUALYS_PASS, false);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		rpIndexPage.clickClearConfigButton(0);
	}

	// Need to have team - NewTeam White hat and application - WhiteHat
	// Application

	@Test
	public void configureTeamLink() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		String orgName = "Sample WhiteHat Remote Provider Team";
		String appName = "WhiteHat Application";
		String urlText = "http://test.com";
		edtMapPage = loginPage.login("user", "password")
							.clickOrganizationHeaderLink()
							.clickAddTeamButton()
							.addNewTeam(orgName)
							.expandTeamRowByName(orgName)
							.addNewApplication(orgName, appName, urlText, "Low")
							.clickRemoteProvidersLink()
							.clickConfigure(2)
							.setAPI(SENTINEL_API_KEY)
							.clickSave(false)
		        			.clickEdit(0);
		
		String pageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Mapping Page Not Found",
				pageHeader.contains("Edit Mapping for Demo Site BE"));
		
		String pageText = edtMapPage.fillAllClickSaveTeam("Sample WhiteHat Remote Provider Team",
				"WhiteHat Application").getH2Tag();
		
		assertTrue("Remote Provider Page not found",
				pageText.contains("Remote Providers"));
	}

	@Test
	public void addTeamsNoApp() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		RemoteProvidersIndexPage rpIndexPage = loginPage.login("user", "password")
				.clickRemoteProvidersLink();
		
		rpIndexPage.clickEdit(3);
		edtMapPage = new EditMappingPage(driver);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Mapping Page Not Found",
				PageHeader.contains("Edit Mapping for Demo Site SE"));
		edtMapPage.fillAllClickSaveTeam("Sample WhiteHat Remote Provider Team", "");
		String Error = driver.findElementById("application.id.errors")
				.getText();
		assertTrue("Mapping Oage Not Found",
				Error.contains("Application is invalid."));
		edtMapPage = new EditMappingPage(driver);
		edtMapPage.clickBackLink();
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageText.contains("Remote Providers"));
	}

	@Test
	public void addNoTeam() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		edtMapPage = loginPage.login("user", "password")
							.clickRemoteProvidersLink()
							.clickEdit(3);
		
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Mapping Page Not Found",
				PageHeader.contains("Edit Mapping for Demo Site SE"));
		edtMapPage.fillAllClickSaveTeam("Pick a Team", "");
		String error = driver.findElementById("application.id.errors")
				.getText();
		assertTrue("Mapping Page Not Found",
				error.contains("Application is invalid."));
		edtMapPage = new EditMappingPage(driver);
		
		String pageText = edtMapPage.clickBackLink().getH2Tag();
		assertTrue("Remote Provider Page not found",
				pageText.contains("Remote Providers"));
	}

	// Need to have team - NewTeam White hat and application - WhiteHat
	// Application

	@Test
	public void importScan() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		RemoteProvidersIndexPage rpIndexPage = loginPage.login("user", "password")
														.clickRemoteProvidersLink();
		rpIndexPage.clickEdit(1);
		edtMapPage = new EditMappingPage(driver);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Mapping Page Not Found",
				PageHeader.contains("Edit Mapping for Demo Site PE"));
		edtMapPage.fillAllClickSaveTeam("Sample WhiteHat Remote Provider Team",
				"WhiteHat Application");
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageText.contains("Remote Providers"));
		rpIndexPage.clickImport(0);
		ApplicationDetailPage appDetPage = new ApplicationDetailPage(driver);
		String pageHeader = appDetPage.getNameText();
		assertTrue("Application Page not Found",
				pageHeader.contains("WhiteHat Application"));
		
		appDetPage.sleep(1000);
		
		appDetPage.clickViewScansLink()
        	.clickDeleteScanButton(0)
        	.clickBackToAppLink()
        	.clickDeleteLink()
        	.clickDeleteButton()
        	.clickRemoteProvidersLink()
        	.clickClearConfigButton(0);
	}
	
}
