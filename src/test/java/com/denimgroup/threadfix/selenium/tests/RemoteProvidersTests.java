////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2011 Denim Group, Ltd.
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 1.1 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     The Original Code is Vulnerability Manager.
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
import com.denimgroup.threadfix.selenium.pages.OrganizationIndexPage;
import com.denimgroup.threadfix.selenium.pages.RemoteProviderCredentialsPage;
import com.denimgroup.threadfix.selenium.pages.RemoteProvidersIndexPage;

public class RemoteProvidersTests extends BaseTest {
	private FirefoxDriver driver;

	private static LoginPage loginPage;

	private RemoteProvidersIndexPage rpIndexPage;
	private OrganizationIndexPage organizationIndexPage;
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
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		sleep(1000);
	}

	@Test
	public void configureSentinel() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		rpIndexPage = new RemoteProvidersIndexPage(
				driver);
		rpIndexPage.clickConfigure(2);
		RemoteProviderCredentialsPage rpCredPage = new RemoteProviderCredentialsPage(
				driver);
		String HeaderText = driver.findElementByTagName("h2").getText();
		assertTrue("Configure Page Not Found",
				HeaderText.contains("Remote Provider WhiteHat Sentinel"));
		rpCredPage.fillAllClickSaveAPI(SENTINEL_API_KEY,false);
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		sleep(1000);
	}

	@Test
	public void testClearSentinel() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
		rpIndexPage.clickClearConfigButton(0);
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		sleep(1000);
	}

	@Test
	public void configureVeracode() {
		if (VERACODE_PASSWORD.equals("password") || VERACODE_USER.equals("username")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
		rpIndexPage.clickConfigure(1);
		RemoteProviderCredentialsPage rpCredPage = new RemoteProviderCredentialsPage(
				driver);
		String HeaderText = driver.findElementByTagName("h2").getText();
		assertTrue("Configure Page Not Found",
				HeaderText.contains("Remote Provider Veracode"));
		rpCredPage.fillAllClickSaveUsernamePassword(VERACODE_USER,
				VERACODE_PASSWORD,false);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		sleep(1000);
	}

	// Remove Configuration User Name Pwd

	@Test
	public void clearVeracodeConfig() {
		if (VERACODE_PASSWORD.equals("password") || VERACODE_USER.equals("username")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
		// driver.findElementById("clearConfig3").click();
		rpIndexPage.clickClearConfigButton(0);
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageHeader.contains("Remote Providers"));
		sleep(1000);
	}

	@Test
	public void configureQualys() {
		if (QUALYS_USER.equals("password") || QUALYS_PASS.equals("username")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
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
		sleep(1000);
		rpIndexPage.clickClearConfigButton(0);
	}

	// Need to have team - NewTeam White hat and application - WhiteHat
	// Application

	@Test
	public void configureTeamLink() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		edtMapPage = loginPage.login("user", "password")
				              .clickAddOrganizationButton()
				              .setNameInput("Sample WhiteHat Remote Provider Team")
				              .clickSubmitButtonValid()
				              .clickAddApplicationLink()
				              .setNameInput("WhiteHat Application")
				              .setUrlInput("http://test.com")
				              .clickAddApplicationButton()
							  .clickConfigurationHeaderLink()
							  .clickRemoteProvidersLink()
							  .clickConfigure(2)
							  .setAPI(SENTINEL_API_KEY)
							  .clickSave(false)
		        			  .clickEdit(0);
		
		String PageHeader = driver.findElementByTagName("h2").getText();
		assertTrue("Mapping Page Not Found",
				PageHeader.contains("Edit Mapping for Demo Site BE"));
		
		edtMapPage.fillAllClickSaveTeam("Sample WhiteHat Remote Provider Team",
				"WhiteHat Application");
		
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageText.contains("Remote Providers"));
		sleep(1000);
	}

	@Test
	public void addTeamsNoApp() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
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
		sleep(1000);
	}

	@Test
	public void addNoTeam() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		edtMapPage = organizationIndexPage.clickConfigurationHeaderLink()
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
		edtMapPage.clickBackLink();
		rpIndexPage = new RemoteProvidersIndexPage(driver);
		String PageText = driver.findElementByTagName("h2").getText();
		assertTrue("Remote Provider Page not found",
				PageText.contains("Remote Providers"));
		sleep(1000);
	}

	// Need to have team - NewTeam White hat and application - WhiteHat
	// Application

	@Test
	public void importScan() {
		if (SENTINEL_API_KEY.equals("your-key")) {
			return;
		}
		organizationIndexPage = loginPage.login("user", "password");
		rpIndexPage = organizationIndexPage.clickConfigurationHeaderLink()
				.clickRemoteProvidersLink();
		RemoteProvidersIndexPage rpIndexPage = new RemoteProvidersIndexPage(
				driver);
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
		sleep(1000);
		
		appDetPage.clickViewScansLink()
        	.clickDeleteScanButton(0)
        	.clickBackToAppLink()
        	.clickDeleteLink()
        	.clickDeleteButton()
        	.clickConfigurationHeaderLink()
        	.clickRemoteProvidersLink()
        	.clickClearConfigButton(0);
	}
	
	public void loginAdmin() {
		LoginPage page = new LoginPage(driver);
		page.login("user", "password");
	}

	private void sleep(int num) {
		try {
			Thread.sleep(num);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public FirefoxDriver getDriver() {
		return driver;
	}
}
