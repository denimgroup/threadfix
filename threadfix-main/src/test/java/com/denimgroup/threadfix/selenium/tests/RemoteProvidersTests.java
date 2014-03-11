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

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import com.denimgroup.threadfix.selenium.pages.RemoteProvidersIndexPage;


public class RemoteProvidersTests extends BaseTest {
	
	private static String SENTINEL_API_KEY = null;
	private static String VERACODE_USER = null;
	private static String VERACODE_PASSWORD = null;
	private static String QUALYS_USER = null;
	private static String QUALYS_PASS = null;

	@Before
	public void init() {
		assignVars();
	}
	
	private void assignVars() {
		String tmp = System.getProperty("WHITEHAT_KEY");
		if (tmp != null) {
			SENTINEL_API_KEY = tmp;
		}
		tmp = System.getProperty("VERACODE_USERNAME");
		if (tmp != null) {
			VERACODE_USER = tmp;
		}
		tmp = System.getProperty("VERACODE_PASSWORD");
		if (tmp != null) {
			VERACODE_PASSWORD = tmp;
		}
		tmp = System.getProperty("QUALYS_USER");
		if (tmp != null) {
			QUALYS_USER = tmp;
		}
		tmp = System.getProperty("QUALYS_PASS");
		if (tmp != null) {
			QUALYS_PASS = tmp;
		}
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
	if (SENTINEL_API_KEY == null) {
			return;
		}
		RemoteProvidersIndexPage indexPage = loginPage.login("user", "password")
							  								.clickRemoteProvidersLink()
							  								.clickConfigureWhiteHat()
							  								.setWhiteHatAPI(SENTINEL_API_KEY)
							  								.saveWhiteHat();
		

		assertTrue("Add Validation is not present",indexPage.successAlert().contains("Applications successfully updated"));
		
		indexPage = indexPage.clearWhiteHat();
		
		assertTrue("Delete Validation is not present",indexPage.successAlert().contains("WhiteHat Sentinel configuration was cleared successfully."));
		//assertTrue("Remote Provider Page not found",
			//	pageHeader.contains("Remote Providers"));
	}

	// Weird that this fails
	@Ignore
	@Test
	public void invalidSentinel(){
		RemoteProvidersIndexPage indexPage = loginPage.login("user", "password")
					.clickRemoteProvidersLink()
					.clickConfigureWhiteHat()
					.setWhiteHatAPI("This should't Work!")
					.saveWhiteHatInvalid();

		assertTrue("Incorrect credentials accepted",indexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));		
	}

	@Test
	public void configureVeracode() {
		if (VERACODE_PASSWORD == null || VERACODE_USER == null) {
			return;
		}
		
		RemoteProvidersIndexPage indexPage = loginPage.login("user", "password")
															.clickRemoteProvidersLink()
															.clickConfigureVeracode()
															.setVeraUsername(VERACODE_USER)
															.setVeraPassword(VERACODE_PASSWORD)
															.saveVera();

		//asserts and deletes when page is working properly
	}
	
	@Test
	public void invalidVeracode(){
		RemoteProvidersIndexPage indexPage = loginPage.login("user", "password")
													.clickRemoteProvidersLink()
													.clickConfigureVeracode()
													.setVeraUsername("No Such User")
													.setVeraPassword("Password Bad")
													.saveVeraInvalid();

		assertTrue("Incorrect credentials accepted",indexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
	}
	// Remove Configuration User Name Pwd

	@Ignore
	@Test
	public void configureQualys() {
		if (QUALYS_PASS == null || QUALYS_USER == null) {
			return;
		}
		RemoteProvidersIndexPage rpIndexPage = loginPage.login("user", "password")
														.clickRemoteProvidersLink()
														.clickConfigureQualys()
														.setQualysUsername(QUALYS_USER)
														.setQualysPassword(QUALYS_PASS)
														.saveQualys();
		
		//assert and clear qualys (waiting on bug fix)
	}
	
	@Test
	public void invalidQualys(){
		RemoteProvidersIndexPage indexPage = loginPage.login("user", "password")
													.clickRemoteProvidersLink()
													.clickConfigureQualys()
													.setQualysUsername("No Such User")
													.setQualysPassword("Password Bad")
													.saveQualysInvalid();
		
		assertTrue("Incorrect credentials accepted",indexPage.getErrorMessage().contains("We were unable to retrieve a list of applications using these credentials. Please ensure that the credentials are valid and that there are applications available in the account."));
	}

	// THESE TESTS HAVE BEEN COMMENTED OUT SO THEIR INTENT CAN BE SCRYED AND REWRITTEN
	// Need to have team - NewTeam White hat and application - WhiteHat Application

	/*@Ignore
	@Test
	public void configureTeamLink() {
		if (SENTINEL_API_KEY == null) {
			return;
		}
		
		String teamName = "SampleWhiteHatRemoteProviderTeam" + getRandomString(3);
		String appName = "WhiteHat Application" + getRandomString(3);
		String urlText = "http://test.com";

		RemoteProvidersIndexPage remoteProvidersIndexPage = loginPage.login("user", "password")
				.clickOrganizationHeaderLink()
				.clickAddTeamButton()
				.setTeamName(teamName)
				.addNewTeam()
				.addNewApplication(teamName, appName, urlText, "Low")
				.clickRemoteProvidersLink()
				.clickConfigureWhiteHat()
				.setWhiteHatAPI(SENTINEL_API_KEY)
				.saveWhiteHat()
				.mapWhiteHatToTeamAndApp(1, teamName, appName);
		
		String pageHeader = driver.findElement(By.tagName("h2")).getText();
		assertTrue("Mapping Page Not Found",
				pageHeader.contains("Edit Mapping for Demo Site BE"));
		
		String pageText =  edtMapPage.fillAllClickSaveTeam("Sample WhiteHat Remote Provider Team",
				"WhiteHat Application").getH2Tag();
		
		assertTrue("Remote Provider Page not found",
				pageText.contains("Remote Providers"));
	}*/

	/*
	@Ignore
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
	*/
	/*
	@Ignore
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
	*/
	
	// Need to have team - NewTeam White hat and application - WhiteHat
	// Application

	/*
	@Ignore
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
	*/
}
